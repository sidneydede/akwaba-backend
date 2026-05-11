// middleware/auth.js — Vérification du token d'authentification
// Token simple basé sur user_id + secret (pas de JWT pour rester compatible .then())

var crypto = require('crypto');
var pool = require('../db/pool');

// TOKEN_SECRET doit être défini quelle que soit l'environnement (un fallback
// dev publiquement connu = tous les tokens forgeables en dev/staging/CI).
// Pour démarrer localement : ajoute TOKEN_SECRET=<32 bytes random hex> dans .env.
var TOKEN_SECRET = process.env.TOKEN_SECRET;
if (!TOKEN_SECRET) {
  throw new Error(
    'TOKEN_SECRET manquant. Génère un secret aléatoire (openssl rand -hex 32) et ' +
    'définis-le dans .env (dev) ou dans les vars d\'environnement Render (prod).'
  );
}

// Durée de vie courte pour les tokens admin (back-office sensible).
var ADMIN_TOKEN_TTL_MS = 8 * 60 * 60 * 1000; // 8h

// Durée de vie tokens mobile/participant. 30 jours = compromis sécurité/UX :
// un user actif refait login mensuel (UX OK), un téléphone perdu n'expose pas
// l'account ad vitam. Pour révocation immédiate, voir POST /auth/logout
// (V2 : table user_token_version pour invalidation globale).
var MOBILE_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 jours

// Garde mémoire : un token volumineux est suspect et coûte du CPU à décoder
// (Buffer.from base64 → string → split). Hard cap pour prévenir CPU DoS.
var MAX_TOKEN_LENGTH = 500;

// Durée du "challenge token" remis après la validation du password mais avant
// la saisie du code TOTP. Court pour limiter une fenêtre d'attaque où ce token
// serait volé. 5 min suffit largement pour ouvrir son app authenticator.
var CHALLENGE_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 min

// Génère un token pour un utilisateur
// @param {number} userId - ID de l'utilisateur
// @returns {string} Token d'authentification
function generateToken(userId) {
  var timestamp = Date.now().toString();
  var data = userId + ':' + timestamp;
  var hash = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('hex');
  // Format: userId:timestamp:hash (encodé en base64)
  var token = Buffer.from(data + ':' + hash).toString('base64');
  return token;
}

// Décode un token et retourne le userId.
// @param {string} token - Token à décoder
// @param {number} [maxAgeMs] - Si fourni, rejette les tokens plus vieux que cette durée.
//   Le flux mobile (auth OTP) appelle sans maxAge → token longue durée.
//   Le flux admin (back-office) appelle avec ADMIN_TOKEN_TTL_MS → expire après 8h.
// @returns {number|null} userId ou null si invalide/expiré
function decodeToken(token, maxAgeMs) {
  try {
    var decoded = Buffer.from(token, 'base64').toString('utf8');
    var parts = decoded.split(':');
    if (parts.length !== 3) return null;
    var userId = parseInt(parts[0]);
    var timestamp = parts[1];
    var hash = parts[2];
    if (!userId || !/^\d+$/.test(timestamp)) return null;
    // Vérifie le hash (HMAC sur userId:timestamp).
    var expectedHash = crypto.createHmac('sha256', TOKEN_SECRET)
      .update(userId + ':' + timestamp)
      .digest('hex');
    // Comparaison timing-safe — le hash est de longueur fixe (64 hex).
    if (hash.length !== expectedHash.length) return null;
    var hashBuf = Buffer.from(hash, 'hex');
    var expBuf = Buffer.from(expectedHash, 'hex');
    if (hashBuf.length !== expBuf.length || !crypto.timingSafeEqual(hashBuf, expBuf)) return null;
    // Vérifie l'expiration si demandé. maxAgeMs=undefined → pas de check.
    if (typeof maxAgeMs === 'number' && maxAgeMs >= 0) {
      var age = Date.now() - parseInt(timestamp);
      if (age > maxAgeMs) return null;
    }
    return userId;
  } catch (e) {
    return null;
  }
}

// Middleware Express pour vérifier l'authentification.
// Applique MOBILE_TOKEN_TTL_MS pour les tokens participant/orga (30 jours).
// Sur 401 token expiré, le front mobile doit refaire login OTP.
function authMiddleware(req, res, next) {
  var authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token manquant' });
  }
  var token = authHeader.replace('Bearer ', '');
  // CPU guard : un token > 500 chars est forcément forgé.
  if (token.length > MAX_TOKEN_LENGTH) {
    return res.status(401).json({ success: false, message: 'Token invalide' });
  }
  var userId = decodeToken(token, MOBILE_TOKEN_TTL_MS);
  if (!userId) {
    return res.status(401).json({
      success: false,
      code: 'token_expired',
      message: 'Session expirée, reconnecte-toi.',
    });
  }
  req.userId = userId;
  next();
}

// Variante stricte pour les routes admin : applique ADMIN_TOKEN_TTL_MS.
// Réponse 401 avec code 'token_expired' distinct pour permettre au front
// d'afficher un message clair ("Session expirée, reconnectez-vous").
function adminAuthMiddleware(req, res, next) {
  var authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token manquant' });
  }
  var token = authHeader.replace('Bearer ', '');
  if (token.length > MAX_TOKEN_LENGTH) {
    return res.status(401).json({ success: false, message: 'Token invalide' });
  }
  var userId = decodeToken(token, ADMIN_TOKEN_TTL_MS);
  if (!userId) {
    return res.status(401).json({
      success: false,
      code: 'token_expired',
      message: 'Session expirée ou invalide'
    });
  }
  req.userId = userId;
  next();
}

// Vérifie que l'utilisateur authentifié est un organisateur
// À chaîner après authMiddleware. Pose req.user = { id, nom, prenom, phone, role }.
function requireOrganizer(req, res, next) {
  pool.query('SELECT id, nom, prenom, phone, role, kyc_status FROM users WHERE id = $1', [req.userId])
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(401).json({ success: false, message: 'Utilisateur introuvable' });
      }
      var user = result.rows[0];
      if (user.role !== 'organisateur') {
        return res.status(403).json({ success: false, message: 'Réservé aux organisateurs' });
      }
      req.user = user;
      next();
    })
    .catch(function(err) {
      console.error('Erreur requireOrganizer:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
}

// Vérifie que l'utilisateur authentifié est un admin et n'est pas suspendu.
// À chaîner après authMiddleware. Pose req.admin = { id, nom, prenom, email,
// role, admin_role }.
function requireAdmin(req, res, next) {
  pool.query(
    'SELECT id, nom, prenom, phone, email, role, admin_role, suspended_at FROM users WHERE id = $1',
    [req.userId]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(401).json({ success: false, message: 'Utilisateur introuvable' });
      }
      var user = result.rows[0];
      if (user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Réservé aux administrateurs' });
      }
      if (user.suspended_at) {
        return res.status(403).json({ success: false, message: 'Compte suspendu' });
      }
      req.admin = user;
      next();
    })
    .catch(function(err) {
      console.error('Erreur requireAdmin:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
}

// Factory : vérifie que req.admin.admin_role est dans la liste autorisée.
// À chaîner APRÈS requireAdmin. super_admin est implicitement autorisé sur
// tout — la liste n'a besoin de mentionner que les autres rôles.
// Usage : router.post('/foo', requireAdminRole(['moderator']), handler);
function requireAdminRole(allowedRoles) {
  return function(req, res, next) {
    if (!req.admin) {
      return res.status(500).json({
        success: false,
        message: 'requireAdminRole utilisé sans requireAdmin préalable',
      });
    }
    var role = req.admin.admin_role;
    if (role === 'super_admin' || (allowedRoles && allowedRoles.indexOf(role) !== -1)) {
      return next();
    }
    res.status(403).json({
      success: false,
      message: 'Permission insuffisante. Requis : ' + allowedRoles.join(' ou ') + ' (vous êtes ' + (role || 'sans rôle') + ').',
    });
  };
}

// Génère un token "purpose-scoped" — utilisé pour le challenge 2FA entre
// l'étape password et l'étape TOTP. Format distinct (4 parts vs 3) pour qu'un
// challenge token ne puisse PAS être accepté par decodeToken/authMiddleware
// comme un token de session normal.
// @param {number} userId
// @param {string} purpose - ex. 'totp_challenge'
// @returns {string}
function generateChallengeToken(userId, purpose) {
  var ts = Date.now().toString();
  var data = userId + ':' + ts + ':' + purpose;
  var hash = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('hex');
  return Buffer.from(data + ':' + hash).toString('base64');
}

// Vérifie un challenge token + son purpose + son âge. Retourne userId ou null.
function decodeChallengeToken(token, expectedPurpose, maxAgeMs) {
  try {
    var decoded = Buffer.from(token, 'base64').toString('utf8');
    var parts = decoded.split(':');
    if (parts.length !== 4) return null;
    var userId = parseInt(parts[0]);
    var ts = parts[1];
    var purpose = parts[2];
    var hash = parts[3];
    if (!userId || !/^\d+$/.test(ts)) return null;
    if (purpose !== expectedPurpose) return null;
    var expected = crypto.createHmac('sha256', TOKEN_SECRET)
      .update(userId + ':' + ts + ':' + purpose).digest('hex');
    if (hash.length !== expected.length) return null;
    var a = Buffer.from(hash, 'hex');
    var b = Buffer.from(expected, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    if (typeof maxAgeMs === 'number' && maxAgeMs >= 0) {
      if (Date.now() - parseInt(ts) > maxAgeMs) return null;
    }
    return userId;
  } catch (e) {
    return null;
  }
}

// Hash un mot de passe avec scrypt + salt aléatoire (64 octets dérivés).
// Format de stockage : "scrypt:<salt-hex>:<derived-hex>"
// scrypt est intégré à Node, pas besoin de dépendance bcrypt.
function hashPassword(password) {
  return new Promise(function(resolve, reject) {
    var salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, function(err, derivedKey) {
      if (err) return reject(err);
      resolve('scrypt:' + salt + ':' + derivedKey.toString('hex'));
    });
  });
}

// Vérifie un mot de passe contre un hash stocké. Comparaison timing-safe.
function verifyPassword(password, stored) {
  return new Promise(function(resolve) {
    if (!stored || typeof stored !== 'string') return resolve(false);
    var parts = stored.split(':');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return resolve(false);
    var salt = parts[1];
    var expected = Buffer.from(parts[2], 'hex');
    crypto.scrypt(password, salt, 64, function(err, derivedKey) {
      if (err || derivedKey.length !== expected.length) return resolve(false);
      resolve(crypto.timingSafeEqual(derivedKey, expected));
    });
  });
}

module.exports = {
  generateToken: generateToken,
  decodeToken: decodeToken,
  generateChallengeToken: generateChallengeToken,
  decodeChallengeToken: decodeChallengeToken,
  authMiddleware: authMiddleware,
  adminAuthMiddleware: adminAuthMiddleware,
  requireOrganizer: requireOrganizer,
  requireAdmin: requireAdmin,
  requireAdminRole: requireAdminRole,
  hashPassword: hashPassword,
  verifyPassword: verifyPassword,
  ADMIN_TOKEN_TTL_MS: ADMIN_TOKEN_TTL_MS,
  MOBILE_TOKEN_TTL_MS: MOBILE_TOKEN_TTL_MS,
  CHALLENGE_TOKEN_TTL_MS: CHALLENGE_TOKEN_TTL_MS,
};
