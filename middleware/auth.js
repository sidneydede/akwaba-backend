// middleware/auth.js — Vérification du token d'authentification
// Token simple basé sur user_id + secret (pas de JWT pour rester compatible .then())

var crypto = require('crypto');
var pool = require('../db/pool');

var TOKEN_SECRET = process.env.TOKEN_SECRET || 'akwaba-secret-dev';

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

// Décode un token et retourne le userId
// @param {string} token - Token à décoder
// @returns {number|null} userId ou null si invalide
function decodeToken(token) {
  try {
    var decoded = Buffer.from(token, 'base64').toString('utf8');
    var parts = decoded.split(':');
    if (parts.length !== 3) return null;
    var userId = parseInt(parts[0]);
    var timestamp = parts[1];
    var hash = parts[2];
    // Vérifie le hash
    var expectedHash = crypto.createHmac('sha256', TOKEN_SECRET)
      .update(userId + ':' + timestamp)
      .digest('hex');
    if (hash !== expectedHash) return null;
    return userId;
  } catch (e) {
    return null;
  }
}

// Middleware Express pour vérifier l'authentification
// Ajoute req.userId si le token est valide
function authMiddleware(req, res, next) {
  var authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token manquant' });
  }
  var token = authHeader.replace('Bearer ', '');
  var userId = decodeToken(token);
  if (!userId) {
    return res.status(401).json({ success: false, message: 'Token invalide' });
  }
  req.userId = userId;
  next();
}

// Vérifie que l'utilisateur authentifié est un organisateur
// À chaîner après authMiddleware. Pose req.user = { id, nom, prenom, phone, role }.
function requireOrganizer(req, res, next) {
  pool.query('SELECT id, nom, prenom, phone, role FROM users WHERE id = $1', [req.userId])
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
// À chaîner après authMiddleware. Pose req.admin = { id, nom, prenom, email, role }.
function requireAdmin(req, res, next) {
  pool.query(
    'SELECT id, nom, prenom, phone, email, role, suspended_at FROM users WHERE id = $1',
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
  authMiddleware: authMiddleware,
  requireOrganizer: requireOrganizer,
  requireAdmin: requireAdmin,
  hashPassword: hashPassword,
  verifyPassword: verifyPassword
};
