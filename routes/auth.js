// routes/auth.js — Authentification OTP par SMS
// Flow : register/login → OTP envoyé par SMS → verify-otp → token

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var sms = require('../services/sms');

// Génère un code OTP à 6 chiffres (crypto-random, pas Math.random qui est prédictible).
// @returns {string}
function generateOtp() {
  var crypto = require('crypto');
  var n = crypto.randomInt(100000, 1000000);
  return n.toString();
}

// Calcule la date d'expiration OTP. Plus strict pour orga (compromission = accès aux fonds).
// @param {string} role - 'participant' | 'organisateur' | 'admin'
// @returns {Date}
function otpExpiry(role) {
  var minutes = role === 'organisateur' ? 5 : 10;
  return new Date(Date.now() + minutes * 60 * 1000);
}

// AUTH-05 : limites de tentatives OTP (brute-force protection).
// Orga = 3 tentatives, lockout 30 min. Participant = 5 tentatives, lockout 15 min.
function otpLimits(role) {
  if (role === 'organisateur') return { maxAttempts: 3, lockoutMinutes: 30 };
  return { maxAttempts: 5, lockoutMinutes: 15 };
}

// Helper : génère + stocke + envoie un OTP pour un user existant.
// Reset les compteurs d'attempts (nouveau code = nouvelle fenêtre de tentatives).
// @param {object} user - Ligne user PostgreSQL (au minimum: id, phone, role)
// @returns {Promise<object>} { dev_otp?: string }
function issueOtp(user) {
  var code = generateOtp();
  var expires = otpExpiry(user.role);
  return pool.query(
    'UPDATE users SET otp_code = $1, otp_expires_at = $2, otp_attempts = 0, ' +
    'otp_locked_until = NULL, updated_at = NOW() WHERE id = $3',
    [code, expires, user.id]
  )
    .then(function() {
      return sms.sendOtp(user.phone, code);
    })
    .then(function(smsResult) {
      // En mode dev, on renvoie l'OTP au client pour faciliter les tests
      if (smsResult.dev) {
        return { dev_otp: code };
      }
      return {};
    });
}

// POST /auth/register — Crée un compte et envoie un OTP par SMS
// @body {string} nom, prenom, phone, role
router.post('/register', function(req, res) {
  var nom = req.body.nom;
  var prenom = req.body.prenom;
  var phone = req.body.phone;
  var role = req.body.role || 'participant';

  if (!nom || !prenom || !phone) {
    return res.status(400).json({
      success: false,
      message: 'Nom, prénom et téléphone sont obligatoires'
    });
  }

  pool.query('SELECT id, phone FROM users WHERE phone = $1', [phone])
    .then(function(result) {
      if (result.rows.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Ce numéro de téléphone est déjà utilisé'
        });
      }

      return pool.query(
        'INSERT INTO users (nom, prenom, phone, role) VALUES ($1, $2, $3, $4) RETURNING id, phone, role',
        [nom, prenom, phone, role]
      )
        .then(function(insertResult) {
          var user = insertResult.rows[0];
          return issueOtp(user).then(function(extra) {
            res.status(201).json(Object.assign({
              success: true,
              message: 'Compte créé. Un code de vérification vous a été envoyé par SMS.',
              phone: user.phone,
              next: 'verify-otp'
            }, extra));
          });
        });
    })
    .catch(function(err) {
      console.error('Erreur register:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /auth/login — Demande un OTP pour un compte existant
// @body {string} phone
router.post('/login', function(req, res) {
  var phone = req.body.phone;

  if (!phone) {
    return res.status(400).json({ success: false, message: 'Numéro de téléphone obligatoire' });
  }

  pool.query('SELECT id, phone, role FROM users WHERE phone = $1', [phone])
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Aucun compte trouvé avec ce numéro'
        });
      }

      var user = result.rows[0];
      return issueOtp(user).then(function(extra) {
        res.json(Object.assign({
          success: true,
          message: 'Code de vérification envoyé par SMS',
          phone: user.phone,
          next: 'verify-otp'
        }, extra));
      });
    })
    .catch(function(err) {
      console.error('Erreur login:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /auth/request-otp — Alias explicite de login (renvoyer un nouveau code)
router.post('/request-otp', function(req, res) {
  req.url = '/login';
  router.handle(req, res);
});

// POST /auth/verify-otp — Vérifie l'OTP et retourne un token + user
// @body {string} phone, code
router.post('/verify-otp', function(req, res) {
  var phone = req.body.phone;
  var code = req.body.code;

  if (!phone || !code) {
    return res.status(400).json({
      success: false,
      message: 'Numéro et code obligatoires'
    });
  }

  pool.query(
    'SELECT id, nom, prenom, phone, role, otp_code, otp_expires_at, otp_attempts, otp_locked_until ' +
    'FROM users WHERE phone = $1',
    [phone]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Compte introuvable' });
      }

      var user = result.rows[0];
      var limits = otpLimits(user.role);

      // AUTH-05 : refus si compte verrouillé après trop de tentatives
      if (user.otp_locked_until && new Date(user.otp_locked_until).getTime() > Date.now()) {
        var minutesLeft = Math.ceil((new Date(user.otp_locked_until).getTime() - Date.now()) / 60000);
        return res.status(429).json({
          success: false,
          code: 'LOCKED',
          message: 'Trop de tentatives. Réessayez dans ' + minutesLeft + ' minute' + (minutesLeft > 1 ? 's' : '') + '.'
        });
      }

      if (!user.otp_code) {
        return res.status(400).json({
          success: false,
          message: 'Aucun code en attente. Demandez un nouveau code.'
        });
      }

      if (new Date(user.otp_expires_at).getTime() < Date.now()) {
        return res.status(400).json({
          success: false,
          message: 'Code expiré. Demandez un nouveau code.'
        });
      }

      if (user.otp_code !== code) {
        // Incrémente attempts + verrouille si dépassement.
        var newAttempts = (user.otp_attempts || 0) + 1;
        if (newAttempts >= limits.maxAttempts) {
          var lockUntil = new Date(Date.now() + limits.lockoutMinutes * 60 * 1000);
          return pool.query(
            'UPDATE users SET otp_attempts = $1, otp_locked_until = $2, ' +
            'otp_code = NULL, otp_expires_at = NULL WHERE id = $3',
            [newAttempts, lockUntil, user.id]
          ).then(function() {
            res.status(429).json({
              success: false,
              code: 'LOCKED',
              message: 'Trop de tentatives. Compte temporairement verrouillé pendant ' +
                limits.lockoutMinutes + ' minutes.'
            });
          });
        }
        return pool.query('UPDATE users SET otp_attempts = $1 WHERE id = $2', [newAttempts, user.id])
          .then(function() {
            res.status(400).json({
              success: false,
              message: 'Code incorrect',
              attempts_left: limits.maxAttempts - newAttempts
            });
          });
      }

      // OK : on efface l'OTP, on reset les compteurs, et on retourne le token
      return pool.query(
        'UPDATE users SET otp_code = NULL, otp_expires_at = NULL, otp_attempts = 0, ' +
        'otp_locked_until = NULL, last_login_at = NOW(), updated_at = NOW() WHERE id = $1',
        [user.id]
      )
        .then(function() {
          var token = auth.generateToken(user.id);
          res.json({
            success: true,
            message: 'Connexion réussie',
            user: {
              id: user.id.toString(),
              nom: user.nom,
              prenom: user.prenom,
              phone: user.phone,
              role: user.role
            },
            token: token
          });
        });
    })
    .catch(function(err) {
      console.error('Erreur verify-otp:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /auth/me — Récupère le profil de l'utilisateur connecté
router.get('/me', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT id, nom, prenom, phone, role, preferences, created_at FROM users WHERE id = $1',
    [req.userId]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
      }

      var user = result.rows[0];

      return pool.query(
        "SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE statut = 'confirme') as actifs FROM bookings WHERE user_id = $1",
        [req.userId]
      )
        .then(function(statsResult) {
          var stats = statsResult.rows[0];
          res.json({
            success: true,
            user: {
              id: user.id.toString(),
              nom: user.nom,
              prenom: user.prenom,
              phone: user.phone,
              role: user.role,
              preferences: user.preferences || {},
              created_at: user.created_at
            },
            stats: {
              total_billets: parseInt(stats.total),
              billets_actifs: parseInt(stats.actifs)
            }
          });
        });
    })
    .catch(function(err) {
      console.error('Erreur auth/me:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /auth/me — Met à jour le profil de l'utilisateur connecté.
// Champs autorisés : prenom, nom. Le téléphone n'est PAS modifiable ici
// (nominatif → nécessite re-OTP, à traiter dans un endpoint dédié). Le role
// et l'id ne sont jamais modifiables par l'utilisateur lui-même.
// @body {string} [prenom] - 1 à 50 caractères
// @body {string} [nom]    - 1 à 50 caractères
router.patch('/me', auth.authMiddleware, function(req, res) {
  var input = req.body || {};
  var sets = [];
  var values = [];
  var i = 1;

  if (input.prenom !== undefined) {
    var p = String(input.prenom).trim();
    if (!p || p.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'Prénom invalide (1 à 50 caractères).'
      });
    }
    sets.push('prenom = $' + i++);
    values.push(p);
  }

  if (input.nom !== undefined) {
    var n = String(input.nom).trim();
    if (!n || n.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'Nom invalide (1 à 50 caractères).'
      });
    }
    sets.push('nom = $' + i++);
    values.push(n);
  }

  if (sets.length === 0) {
    return res.status(400).json({
      success: false,
      message: 'Aucun champ à mettre à jour (prenom et/ou nom requis).'
    });
  }

  sets.push('updated_at = NOW()');
  values.push(req.userId);

  pool.query(
    'UPDATE users SET ' + sets.join(', ') + ' WHERE id = $' + i +
    ' RETURNING id, nom, prenom, phone, role, preferences, created_at',
    values
  )
    .then(function(result) {
      if (result.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'Utilisateur introuvable' });
      }
      var user = result.rows[0];
      res.json({
        success: true,
        user: {
          id: user.id.toString(),
          nom: user.nom,
          prenom: user.prenom,
          phone: user.phone,
          role: user.role,
          preferences: user.preferences || {},
          created_at: user.created_at
        }
      });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /auth/me:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /auth/me/preferences — Met à jour les préférences de l'utilisateur connecté.
// @body {object} preferences - { categories?: string[], lang?: string }
// On merge avec l'existant pour ne pas écraser les autres clés.
router.patch('/me/preferences', auth.authMiddleware, function(req, res) {
  var input = req.body.preferences;
  if (!input || typeof input !== 'object') {
    return res.status(400).json({ success: false, message: 'preferences (object) requis' });
  }

  // Validation : categories doit être un array de strings si fourni.
  if (input.categories !== undefined) {
    if (!Array.isArray(input.categories) ||
        !input.categories.every(function(c) { return typeof c === 'string'; })) {
      return res.status(400).json({
        success: false, message: 'preferences.categories doit être un array de strings',
      });
    }
  }

  // Merge JSONB : COALESCE pour le cas où preferences est NULL en base.
  pool.query(
    "UPDATE users SET preferences = COALESCE(preferences, '{}') || $1::jsonb, updated_at = NOW() " +
    'WHERE id = $2 RETURNING preferences',
    [JSON.stringify(input), req.userId]
  )
    .then(function(r) {
      res.json({ success: true, preferences: r.rows[0].preferences });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /auth/me/preferences:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
