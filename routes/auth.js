// routes/auth.js — Authentification OTP par SMS
// Flow : register/login → OTP envoyé par SMS → verify-otp → token

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var sms = require('../services/sms');

// Génère un code OTP à 6 chiffres
// @returns {string}
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Calcule la date d'expiration OTP (10 minutes dans le futur)
// @returns {Date}
function otpExpiry() {
  return new Date(Date.now() + 10 * 60 * 1000);
}

// Helper : génère + stocke + envoie un OTP pour un user existant
// @param {object} user - Ligne user PostgreSQL
// @returns {Promise<object>} { dev_otp?: string }
function issueOtp(user) {
  var code = generateOtp();
  var expires = otpExpiry();
  return pool.query(
    'UPDATE users SET otp_code = $1, otp_expires_at = $2, updated_at = NOW() WHERE id = $3',
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
        'INSERT INTO users (nom, prenom, phone, role) VALUES ($1, $2, $3, $4) RETURNING id, phone',
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

  pool.query('SELECT id, phone FROM users WHERE phone = $1', [phone])
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
    'SELECT id, nom, prenom, phone, role, otp_code, otp_expires_at FROM users WHERE phone = $1',
    [phone]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Compte introuvable' });
      }

      var user = result.rows[0];

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
        return res.status(400).json({
          success: false,
          message: 'Code incorrect'
        });
      }

      // OK : on efface l'OTP et on retourne le token
      return pool.query(
        'UPDATE users SET otp_code = NULL, otp_expires_at = NULL, updated_at = NOW() WHERE id = $1',
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
    'SELECT id, nom, prenom, phone, role, created_at FROM users WHERE id = $1',
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

module.exports = router;
