// routes/auth.js — Authentification (register + login)
// Pour l'instant : login par phone, pas encore d'OTP SMS réel

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');

// POST /auth/register — Créer un nouveau compte
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

  // Vérifie si le numéro existe déjà
  pool.query('SELECT id FROM users WHERE phone = $1', [phone])
    .then(function(result) {
      if (result.rows.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Ce numéro de téléphone est déjà utilisé'
        });
      }

      // Insère le nouvel utilisateur
      return pool.query(
        'INSERT INTO users (nom, prenom, phone, role) VALUES ($1, $2, $3, $4) RETURNING id, nom, prenom, phone, role',
        [nom, prenom, phone, role]
      )
        .then(function(insertResult) {
          var user = insertResult.rows[0];
          var token = auth.generateToken(user.id);

          res.status(201).json({
            success: true,
            message: 'Compte créé avec succès',
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
      console.error('Erreur register:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /auth/login — Connexion par numéro de téléphone
// @body {string} phone
router.post('/login', function(req, res) {
  var phone = req.body.phone;

  if (!phone) {
    return res.status(400).json({
      success: false,
      message: 'Numéro de téléphone obligatoire'
    });
  }

  pool.query('SELECT id, nom, prenom, phone, role FROM users WHERE phone = $1', [phone])
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Aucun compte trouvé avec ce numéro'
        });
      }

      var user = result.rows[0];
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
    })
    .catch(function(err) {
      console.error('Erreur login:', err.message);
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

      // Compte les billets de l'utilisateur
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
