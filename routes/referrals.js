// routes/referrals.js — Programme de parrainage (REF-01)
//
// Mecanique :
//   1. Filleul s'inscrit, recupere le code parrain via apply (POST /redeem) :
//      → Cree un referral pending (parrain_id, filleul_id)
//      → Award immediatement 500 pts au filleul (level Or direct)
//   2. Quand le filleul fait sa 1ere reservation confirmee (hook webhook
//      /payments/notify, cf. routes/payments.js) :
//      → UPDATE referral status='confirmed', parrain_points_awarded=true
//      → Award 200 pts au parrain
//      → Push notif "🎁 X vient de reserver son 1er event !"

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');

// POST /referrals/redeem — Filleul applique un code parrain.
// @body {string} code (format AKW-XXXX)
router.post('/redeem', auth.authMiddleware, function(req, res) {
  var code = req.body && req.body.code;
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ success: false, message: 'Code requis' });
  }
  var normalized = code.trim().toUpperCase();
  if (!/^AKW-[A-Z0-9]{4,8}$/.test(normalized)) {
    return res.status(400).json({ success: false, message: 'Code parrain invalide' });
  }

  // Cherche le parrain via referral_code
  pool.query('SELECT id FROM users WHERE referral_code = $1', [normalized])
    .then(function(parrainResult) {
      if (parrainResult.rows.length === 0) {
        return res.status(400).json({ success: false, message: 'Code parrain invalide' });
      }
      var parrainId = parrainResult.rows[0].id;

      // Refuse l'auto-parrainage
      if (parrainId === req.userId) {
        return res.status(400).json({
          success: false,
          message: 'Tu ne peux pas utiliser ton propre code parrain'
        });
      }

      // Tente l'INSERT — UNIQUE (filleul_id) refuse un 2eme parrain
      // Award 500 pts au filleul dans la meme transaction (atomique).
      return pool.query('BEGIN')
        .then(function() {
          return pool.query(
            'INSERT INTO referrals (parrain_id, filleul_id, status) VALUES ($1, $2, \'pending\') ' +
            'RETURNING id, points_filleul, points_parrain, created_at',
            [parrainId, req.userId]
          );
        })
        .then(function(insertResult) {
          var ref = insertResult.rows[0];
          // Award immediat des points au filleul (500 par defaut)
          return pool.query(
            "UPDATE users SET points = COALESCE(points, 0) + $1, " +
            "acquisition_source = COALESCE(acquisition_source, 'referral') " +
            "WHERE id = $2 RETURNING points",
            [ref.points_filleul, req.userId]
          ).then(function(pointsResult) {
            return pool.query('COMMIT').then(function() {
              return { ref: ref, newPoints: pointsResult.rows[0].points };
            });
          });
        })
        .then(function(state) {
          res.json({
            success: true,
            message: 'Code parrain accepté ! Tu as gagné ' + state.ref.points_filleul + ' points fidélité.',
            referral: {
              id: state.ref.id,
              status: 'pending',
              points_awarded: state.ref.points_filleul,
              created_at: state.ref.created_at,
            },
            user_points: state.newPoints,
          });
        })
        .catch(function(err) {
          // Rollback en cas d'erreur (UNIQUE violation, etc.)
          pool.query('ROLLBACK').catch(function() {});
          if (err && err.code === '23505') {
            // unique_violation : filleul a deja un parrain
            return res.status(409).json({
              success: false,
              message: 'Tu as déjà utilisé un code parrain'
            });
          }
          if (err && err.code === '23514') {
            // check_violation : auto-parrainage (theoriquement impossible vu le check au-dessus, mais defense en profondeur)
            return res.status(400).json({
              success: false,
              message: 'Code parrain invalide'
            });
          }
          console.error('Erreur POST /referrals/redeem:', err.message);
          res.status(500).json({ success: false, message: 'Erreur serveur' });
        });
    })
    .catch(function(err) {
      console.error('Erreur lookup parrain:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /referrals/mine — Liste des filleuls parraines par l'user connecte.
// Privacy : retourne uniquement le PRENOM du filleul (pas nom ni telephone).
router.get('/mine', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT r.id, r.status, r.points_parrain, r.parrain_points_awarded, ' +
    'r.created_at, r.confirmed_at, u.prenom AS filleul_prenom ' +
    'FROM referrals r JOIN users u ON u.id = r.filleul_id ' +
    'WHERE r.parrain_id = $1 ORDER BY r.created_at DESC',
    [req.userId]
  )
    .then(function(result) {
      var referrals = result.rows.map(function(r) {
        return {
          id: r.id,
          filleul_prenom: r.filleul_prenom,
          status: r.status,
          points_awarded: r.parrain_points_awarded ? r.points_parrain : 0,
          created_at: r.created_at,
          confirmed_at: r.confirmed_at,
        };
      });
      res.json({ success: true, referrals: referrals });
    })
    .catch(function(err) {
      console.error('Erreur GET /referrals/mine:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
