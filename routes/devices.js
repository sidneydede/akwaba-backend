// routes/devices.js — Enregistrement des tokens Expo Push
// Le frontend appelle POST /devices/register après login pour enregistrer
// son token push, et DELETE /devices/unregister à la déconnexion.

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');

// POST /devices/register — Enregistre (ou rafraîchit) un token push
// @body {string} token - ExponentPushToken[...]
// @body {string} platform - 'ios' | 'android' | 'web' (optionnel)
router.post('/register', auth.authMiddleware, function(req, res) {
  var token = req.body.token;
  var platform = req.body.platform || null;

  if (!token || typeof token !== 'string') {
    return res.status(400).json({ success: false, message: 'Token manquant' });
  }
  if (token.indexOf('ExponentPushToken[') !== 0 && token.indexOf('ExpoPushToken[') !== 0) {
    return res.status(400).json({ success: false, message: 'Format de token invalide' });
  }

  pool.query(
    'INSERT INTO device_tokens (user_id, token, platform) VALUES ($1, $2, $3) ' +
    'ON CONFLICT (user_id, token) DO UPDATE SET last_seen_at = NOW(), platform = COALESCE(EXCLUDED.platform, device_tokens.platform) ' +
    'RETURNING id',
    [req.userId, token, platform]
  )
    .then(function(result) {
      res.json({ success: true, message: 'Device enregistré', id: result.rows[0].id });
    })
    .catch(function(err) {
      console.error('Erreur POST /devices/register:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// DELETE /devices/unregister — Supprime un token push (au logout)
// @body {string} token
router.delete('/unregister', auth.authMiddleware, function(req, res) {
  var token = req.body.token;
  if (!token) {
    return res.status(400).json({ success: false, message: 'Token manquant' });
  }
  pool.query(
    'DELETE FROM device_tokens WHERE user_id = $1 AND token = $2',
    [req.userId, token]
  )
    .then(function() {
      res.json({ success: true, message: 'Device désenregistré' });
    })
    .catch(function(err) {
      console.error('Erreur DELETE /devices/unregister:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
