// routes/banners.js — Endpoint public pour le carousel "À la une" mobile
// GET /banners : retourne les bannières actuellement actives, triées par position.

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');

// GET /banners — Liste des bannières actives.
// Active = active_from IS NULL OR active_from <= NOW(), même chose pour active_until.
router.get('/', function(req, res) {
  pool.query(
    'SELECT id, title, subtitle, image_url, link_type, link_target, position ' +
    'FROM banners ' +
    'WHERE (active_from IS NULL OR active_from <= NOW()) ' +
    '  AND (active_until IS NULL OR active_until >= NOW()) ' +
    'ORDER BY position ASC, created_at DESC ' +
    'LIMIT 10'
  )
    .then(function(result) {
      res.json({
        success: true,
        banners: result.rows.map(function(r) {
          return {
            id: r.id.toString(),
            title: r.title,
            subtitle: r.subtitle,
            image_url: r.image_url,
            link_type: r.link_type,
            link_target: r.link_target,
            position: r.position,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /banners:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
