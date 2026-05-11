// routes/reviews.js — Avis publics sur events (REVIEW-01 / P3.1)
//
// Endpoints sous /events/:eventId/reviews. Mount avec mergeParams: true
// pour acceder a req.params.eventId (cf. server.js).
//
// Reviews = social proof PUBLIC, distinct de feedback (NPS prive).

var express = require('express');
var router = express.Router({ mergeParams: true });
var pool = require('../db/pool');
var auth = require('../middleware/auth');

// GET /events/:eventId/reviews — Liste les avis + stats agreges (avg, count, has_reviewed).
// Auth optionnelle : has_reviewed n'est calcule que si user authentifie.
router.get('/', function(req, res) {
  var eventId = parseInt(req.params.eventId, 10);
  if (isNaN(eventId)) {
    return res.status(400).json({ success: false, message: 'eventId invalide' });
  }

  // Auth optionnelle : decode si token present, sinon userId reste null
  var userId = null;
  try {
    var authHeader = req.headers.authorization;
    if (authHeader && authHeader.indexOf('Bearer ') === 0) {
      userId = auth.decodeToken(authHeader.replace('Bearer ', ''));
    }
  } catch (e) { userId = null; }

  Promise.all([
    // 5 derniers avis avec user.prenom (pas le nom complet — privacy)
    pool.query(
      'SELECT r.id, r.rating, r.comment, r.created_at, u.prenom AS user_prenom ' +
      'FROM reviews r JOIN users u ON u.id = r.user_id ' +
      'WHERE r.event_id = $1 ORDER BY r.created_at DESC LIMIT 5',
      [eventId]
    ),
    // Stats agreges sur tous les reviews (pas juste les 5 derniers)
    pool.query(
      'SELECT COUNT(*)::int AS count, COALESCE(AVG(rating)::numeric(10,1), 0) AS avg_rating ' +
      'FROM reviews WHERE event_id = $1',
      [eventId]
    ),
    // has_reviewed : seulement si user authentifie
    userId
      ? pool.query('SELECT 1 FROM reviews WHERE user_id = $1 AND event_id = $2 LIMIT 1', [userId, eventId])
      : Promise.resolve({ rows: [] }),
  ])
    .then(function(results) {
      var reviews = results[0].rows.map(function(r) {
        return {
          id: r.id,
          user_prenom: r.user_prenom,
          rating: r.rating,
          comment: r.comment,
          created_at: r.created_at,
        };
      });
      var stats = results[1].rows[0] || { count: 0, avg_rating: 0 };
      var hasReviewed = userId ? results[2].rows.length > 0 : false;
      res.json({
        success: true,
        reviews: reviews,
        stats: {
          count: parseInt(stats.count) || 0,
          avg_rating: parseFloat(stats.avg_rating) || 0,
          has_reviewed: hasReviewed,
        },
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /events/:id/reviews:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /events/:eventId/reviews — Cree un avis. Auth requise.
// @body {number} rating (1-5) (required)
// @body {string} comment (optional, max 500 chars, truncate au-dela)
//
// Validations :
//   - 409 si user a deja note cet event (UNIQUE constraint)
//   - 404 si event n'existe pas
//   - V2 (recommande, anti-spam) : verifier que l'user a un booking confirme
//     sur cet event avant d'autoriser l'avis. Pour V1 on accepte toute auth.
router.post('/', auth.authMiddleware, function(req, res) {
  var eventId = parseInt(req.params.eventId, 10);
  var rating = parseInt(req.body.rating, 10);
  var comment = req.body.comment;

  if (isNaN(eventId)) {
    return res.status(400).json({ success: false, message: 'eventId invalide' });
  }
  if (isNaN(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ success: false, message: 'Note invalide (1 à 5)' });
  }
  var commentClean = null;
  if (comment !== undefined && comment !== null) {
    commentClean = String(comment).trim().slice(0, 500);
    if (!commentClean) commentClean = null;
  }

  // Verifie que l'event existe (sinon FK error -> 500 peu informatif)
  pool.query('SELECT id FROM events WHERE id = $1', [eventId])
    .then(function(eventCheck) {
      if (eventCheck.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Événement introuvable' });
      }
      return pool.query(
        'INSERT INTO reviews (user_id, event_id, rating, comment) VALUES ($1, $2, $3, $4) ' +
        'RETURNING id, rating, comment, created_at',
        [req.userId, eventId, rating, commentClean]
      ).then(function(insertResult) {
        var review = insertResult.rows[0];
        res.status(201).json({
          success: true,
          review: {
            id: review.id,
            rating: review.rating,
            comment: review.comment,
            created_at: review.created_at,
          },
        });
      });
    })
    .catch(function(err) {
      if (err && err.code === '23505') {
        return res.status(409).json({
          success: false,
          message: 'Tu as déjà noté cet événement'
        });
      }
      console.error('Erreur POST /events/:id/reviews:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
