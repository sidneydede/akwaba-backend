// routes/feedback.js — Feedback NPS post-événement (FEEDBACK-01)
//
// Différent des reviews publics (P3.1 reviews) : feedback est PRIVÉ (signal
// qualité pour l'équipe Akwaba), reviews est PUBLIC (social proof sur fiche event).
// L'app prompt l'utilisateur via NPSPrompt component dans MesBilletsScreen pour
// les events passés sans feedback.

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');

// POST /feedback — Soumet un feedback NPS pour un booking de l'user.
// @body {number} booking_id (required)
// @body {number} event_id (optional, recommandé pour stats par event)
// @body {number} rating (required, 1-5)
// @body {string} comment (optional, max 500 chars, truncate au-dela)
//
// Validations :
//   - rating : entier 1-5 (sinon 400)
//   - booking doit appartenir a l'user (sinon 403)
//   - 1 feedback max par (user, booking) → 409 si déjà soumis
router.post('/', auth.authMiddleware, function(req, res) {
  var bookingId = parseInt(req.body.booking_id, 10);
  var eventId = req.body.event_id ? parseInt(req.body.event_id, 10) : null;
  var rating = parseInt(req.body.rating, 10);
  var comment = req.body.comment;

  if (isNaN(bookingId)) {
    return res.status(400).json({ success: false, message: 'booking_id requis' });
  }
  if (isNaN(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ success: false, message: 'Note invalide (1 à 5)' });
  }
  if (eventId !== null && isNaN(eventId)) {
    eventId = null; // Coerce silencieusement plutot que rejeter
  }
  // Truncate comment plutot que rejeter (UX moins frustrante : on garde l'essentiel)
  var commentClean = null;
  if (comment !== undefined && comment !== null) {
    commentClean = String(comment).trim().slice(0, 500);
    if (!commentClean) commentClean = null;
  }

  // Verifie que le booking appartient bien a l'user authentifie
  pool.query('SELECT id, event_id FROM bookings WHERE id = $1 AND user_id = $2', [bookingId, req.userId])
    .then(function(bookingCheck) {
      if (bookingCheck.rows.length === 0) {
        return res.status(403).json({
          success: false,
          message: 'Ce billet ne vous appartient pas ou n\'existe pas'
        });
      }
      // Si eventId pas fourni, le derive du booking (mieux que rien)
      var resolvedEventId = eventId !== null ? eventId : bookingCheck.rows[0].event_id;

      return pool.query(
        'INSERT INTO feedback (user_id, booking_id, event_id, rating, comment) ' +
        'VALUES ($1, $2, $3, $4, $5) RETURNING id, rating, comment, created_at',
        [req.userId, bookingId, resolvedEventId, rating, commentClean]
      )
        .then(function(insertResult) {
          var fb = insertResult.rows[0];
          res.status(201).json({
            success: true,
            feedback: {
              id: fb.id,
              rating: fb.rating,
              comment: fb.comment,
              created_at: fb.created_at,
            },
          });
        });
    })
    .catch(function(err) {
      // 23505 = unique_violation Postgres (déjà soumis)
      if (err && err.code === '23505') {
        return res.status(409).json({
          success: false,
          message: 'Feedback déjà soumis pour ce billet'
        });
      }
      console.error('Erreur POST /feedback:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
