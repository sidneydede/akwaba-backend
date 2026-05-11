// routes/waitlist.js — Liste d'attente sur events sold-out (WAITLIST-01)
//
// Mecanique :
//   - User tap "Rejoindre la liste d'attente" sur fiche event sold-out
//     -> POST /waitlist/:eventId, INSERT row pending (notified_at NULL)
//   - Quand un booking de cet event est annule (hook dans bookings.js),
//     query 1er user waitlist (joined_at ASC, notified_at NULL),
//     UPDATE notified_at NOW + push notif "Une place s'est liberee"
//   - User peut quitter la waitlist a tout moment (DELETE)
//
// Helper notifyNextOnWaitlist(eventId) exporte pour le hook bookings.js.

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var push = require('../services/push');

// POST /waitlist/:eventId — Rejoindre la liste d'attente.
// Idempotent : ON CONFLICT DO NOTHING (refuse silencieusement si deja inscrit).
// Refuse 400 si event a encore des places disponibles (l'user devrait reserver
// directement plutot que rejoindre la waitlist).
router.post('/:eventId', auth.authMiddleware, function(req, res) {
  var eventId = parseInt(req.params.eventId, 10);
  if (isNaN(eventId)) {
    return res.status(400).json({ success: false, message: 'eventId invalide' });
  }

  pool.query('SELECT id, places_restantes FROM events WHERE id = $1', [eventId])
    .then(function(eventCheck) {
      if (eventCheck.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Événement introuvable' });
      }
      var ev = eventCheck.rows[0];
      if (ev.places_restantes > 0) {
        return res.status(400).json({
          success: false,
          message: 'Il reste des places — réserve directement.',
          places_restantes: ev.places_restantes,
        });
      }
      return pool.query(
        'INSERT INTO waitlists (user_id, event_id) VALUES ($1, $2) ' +
        'ON CONFLICT (user_id, event_id) DO NOTHING RETURNING joined_at',
        [req.userId, eventId]
      ).then(function(insertResult) {
        var alreadyExisted = insertResult.rows.length === 0;
        // Calcule la position dans la queue (combien d'users joined_at AVANT moi)
        return pool.query(
          'SELECT COUNT(*)::int + 1 AS position FROM waitlists ' +
          'WHERE event_id = $1 AND joined_at < (SELECT joined_at FROM waitlists WHERE user_id = $2 AND event_id = $1)',
          [eventId, req.userId]
        ).then(function(posResult) {
          res.json({
            success: true,
            waitlist: {
              event_id: eventId.toString(),
              already_existed: alreadyExisted,
              position: parseInt(posResult.rows[0].position, 10) || 1,
            },
          });
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /waitlist/:eventId:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// DELETE /waitlist/:eventId — Quitter la liste d'attente. Idempotent.
router.delete('/:eventId', auth.authMiddleware, function(req, res) {
  var eventId = parseInt(req.params.eventId, 10);
  if (isNaN(eventId)) {
    return res.status(400).json({ success: false, message: 'eventId invalide' });
  }
  pool.query(
    'DELETE FROM waitlists WHERE user_id = $1 AND event_id = $2',
    [req.userId, eventId]
  )
    .then(function(result) {
      res.json({ success: true, removed: result.rowCount > 0 });
    })
    .catch(function(err) {
      console.error('Erreur DELETE /waitlist/:eventId:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /waitlist/mine — Liste des events sur lesquels l'user est en waitlist.
// Renvoie les events avec leur status (notified ou pending) + position.
router.get('/mine', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT w.id, w.event_id, w.joined_at, w.notified_at, ' +
    'e.title, e.date, e.lieu, e.prix_display, e.image_url, e.color, e.emoji, ' +
    'e.places_total, e.places_restantes, ' +
    '(SELECT COUNT(*)::int + 1 FROM waitlists w2 WHERE w2.event_id = w.event_id AND w2.joined_at < w.joined_at) AS position ' +
    'FROM waitlists w JOIN events e ON e.id = w.event_id ' +
    'WHERE w.user_id = $1 AND e.status != \'rejected\' ' +
    'ORDER BY w.joined_at DESC',
    [req.userId]
  )
    .then(function(result) {
      var items = result.rows.map(function(r) {
        return {
          id: r.id,
          event_id: r.event_id.toString(),
          joined_at: r.joined_at,
          notified_at: r.notified_at,
          position: r.position,
          event: {
            id: r.event_id.toString(),
            title: r.title,
            date: r.date,
            lieu: r.lieu,
            prix: r.prix_display,
            image_url: r.image_url,
            color: r.color,
            emoji: r.emoji,
            places_total: r.places_total,
            places_restantes: r.places_restantes,
          },
        };
      });
      res.json({ success: true, waitlists: items });
    })
    .catch(function(err) {
      console.error('Erreur GET /waitlist/mine:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// Helper : notifie le prochain user en waitlist quand une place se libere
// (appele depuis bookings.js cancel handler apres UPDATE places_restantes).
//
// Strategie : prend le 1er user joined_at ASC AVEC notified_at IS NULL.
// UPDATE notified_at NOW dans la meme transaction pour eviter race conditions
// (multi-cancellations simultanees).
//
// Best effort : log errors, jamais throw.
//
// @param {number} eventId
function notifyNextOnWaitlist(eventId) {
  pool.query(
    'SELECT e.title FROM events WHERE id = $1',
    [eventId]
  )
    .then(function(eventResult) {
      if (eventResult.rows.length === 0) return;
      var eventTitle = eventResult.rows[0].title;

      // UPDATE atomique : prend le prochain user pending, mark notified_at NOW.
      // RETURNING user_id pour pouvoir push.
      return pool.query(
        'UPDATE waitlists SET notified_at = NOW() WHERE id = (' +
        '  SELECT id FROM waitlists ' +
        '  WHERE event_id = $1 AND notified_at IS NULL ' +
        '  ORDER BY joined_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED' +
        ') RETURNING user_id',
        [eventId]
      ).then(function(updateResult) {
        if (updateResult.rows.length === 0) {
          // Pas de user pending, rien a faire
          console.log('WAITLIST-01: event', eventId, 'aucun user en waitlist pending');
          return;
        }
        var userId = updateResult.rows[0].user_id;
        push.notifyUser(userId, {
          title: '🎟 Une place s\'est libérée',
          body: 'Tu peux maintenant réserver « ' + (eventTitle || 'cet evenement') + ' »',
          data: {
            type: 'waitlist_slot_available',
            event_id: eventId.toString(),
          },
        });
        console.log('WAITLIST-01: notifie user', userId, 'pour event', eventId);
      });
    })
    .catch(function(err) {
      console.error('Erreur notifyNextOnWaitlist:', err.message);
    });
}

router.notifyNextOnWaitlist = notifyNextOnWaitlist;
module.exports = router;
