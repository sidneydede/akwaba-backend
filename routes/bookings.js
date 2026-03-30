// routes/bookings.js — Gestion des réservations / billets
// POST /bookings : créer une réservation, GET /bookings : mes billets

var express = require('express');
var router = express.Router();
var crypto = require('crypto');
var pool = require('../db/pool');
var auth = require('../middleware/auth');

// Génère une référence unique pour le billet
// @returns {string} Référence au format AKW-XXXXXXXX
function generateRef() {
  return 'AKW-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

// POST /bookings — Créer une réservation
// @body {number} eventId, {string} paiement, {number} quantity
router.post('/', auth.authMiddleware, function(req, res) {
  var eventId = req.body.eventId;
  var paiement = req.body.paiement;
  var quantity = parseInt(req.body.quantity) || 1;

  if (!eventId) {
    return res.status(400).json({
      success: false,
      message: 'eventId est obligatoire'
    });
  }

  // Récupère l'événement pour vérifier les places et le prix
  pool.query('SELECT id, title, prix, prix_display, places_restantes FROM events WHERE id = $1', [eventId])
    .then(function(eventResult) {
      if (eventResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Événement non trouvé'
        });
      }

      var event = eventResult.rows[0];

      if (event.places_restantes < quantity) {
        return res.status(400).json({
          success: false,
          message: 'Plus assez de places disponibles'
        });
      }

      var ref = generateRef();
      var totalAmount = event.prix * quantity;

      // Crée la réservation
      return pool.query(
        "INSERT INTO bookings (user_id, event_id, ref, quantity, total_amount, paiement_method, statut) VALUES ($1, $2, $3, $4, $5, $6, 'en_attente') RETURNING *",
        [req.userId, eventId, ref, quantity, totalAmount, paiement]
      )
        .then(function(bookingResult) {
          var booking = bookingResult.rows[0];

          // Décrémente les places restantes
          return pool.query(
            'UPDATE events SET places_restantes = places_restantes - $1 WHERE id = $2',
            [quantity, eventId]
          )
            .then(function() {
              res.status(201).json({
                success: true,
                message: 'Réservation confirmée',
                booking: {
                  id: booking.id.toString(),
                  eventId: booking.event_id.toString(),
                  ref: booking.ref,
                  quantity: booking.quantity,
                  total_amount: totalAmount,
                  paiement: booking.paiement_method,
                  statut: booking.statut,
                  createdAt: booking.created_at
                }
              });
            });
        });
    })
    .catch(function(err) {
      console.error('Erreur POST /bookings:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /bookings — Liste les billets de l'utilisateur connecté
router.get('/', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT b.id, b.ref, b.quantity, b.total_amount, b.paiement_method, b.statut, b.created_at, ' +
    'e.title, e.date, e.lieu, e.prix_display, e.emoji, e.color, e.category ' +
    'FROM bookings b JOIN events e ON b.event_id = e.id ' +
    'WHERE b.user_id = $1 ORDER BY b.created_at DESC',
    [req.userId]
  )
    .then(function(result) {
      var billets = result.rows.map(function(row) {
        return {
          id: row.id.toString(),
          ref: row.ref,
          quantity: row.quantity,
          total_amount: row.total_amount,
          paiement: row.paiement_method,
          statut: row.statut,
          created_at: row.created_at,
          event: {
            title: row.title,
            date: row.date,
            lieu: row.lieu,
            prix: row.prix_display,
            emoji: row.emoji,
            color: row.color,
            category: row.category
          }
        };
      });

      res.json({ success: true, billets: billets });
    })
    .catch(function(err) {
      console.error('Erreur GET /bookings:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /bookings/:id/confirm — Confirme une réservation (après paiement)
router.patch('/:id/confirm', function(req, res) {
  var bookingId = req.params.id;
  var transactionId = req.body.transaction_id;

  pool.query(
    "UPDATE bookings SET statut = 'confirme', transaction_id = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    [transactionId, bookingId]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Réservation non trouvée' });
      }

      res.json({
        success: true,
        message: 'Réservation confirmée',
        booking: result.rows[0]
      });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /bookings/:id/confirm:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
