// routes/payments.js — Webhook CinetPay et vérification paiement
// POST /payments/notify : webhook appelé par CinetPay après paiement

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var push = require('../services/push');

// Notifie participant + organisateur quand un booking est confirmé via webhook
// (factorisé pour éviter la duplication avec routes/bookings.js).
function notifyBookingConfirmed(bookingId) {
  pool.query(
    'SELECT b.id, b.ref, b.quantity, b.user_id, e.id AS event_id, e.title, e.organizer_id ' +
    'FROM bookings b JOIN events e ON b.event_id = e.id WHERE b.id = $1',
    [bookingId]
  )
    .then(function(result) {
      if (result.rows.length === 0) return;
      var b = result.rows[0];
      push.notifyUser(b.user_id, {
        title: 'Billet confirmé 🎟️',
        body: '« ' + b.title + ' » — réf ' + b.ref + (b.quantity > 1 ? ' (' + b.quantity + ' places)' : ''),
        data: { type: 'booking_confirmed', bookingId: b.id.toString(), eventId: b.event_id.toString() }
      });
      if (b.organizer_id && b.organizer_id !== b.user_id) {
        push.notifyUser(b.organizer_id, {
          title: 'Nouvelle vente 💰',
          body: b.quantity + ' billet' + (b.quantity > 1 ? 's' : '') + ' vendu' + (b.quantity > 1 ? 's' : '') + ' sur « ' + b.title + ' »',
          data: { type: 'sale', bookingId: b.id.toString(), eventId: b.event_id.toString() }
        });
      }
    })
    .catch(function(err) { console.error('Erreur notifyBookingConfirmed (webhook):', err.message); });
}

// POST /payments/notify — Webhook CinetPay
// CinetPay envoie une notification quand le paiement est traité
// @body {string} cpm_trans_id, cpm_site_id, cpm_trans_status, ...
router.post('/notify', function(req, res) {
  var transactionId = req.body.cpm_trans_id;
  var status = req.body.cpm_trans_status || req.body.status;
  var amount = parseInt(req.body.cpm_amount) || 0;
  var method = req.body.payment_method || 'unknown';

  console.log('Webhook CinetPay reçu:', transactionId, status);

  if (!transactionId) {
    return res.status(400).json({ success: false, message: 'Transaction ID manquant' });
  }

  // Enregistre le paiement
  pool.query(
    'INSERT INTO payments (transaction_id, amount, method, status, cinetpay_data) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (transaction_id) DO UPDATE SET status = $4, cinetpay_data = $5, updated_at = NOW() RETURNING *',
    [transactionId, amount, method, status, JSON.stringify(req.body)]
  )
    .then(function(paymentResult) {
      // Si le paiement est accepté, confirme la réservation associée
      if (status === 'ACCEPTED' || status === '00') {
        return pool.query(
          "UPDATE bookings SET statut = 'confirme', transaction_id = $1, updated_at = NOW() WHERE transaction_id = $1 OR ref = $1 RETURNING id",
          [transactionId]
        )
          .then(function(updateResult) {
            updateResult.rows.forEach(function(row) {
              notifyBookingConfirmed(row.id);
            });
            res.json({ success: true, message: 'Paiement enregistré et réservation confirmée' });
          });
      }

      res.json({ success: true, message: 'Paiement enregistré', status: status });
    })
    .catch(function(err) {
      console.error('Erreur webhook paiement:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /payments/verify — Vérifie le statut d'un paiement
// @body {string} transaction_id
router.post('/verify', function(req, res) {
  var transactionId = req.body.transaction_id;

  if (!transactionId) {
    return res.status(400).json({ success: false, message: 'Transaction ID manquant' });
  }

  pool.query('SELECT * FROM payments WHERE transaction_id = $1', [transactionId])
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.json({
          success: true,
          status: 'NOT_FOUND',
          message: 'Aucun paiement trouvé pour cette transaction'
        });
      }

      var payment = result.rows[0];
      res.json({
        success: true,
        status: payment.status,
        amount: payment.amount,
        method: payment.method,
        created_at: payment.created_at
      });
    })
    .catch(function(err) {
      console.error('Erreur verify paiement:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
