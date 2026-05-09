// routes/payments.js — Webhook CinetPay et vérification paiement
// POST /payments/notify : webhook appelé par CinetPay après paiement

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var push = require('../services/push');
var cinetpay = require('../services/cinetpay');

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
// Sécurité (deux couches) :
//   1. Vérification HMAC du header x-token (signature partagée avec CinetPay).
//   2. Double-check API : interroge directement CinetPay /v2/payment/check pour
//      confirmer le statut réel de la transaction. Sans cette double vérification,
//      n'importe qui pourrait POST sur /payments/notify pour valider de faux paiements.
// @header {string} x-token - HMAC-SHA256 du payload (clé : CINETPAY_SECRET_KEY)
// @body {string} cpm_trans_id, cpm_site_id, cpm_trans_status, ...
router.post('/notify', function(req, res) {
  var transactionId = req.body.cpm_trans_id;
  var method = req.body.payment_method || 'unknown';
  var headerToken = req.headers['x-token'];

  console.log('Webhook CinetPay reçu:', transactionId);

  if (!transactionId) {
    return res.status(400).json({ success: false, message: 'Transaction ID manquant' });
  }

  // Couche 1 : vérification HMAC. Rejette les appels manifestement contrefaits sans
  // payer le coût d'un appel API. Skip silencieusement si SECRET_KEY pas configurée.
  if (!cinetpay.verifyHmacToken(req.body, headerToken)) {
    console.error('Webhook CinetPay : signature HMAC invalide pour', transactionId);
    return res.status(401).json({ success: false, message: 'Signature invalide' });
  }

  // Couche 2 : double-check via API CinetPay. C'est l'autorité finale — un faux webhook
  // qui passerait le HMAC échouerait ici car la transaction n'existerait pas chez CinetPay.
  cinetpay.verifyTransactionWithApi(transactionId)
    .then(function(check) {
      var realStatus = check.status; // 'ACCEPTED' | 'REFUSED' | 'PENDING' | etc.
      var realAmount = check.amount || 0;

      // Toujours enregistrer la transaction pour audit, même si non validée.
      // Idempotence : ON CONFLICT met à jour le statut sans créer de doublon.
      return pool.query(
        'INSERT INTO payments (transaction_id, amount, method, status, cinetpay_data) ' +
        'VALUES ($1, $2, $3, $4, $5) ' +
        'ON CONFLICT (transaction_id) DO UPDATE SET status = $4, cinetpay_data = $5, updated_at = NOW() RETURNING *',
        [transactionId, realAmount, method, realStatus, JSON.stringify({ webhook: req.body, check: check.raw })]
      )
        .then(function() {
          if (!check.ok) {
            // Paiement non confirmé par CinetPay : on accuse réception au webhook (pour
            // qu'il ne retente pas indéfiniment) mais on ne confirme pas la réservation.
            console.log('Webhook CinetPay : transaction non ACCEPTED selon API:', transactionId, realStatus);
            return res.json({ success: true, message: 'Webhook enregistré, statut: ' + realStatus });
          }

          // Paiement vraiment confirmé : on update le booking.
          // On match par transaction_id (déjà rattaché lors de l'init paiement) ou ref.
          return pool.query(
            "UPDATE bookings SET statut = 'confirme', transaction_id = $1, updated_at = NOW() " +
            "WHERE (transaction_id = $1 OR ref = $1) AND statut != 'confirme' RETURNING id",
            [transactionId]
          )
            .then(function(updateResult) {
              updateResult.rows.forEach(function(row) { notifyBookingConfirmed(row.id); });
              res.json({
                success: true,
                message: 'Paiement vérifié et réservation confirmée',
                bookings_confirmed: updateResult.rows.length,
              });
            });
        });
    })
    .catch(function(err) {
      console.error('Erreur webhook /payments/notify:', err.message);
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
