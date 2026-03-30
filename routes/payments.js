// routes/payments.js — Webhook CinetPay et vérification paiement
// POST /payments/notify : webhook appelé par CinetPay après paiement

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');

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
          "UPDATE bookings SET statut = 'confirme', transaction_id = $1, updated_at = NOW() WHERE transaction_id = $1 OR ref = $1",
          [transactionId]
        )
          .then(function() {
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
