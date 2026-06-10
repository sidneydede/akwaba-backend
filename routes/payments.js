// routes/payments.js — Webhooks paiement (Paystack actif, CinetPay legacy)
//
// Routes :
//   POST /payments/paystack-notify — webhook Paystack (charge/transfer/refund)
//   POST /payments/notify          — webhook CinetPay (legacy, sera supprime)
//   POST /payments/verify          — lookup statut transaction depuis la DB

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var push = require('../services/push');
var cinetpay = require('../services/cinetpay');
var paystack = require('../services/paystack');

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

// REF-01 : Si l'user qui vient de booking_confirmed a un referral pending et
// que le bonus parrain n'a pas encore ete delivre, on award 200 pts au parrain
// + push notif. Idempotent : la condition parrain_points_awarded = false +
// status = 'pending' s'execute UNE fois (UPDATE atomique).
//
// Appele apres notifyBookingConfirmed dans le webhook /payments/notify.
// Best effort : log les erreurs mais ne throw jamais (booking confirme reste OK).
function awardReferralBonusIfEligible(bookingId) {
  pool.query(
    'SELECT b.user_id, u.prenom AS filleul_prenom FROM bookings b ' +
    'JOIN users u ON u.id = b.user_id WHERE b.id = $1',
    [bookingId]
  )
    .then(function(bookingResult) {
      if (bookingResult.rows.length === 0) return;
      var filleulId = bookingResult.rows[0].user_id;
      var filleulPrenom = bookingResult.rows[0].filleul_prenom;

      // UPDATE atomique : marque le referral confirmed + retourne parrain_id et points si eligible.
      // Si pas de row affecte (pas de referral pending OU deja awarded), pas de side-effect.
      return pool.query(
        'UPDATE referrals SET status = \'confirmed\', parrain_points_awarded = true, ' +
        'confirmed_at = NOW() ' +
        'WHERE filleul_id = $1 AND status = \'pending\' AND parrain_points_awarded = false ' +
        'RETURNING parrain_id, points_parrain',
        [filleulId]
      ).then(function(refResult) {
        if (refResult.rows.length === 0) return; // Pas eligible (pas de referral, ou deja award)
        var parrainId = refResult.rows[0].parrain_id;
        var pointsParrain = refResult.rows[0].points_parrain;

        // Award points au parrain
        return pool.query(
          'UPDATE users SET points = COALESCE(points, 0) + $1 WHERE id = $2',
          [pointsParrain, parrainId]
        ).then(function() {
          // Push notif au parrain
          push.notifyUser(parrainId, {
            title: '🎁 Bonus parrainage',
            body: filleulPrenom + ' vient de réserver son 1er événement ! Tu as gagné ' + pointsParrain + ' pts.',
            data: {
              type: 'referral_confirmed',
              filleul_prenom: filleulPrenom,
              points: pointsParrain,
            }
          });
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur awardReferralBonusIfEligible:', err.message);
    });
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

          // Paiement vraiment confirmé : on update le booking. Match STRICT
          // sur transaction_id uniquement (le booking est rattaché à transac
          // dès l'init paiement). Le match sur ref a été retiré (SEC-SPRINT0)
          // car il permettait des cross-confirmations si transaction_id était
          // accidentellement = à un ref booking d'un autre user.
          return pool.query(
            "UPDATE bookings SET statut = 'confirme', updated_at = NOW() " +
            "WHERE transaction_id = $1 AND statut != 'confirme' RETURNING id",
            [transactionId]
          )
            .then(function(updateResult) {
              updateResult.rows.forEach(function(row) {
                notifyBookingConfirmed(row.id);
                // REF-01 : check si l'user a un referral pending → award bonus parrain
                awardReferralBonusIfEligible(row.id);
              });
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

// ============================================================
// Paystack webhook — dispatcher d'events
// ============================================================
//
// Paystack envoie des events typés (charge.success, transfer.success, etc.)
// avec une signature HMAC-SHA512 du raw body dans le header x-paystack-signature.
// Le verify callback de express.json() dans server.js capture req.rawBody.
//
// Events gérés :
//   - charge.success      → confirme le booking (statut='confirme')
//   - transfer.success    → marque le payout comme transferred
//   - transfer.failed     → marque le payout comme failed (admin re-trigger)
//   - transfer.reversed   → idem failed (fonds retournés)
//   - refund.processed    → marque le refund booking comme paid
//   - refund.failed       → marque le refund booking comme failed
//
// On répond TOUJOURS 200 quand on a accusé réception (même si on ignore
// l'event ou que la transac n'est pas la nôtre) pour éviter que Paystack
// retente indéfiniment.
router.post('/paystack-notify', function(req, res) {
  var signature = req.headers['x-paystack-signature'];
  var rawBody = req.rawBody;
  var body = req.body || {};
  var eventType = body.event || 'unknown';

  console.log('Webhook Paystack reçu:', eventType, body.data && body.data.reference);

  // Couche unique : Paystack n'a pas d'API "check-by-id" comme CinetPay
  // (verifyTransaction n'est utilisé que pour charges). La signature HMAC
  // est donc la seule défense — c'est ce que Paystack documente. Fail-closed.
  if (!paystack.verifyWebhookSignature(rawBody, signature)) {
    console.error('Webhook Paystack : signature HMAC invalide pour', eventType);
    return res.status(401).json({ success: false, message: 'Signature invalide' });
  }

  var data = body.data || {};
  var reference = data.reference || (data.transaction && data.transaction.reference);

  // ─── charge.success ──────────────────────────────────────────────────
  // Equivalent du webhook CinetPay : confirme le booking. On double-check
  // via verifyTransaction pour matcher le pattern fail-safe historique
  // (un attaquant qui aurait la clé secrète et forgerait un webhook serait
  // démasqué ici parce que la transac n'existe pas vraiment chez Paystack).
  if (eventType === 'charge.success') {
    if (!reference) {
      return res.status(400).json({ success: false, message: 'Reference manquante' });
    }
    return paystack.verifyTransaction(reference)
      .then(function(check) {
        var realStatus = check.status;
        var realAmount = check.amount || 0;
        return pool.query(
          'INSERT INTO payments (transaction_id, amount, method, status, cinetpay_data) ' +
          'VALUES ($1, $2, $3, $4, $5) ' +
          'ON CONFLICT (transaction_id) DO UPDATE SET status = $4, cinetpay_data = $5, updated_at = NOW() RETURNING *',
          [reference, realAmount, 'paystack', realStatus, JSON.stringify({ webhook: body, check: check.raw })]
        )
          .then(function() {
            if (!check.ok) {
              console.log('Webhook Paystack : transac non success selon API:', reference, realStatus);
              return res.json({ success: true, message: 'Webhook enregistré, statut: ' + realStatus });
            }
            // SEC C1 : avant de confirmer, vérifier que le montant réellement
            // encaissé couvre le montant dû du booking. Sans ça, une transac
            // 'success' forgée/réutilisée pour un faible montant rattachée à
            // une ref connue (la ref est renvoyée au client) confirmerait un
            // billet sous-payé. realAmount est en FCFA naturel (fromSubunit),
            // total_amount aussi → comparables directement.
            return pool.query(
              "SELECT COALESCE(SUM(total_amount), 0) AS due, COUNT(*) AS n " +
              "FROM bookings WHERE transaction_id = $1 AND statut != 'confirme'",
              [reference]
            ).then(function(dueRes) {
              var n = parseInt(dueRes.rows[0].n, 10);
              if (n === 0) {
                return res.json({ success: true, message: 'Aucun booking en attente pour cette référence' });
              }
              var due = Number(dueRes.rows[0].due) || 0;
              if (realAmount < due) {
                console.error('[paystack] SOUS-PAIEMENT détecté ref=' + reference +
                  ' payé=' + realAmount + ' dû=' + due + ' — booking NON confirmé');
                return res.json({ success: true, message: 'Montant insuffisant — réservation non confirmée' });
              }
              return pool.query(
                "UPDATE bookings SET statut = 'confirme', updated_at = NOW() " +
                "WHERE transaction_id = $1 AND statut != 'confirme' RETURNING id",
                [reference]
              )
                .then(function(updateResult) {
                  updateResult.rows.forEach(function(row) {
                    notifyBookingConfirmed(row.id);
                    awardReferralBonusIfEligible(row.id);
                  });
                  res.json({
                    success: true,
                    message: 'Paiement vérifié et réservation confirmée',
                    bookings_confirmed: updateResult.rows.length,
                  });
                });
            });
          });
      })
      .catch(function(err) {
        console.error('Erreur webhook charge.success:', err.message);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
      });
  }

  // ─── transfer.success / transfer.failed / transfer.reversed ──────────
  // reference = celle qu'on a envoyée à /transfer (format 'PAYOUT-N').
  // On l'utilise pour matcher la ligne payouts.
  if (eventType === 'transfer.success' || eventType === 'transfer.failed' || eventType === 'transfer.reversed') {
    var transferRef = data.reference || data.transfer_code;
    if (!transferRef) {
      return res.json({ success: true, message: 'Reference transfer manquante, ignoré' });
    }
    // Extrait l'id payout depuis 'PAYOUT-N'. Si pattern différent, on lookup
    // par transfer_reference (fallback).
    var payoutId = null;
    var m = String(transferRef).match(/^PAYOUT-(\d+)$/);
    if (m) payoutId = parseInt(m[1], 10);

    var newTransferStatus = eventType === 'transfer.success' ? 'success' : (eventType === 'transfer.failed' ? 'failed' : 'reversed');

    var updateQuery, updateParams;
    if (payoutId) {
      updateQuery = 'UPDATE payouts SET transfer_status = $1, transfer_data = $2, updated_at = NOW() WHERE id = $3 RETURNING id';
      updateParams = [newTransferStatus, JSON.stringify(body), payoutId];
    } else {
      updateQuery = 'UPDATE payouts SET transfer_status = $1, transfer_data = $2, updated_at = NOW() WHERE transfer_reference = $3 RETURNING id';
      updateParams = [newTransferStatus, JSON.stringify(body), transferRef];
    }
    return pool.query(updateQuery, updateParams)
      .then(function(r) {
        console.log('Webhook Paystack ' + eventType + ' : payout', r.rows.length, 'maj');
        res.json({ success: true, message: eventType + ' enregistré', payouts_updated: r.rows.length });
      })
      .catch(function(err) {
        console.error('Erreur webhook ' + eventType + ':', err.message);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
      });
  }

  // ─── refund.processed / refund.failed ────────────────────────────────
  // data.transaction.reference = la ref initiale du paiement (notre booking ref).
  if (eventType === 'refund.processed' || eventType === 'refund.failed') {
    var refundedTx = (data.transaction && data.transaction.reference) || data.reference;
    if (!refundedTx) {
      return res.json({ success: true, message: 'Reference transac refund manquante, ignoré' });
    }
    var newRefundStatus = eventType === 'refund.processed' ? 'paid' : 'failed';
    return pool.query(
      'UPDATE bookings SET refund_status = $1, refund_paid_at = ' +
      "CASE WHEN $1 = 'paid' THEN NOW() ELSE refund_paid_at END, updated_at = NOW() " +
      'WHERE transaction_id = $2 RETURNING id',
      [newRefundStatus, refundedTx]
    )
      .then(function(r) {
        console.log('Webhook Paystack ' + eventType + ' : booking', r.rows.length, 'maj');
        res.json({ success: true, message: eventType + ' enregistré', bookings_updated: r.rows.length });
      })
      .catch(function(err) {
        console.error('Erreur webhook ' + eventType + ':', err.message);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
      });
  }

  // Events non gérés (charge.failed, customeridentification.*, etc.) :
  // on accuse réception pour ne pas faire retenter Paystack.
  console.log('Webhook Paystack ignoré:', eventType);
  res.json({ success: true, message: 'Event ignoré: ' + eventType });
});

module.exports = router;
