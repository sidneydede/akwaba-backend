// jobs/reconcile-payments.js — Réconciliation périodique des paiements Paystack
//
// Pourquoi : un utilisateur peut être débité (Orange Money prélève) sans que le webhook
// /payments/paystack-notify n'arrive. Latence MoMo CI fréquente (3-5 min), webhook qui
// échoue côté Paystack, app fermée avant retour. Sans ce job, un booking 'en_attente'
// reste bloqué, l'utilisateur a payé pour rien et la place est immobilisée.
//
// Stratégie :
//   - Toutes les 60 secondes, on prend les bookings 'en_attente' avec un transaction_id,
//     créés il y a > 2 min mais < 30 min (au-delà on considère expiré).
//   - On interroge GET /transaction/verify/:reference Paystack pour chaque ref.
//   - status='success'  → on confirme le booking (idem webhook).
//   - status='failed'|'abandoned' → on annule le booking et on relâche les places.
//   - status='ongoing'|'pending'  → on laisse passer un cycle.
//   - Au-delà de 30 min : on annule par timeout.

var pool = require('../db/pool');
var paystack = require('./../services/paystack');
var push = require('../services/push');

// Notifications copiées de bookings.js — DRY non strict pour éviter import circulaire.
function notifyConfirmed(b) {
  push.notifyUser(b.user_id, {
    title: 'Billet confirmé 🎟️',
    body: '« ' + b.title + ' » — réf ' + b.ref,
    data: { type: 'booking_confirmed', bookingId: b.id.toString(), eventId: b.event_id.toString() }
  });
  if (b.organizer_id && b.organizer_id !== b.user_id) {
    push.notifyUser(b.organizer_id, {
      title: 'Nouvelle vente 💰',
      body: b.quantity + ' billet' + (b.quantity > 1 ? 's' : '') + ' vendu sur « ' + b.title + ' »',
      data: { type: 'sale', bookingId: b.id.toString(), eventId: b.event_id.toString() }
    });
  }
}
function notifyFailed(b) {
  push.notifyUser(b.user_id, {
    title: 'Paiement échoué',
    body: '« ' + b.title + ' » — ton paiement n\'a pas pu être confirmé. Aucun débit final.',
    data: { type: 'payment_failed', bookingId: b.id.toString() }
  });
}

// Traite un booking : interroge Paystack et applique le verdict.
// @param {object} b - Booking row joint avec event
// @returns {Promise<string>} - Verdict appliqué ('confirme' | 'annule' | 'pending' | 'skip')
function reconcileOne(b) {
  return paystack.verifyTransaction(b.transaction_id)
    .then(function(check) {
      var status = check.status;

      // Paystack confirme : on transite vers 'confirme' (idempotent — autre process
      // pourrait avoir déjà confirmé via le webhook entre-temps, on accepte).
      if (status === 'success') {
        return pool.query(
          "UPDATE bookings SET statut = 'confirme', updated_at = NOW() " +
          "WHERE id = $1 AND statut = 'en_attente' RETURNING id",
          [b.id]
        ).then(function(r) {
          if (r.rowCount > 0) {
            console.log('[reconcile] confirmé', b.ref);
            notifyConfirmed(b);
            // Met aussi à jour la table payments
            pool.query(
              'INSERT INTO payments (transaction_id, amount, method, status, booking_id) VALUES ($1, $2, $3, $4, $5) ' +
              'ON CONFLICT (transaction_id) DO UPDATE SET status = $4, booking_id = $5, updated_at = NOW()',
              [b.transaction_id, b.total_amount, b.paiement_method, 'success', b.id]
            ).catch(function(e) { console.error('[reconcile] erreur payments insert:', e.message); });
          }
          return 'confirme';
        });
      }

      // Paystack refuse : on annule et on relâche les places.
      if (status === 'failed' || status === 'abandoned' || status === 'reversed') {
        return pool.query(
          "UPDATE bookings SET statut = 'annule', updated_at = NOW() " +
          "WHERE id = $1 AND statut = 'en_attente' RETURNING id",
          [b.id]
        ).then(function(r) {
          if (r.rowCount === 0) return 'skip';
          return pool.query(
            'UPDATE events SET places_restantes = places_restantes + $1 WHERE id = $2',
            [b.quantity, b.event_id]
          ).then(function() {
            console.log('[reconcile] annulé (paiement', status + ')', b.ref);
            notifyFailed(b);
            return 'annule';
          });
        });
      }

      // ongoing / pending / processing : on laisse encore mariner
      return 'pending';
    })
    .catch(function(err) {
      // Erreur réseau Paystack : on retentera au cycle suivant. Ne pas re-throw pour
      // ne pas casser la batch — un booking mort ne doit pas bloquer les autres.
      console.error('[reconcile] erreur ' + b.ref + ':', err.message);
      return 'error';
    });
}

// Boucle de réconciliation. Pas de Promise.all pour éviter de saturer Paystack
// (séquentiel, max 50 bookings par tick — au-delà c'est qu'il y a un problème plus large).
function reconcilePending() {
  return pool.query(
    'SELECT b.id, b.ref, b.transaction_id, b.user_id, b.event_id, b.quantity, ' +
    'b.total_amount, b.paiement_method, b.created_at, ' +
    'e.title, e.organizer_id ' +
    'FROM bookings b JOIN events e ON e.id = b.event_id ' +
    "WHERE b.statut = 'en_attente' " +
    'AND b.transaction_id IS NOT NULL ' +
    "AND b.created_at < NOW() - INTERVAL '2 minutes' " +
    "AND b.created_at > NOW() - INTERVAL '30 minutes' " +
    'ORDER BY b.created_at ASC LIMIT 50'
  )
    .then(function(result) {
      if (result.rows.length === 0) return;
      console.log('[reconcile] ' + result.rows.length + ' booking(s) en attente à vérifier');

      // Séquentiel via reduce-promise pour limiter la charge CinetPay.
      return result.rows.reduce(function(p, b) {
        return p.then(function() { return reconcileOne(b); });
      }, Promise.resolve());
    })
    .then(function() {
      // Bookings >30 min : timeout définitif. On annule + relâche les places sans appel API.
      return pool.query(
        "UPDATE bookings SET statut = 'annule', updated_at = NOW() " +
        "WHERE statut = 'en_attente' AND created_at < NOW() - INTERVAL '30 minutes' " +
        'RETURNING id, event_id, quantity, ref'
      );
    })
    .then(function(timeoutResult) {
      if (!timeoutResult || timeoutResult.rows.length === 0) return;
      console.log('[reconcile] ' + timeoutResult.rows.length + ' booking(s) timeout > 30min');
      // Relâche les places en batch
      var promises = timeoutResult.rows.map(function(b) {
        return pool.query(
          'UPDATE events SET places_restantes = places_restantes + $1 WHERE id = $2',
          [b.quantity, b.event_id]
        );
      });
      return Promise.all(promises);
    })
    .catch(function(err) {
      console.error('[reconcile] erreur globale:', err.message);
    });
}

// Démarre la réconciliation périodique. Appelé une fois depuis server.js.
function start(intervalMs) {
  var ms = intervalMs || 60000;
  // Premier run après 30s pour ne pas tourner pendant le boot
  setTimeout(function() {
    reconcilePending();
    setInterval(reconcilePending, ms);
  }, 30000);
  console.log('[reconcile] worker actif (toutes les ' + (ms / 1000) + 's)');
}

module.exports = { start: start, reconcilePending: reconcilePending };
