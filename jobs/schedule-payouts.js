// jobs/schedule-payouts.js — Auto-scheduling des reversements organisateurs (v2-A)
//
// Pourquoi : sans ce job, l'admin doit déclencher manuellement chaque payout
// événement par événement. Avec, le système crée automatiquement un payout
// 'scheduled' pour chaque event terminé (end_at + escrow_hours dans le passé)
// qui n'a pas encore de payout. L'admin n'a plus qu'à confirmer le release.
//
// Stratégie :
//   - Toutes les heures, cherche les events qui matchent :
//       * status = 'approved'
//       * end_at IS NOT NULL (sinon on ne peut pas calculer la fenêtre escrow)
//       * end_at + escrow_hours <= NOW()
//       * pas de payout actif (status != 'cancelled')
//   - Pour chacun, compute gross/commission/fees/net depuis bookings 'confirme'
//   - Insère un payout 'scheduled', flag auto_release_eligible si conditions remplies
//
// Conditions auto_release_eligible :
//   - net_amount < payout_review_threshold_amount (default 500 000 FCFA)
//   - refund_ratio < payout_review_refund_ratio (default 10%)

var pool = require('../db/pool');

// Lit un setting numérique avec fallback. JSONB côté DB, parseFloat côté JS.
function getSetting(key, fallback) {
  return pool.query('SELECT value FROM app_settings WHERE key = $1', [key])
    .then(function(r) {
      if (r.rows.length === 0) return fallback;
      return r.rows[0].value;
    })
    .catch(function() { return fallback; });
}

// Calcule l'auto_release_eligible flag en fonction des bookings.
// @returns Promise<boolean>
function computeEligibility(eventId, netAmount, thresholdAmount, refundRatioMax) {
  if (netAmount >= thresholdAmount) return Promise.resolve(false);

  return pool.query(
    "SELECT " +
    "COUNT(*) FILTER (WHERE statut = 'confirme')::int AS confirmed, " +
    "COUNT(*) FILTER (WHERE statut = 'rembourse')::int AS refunded " +
    'FROM bookings WHERE event_id = $1',
    [eventId]
  ).then(function(r) {
    var stats = r.rows[0];
    var total = stats.confirmed + stats.refunded;
    if (total === 0) return false;
    var ratio = stats.refunded / total;
    return ratio < refundRatioMax;
  });
}

// Crée un payout 'scheduled' pour un event donné.
// @param {object} event - { id, organizer_id, title, start_at, end_at }
// @param {object} settings - { commissionRate, feeRate, escrowHours, thresholdAmount, refundRatioMax }
// @returns Promise<{created: boolean, payoutId?: number}>
function createPayoutForEvent(event, settings) {
  return pool.query(
    "SELECT COUNT(*)::int AS n, COALESCE(SUM(total_amount), 0)::bigint AS gross " +
    "FROM bookings WHERE event_id = $1 AND statut = 'confirme'",
    [event.id]
  ).then(function(r) {
    var bookings = r.rows[0];
    var gross = parseInt(bookings.gross) || 0;
    if (gross === 0 || bookings.n === 0) {
      // Pas de revenu : pas de payout à créer (l'event a tourné à vide).
      return { created: false };
    }

    var commission = Math.ceil(gross * settings.commissionRate);
    var fees = Math.ceil(gross * settings.feeRate);
    var net = gross - commission - fees;

    var basis = event.end_at || event.start_at;
    var scheduledAt = basis
      ? new Date(new Date(basis).getTime() + settings.escrowHours * 3600 * 1000)
      : new Date();

    return computeEligibility(event.id, net, settings.thresholdAmount, settings.refundRatioMax)
      .then(function(eligible) {
        return pool.query(
          'INSERT INTO payouts (organizer_id, event_id, period_start, period_end, ' +
          'bookings_count, gross_amount, commission_amount, cinetpay_fees, net_amount, ' +
          "status, scheduled_at, auto_release_eligible, notes) " +
          "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'scheduled', $10, $11, $12) RETURNING id",
          [
            event.organizer_id, event.id,
            event.start_at, event.end_at || event.start_at,
            bookings.n, gross, commission, fees, net,
            scheduledAt, eligible,
            'Reversement auto-créé (CRON schedule-payouts) pour « ' + event.title + ' »',
          ]
        ).then(function(insRes) {
          console.log('[schedule-payouts] créé payout #' + insRes.rows[0].id +
            ' pour event "' + event.title + '" (net=' + net + ', eligible=' + eligible + ')');
          return { created: true, payoutId: insRes.rows[0].id, eligible: eligible };
        });
      });
  });
}

// Boucle principale : trouve les events à processer puis applique séquentiellement.
function scheduleDuePayouts() {
  return Promise.all([
    getSetting('commission_rate', 0.06),
    getSetting('cinetpay_fee_rate', 0.015),
    getSetting('escrow_hours', 48),
    getSetting('payout_review_threshold_amount', 500000),
    getSetting('payout_review_refund_ratio', 0.10),
  ])
    .then(function(settingsArr) {
      var settings = {
        commissionRate: parseFloat(settingsArr[0]),
        feeRate: parseFloat(settingsArr[1]),
        escrowHours: parseInt(settingsArr[2]),
        thresholdAmount: parseInt(settingsArr[3]),
        refundRatioMax: parseFloat(settingsArr[4]),
      };

      // SQL : events approved, end_at + escrow <= NOW(), pas de payout actif.
      // COALESCE(end_at, start_at) pour les events sans end_at explicite.
      return pool.query(
        'SELECT e.id, e.organizer_id, e.title, e.start_at, e.end_at ' +
        'FROM events e ' +
        "WHERE e.status = 'approved' " +
        "  AND COALESCE(e.end_at, e.start_at) IS NOT NULL " +
        "  AND COALESCE(e.end_at, e.start_at) + (INTERVAL '1 hour' * $1) <= NOW() " +
        "  AND NOT EXISTS (" +
        "    SELECT 1 FROM payouts p WHERE p.event_id = e.id AND p.status != 'cancelled'" +
        '  )' +
        ' LIMIT 50',
        [settings.escrowHours]
      ).then(function(eventsRes) {
        if (eventsRes.rows.length === 0) {
          return { events_found: 0, payouts_created: 0 };
        }
        console.log('[schedule-payouts] ' + eventsRes.rows.length + ' event(s) à processer');

        // Séquentiel pour ne pas saturer la DB et avoir des logs lisibles.
        return eventsRes.rows.reduce(function(p, ev) {
          return p.then(function(stats) {
            return createPayoutForEvent(ev, settings)
              .then(function(result) {
                return {
                  events_found: stats.events_found + 1,
                  payouts_created: stats.payouts_created + (result.created ? 1 : 0),
                };
              })
              .catch(function(err) {
                console.error('[schedule-payouts] erreur event ' + ev.id + ':', err.message);
                return stats;
              });
          });
        }, Promise.resolve({ events_found: 0, payouts_created: 0 }));
      });
    })
    .then(function(stats) {
      if (stats.payouts_created > 0) {
        console.log('[schedule-payouts] terminé : ' + stats.payouts_created + '/' +
          stats.events_found + ' payouts créés');
      }
      return stats;
    })
    .catch(function(err) {
      console.error('[schedule-payouts] erreur globale:', err.message);
      return { events_found: 0, payouts_created: 0, error: err.message };
    });
}

// Démarre le job périodique. 1h par défaut — on n'a pas besoin de plus de précision
// pour J+2, et ça limite la charge DB.
function start(intervalMs) {
  var ms = intervalMs || 3600 * 1000;
  // Premier run après 60s (pour ne pas tourner pendant le boot)
  setTimeout(function() {
    scheduleDuePayouts();
    setInterval(scheduleDuePayouts, ms);
  }, 60 * 1000);
  console.log('[schedule-payouts] worker actif (toutes les ' + (ms / 60000) + ' min)');
}

module.exports = { start: start, scheduleDuePayouts: scheduleDuePayouts };
