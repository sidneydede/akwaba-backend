// jobs/data-retention.js — Nettoyage automatique des données expirées (RGPD).
//
// Stratégie : tick toutes les 24h, delete les rows au-delà de la rétention
// définie par table. Désactivable via DISABLE_DATA_RETENTION=true (utile
// en dev pour ne pas perdre les test data).
//
// Tables couvertes :
//   - search_queries : 90 jours (signal acquisition produit, pas un audit légal)
//   - admin_digests  : 180 jours (historique digests, regénérables)
//   - admin_audit_log : 365 jours (conformité RGPD article 30 — registre des
//     traitements, mais on peut anonymiser admin_id après 1 an)
//
// Conservation explicite (NE pas toucher) :
//   - bookings, payments, payouts : retention illimitée (comptable + fiscal CI)
//   - users : retention illimitée (compte actif)
//   - admin_notes : retention illimitée (historique opérationnel)
//   - support_tickets / support_messages : retention illimitée (résolution incidents)

var pool = require('../db/pool');

function tick() {
  var start = Date.now();
  return Promise.all([
    pool.query("DELETE FROM search_queries WHERE created_at < NOW() - INTERVAL '90 days'"),
    pool.query("DELETE FROM admin_digests WHERE digest_date < (CURRENT_DATE - INTERVAL '180 days')"),
    pool.query("DELETE FROM admin_audit_log WHERE created_at < NOW() - INTERVAL '365 days'"),
    // ONBOARDING-DEFER : pending_registrations abandonnés > 24h. L'OTP
    // expire en 5-10 min de toute façon, donc 24h est large.
    pool.query("DELETE FROM pending_registrations WHERE created_at < NOW() - INTERVAL '24 hours'"),
  ])
    .then(function(results) {
      var counts = {
        search_queries: results[0].rowCount || 0,
        admin_digests: results[1].rowCount || 0,
        admin_audit_log: results[2].rowCount || 0,
        pending_registrations: results[3].rowCount || 0,
      };
      var total = counts.search_queries + counts.admin_digests + counts.admin_audit_log + counts.pending_registrations;
      var elapsedMs = Date.now() - start;
      if (total > 0) {
        console.log('[data-retention] Deleted ' + total + ' expired rows in ' +
          elapsedMs + 'ms — ' + JSON.stringify(counts));
      }
      return counts;
    })
    .catch(function(err) {
      console.error('[data-retention] erreur tick:', err.message);
    });
}

// Tick chaque 24h. Premier run 5 min après boot pour laisser le serveur se
// stabiliser (et ne pas mettre la DB sous pression pendant warm-up).
function start(intervalMs) {
  var ms = intervalMs || 24 * 60 * 60 * 1000; // 24h
  setTimeout(function() {
    tick();
    setInterval(tick, ms);
  }, 5 * 60 * 1000);
  console.log('[data-retention] worker actif (tick toutes les ' +
    (ms / 60000 / 60) + ' h)');
}

module.exports = { start: start, tick: tick };
