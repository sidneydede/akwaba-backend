// jobs/event-reminders.js — Rappels push J-1 et H-2 avant l'événement (NOTIF-01).
//
// Pourquoi : c'est la fonctionnalité qui fait revenir les utilisateurs et
// réduit drastiquement les no-shows. Sans rappels, l'orga vend des billets
// que personne n'utilise → mauvaise réputation, taux de remplissage faible.
//
// Stratégie :
//   - Toutes les 30 min, scanner :
//       * Bookings 'confirme' avec event.start_at dans NOW+23h ... NOW+25h
//         ET reminder_sent_d1 = false   → envoie rappel J-1
//       * Bookings 'confirme' avec event.start_at dans NOW+1h45 ... NOW+2h15
//         ET reminder_sent_h2 = false   → envoie rappel H-2
//   - UPDATE le flag immédiatement pour éviter doublons même si le push échoue.
//   - Bookings sans event.start_at : skip (legacy, non rappelable).

var pool = require('../db/pool');
var push = require('../services/push');

// Format date FR pour le body du push : "ce soir 20h00", "demain 14h", "à 16h30"
function formatHumanTime(startAtIso) {
  var d = new Date(startAtIso);
  var hh = d.getHours().toString().padStart(2, '0');
  var mm = d.getMinutes().toString().padStart(2, '0');
  return hh + 'h' + (mm === '00' ? '' : mm);
}

// Envoie le rappel J-1 ("Demain à 20h : Concert X au Palais").
// Marque immédiatement reminder_sent_d1 = true pour éviter doublon.
function sendD1Reminders() {
  return pool.query(
    'SELECT b.id, b.user_id, e.id AS event_id, e.title, e.lieu, e.start_at ' +
    'FROM bookings b JOIN events e ON e.id = b.event_id ' +
    "WHERE b.statut = 'confirme' " +
    '  AND b.reminder_sent_d1 = false ' +
    '  AND e.start_at IS NOT NULL ' +
    "  AND e.start_at BETWEEN NOW() + INTERVAL '23 hours' AND NOW() + INTERVAL '25 hours' " +
    'LIMIT 200'
  )
    .then(function(result) {
      if (result.rows.length === 0) return 0;

      // UPDATE en batch d'abord pour éviter les doublons en cas de re-tick.
      var ids = result.rows.map(function(r) { return r.id; });
      return pool.query(
        'UPDATE bookings SET reminder_sent_d1 = true WHERE id = ANY($1::int[])',
        [ids]
      ).then(function() {
        // Puis envoie en parallèle. fire-and-forget : on ignore les erreurs push individuelles.
        result.rows.forEach(function(b) {
          push.notifyUser(b.user_id, {
            title: 'Demain à ' + formatHumanTime(b.start_at) + ' 🎟️',
            body: '« ' + b.title + ' » — ' + b.lieu + '. À demain !',
            data: { type: 'event_reminder_d1', bookingId: b.id.toString(), eventId: b.event_id.toString() },
          });
        });
        return result.rows.length;
      });
    });
}

// Envoie le rappel H-2 ("Dans 2h : n'oublie pas ton billet").
function sendH2Reminders() {
  return pool.query(
    'SELECT b.id, b.user_id, e.id AS event_id, e.title, e.lieu, e.start_at ' +
    'FROM bookings b JOIN events e ON e.id = b.event_id ' +
    "WHERE b.statut = 'confirme' " +
    '  AND b.reminder_sent_h2 = false ' +
    '  AND e.start_at IS NOT NULL ' +
    "  AND e.start_at BETWEEN NOW() + INTERVAL '105 minutes' AND NOW() + INTERVAL '135 minutes' " +
    'LIMIT 200'
  )
    .then(function(result) {
      if (result.rows.length === 0) return 0;

      var ids = result.rows.map(function(r) { return r.id; });
      return pool.query(
        'UPDATE bookings SET reminder_sent_h2 = true WHERE id = ANY($1::int[])',
        [ids]
      ).then(function() {
        result.rows.forEach(function(b) {
          push.notifyUser(b.user_id, {
            title: 'Dans 2h : ' + b.title + ' ⏰',
            body: 'Rendez-vous à ' + b.lieu + '. N\'oublie pas ton QR code !',
            data: { type: 'event_reminder_h2', bookingId: b.id.toString(), eventId: b.event_id.toString() },
          });
        });
        return result.rows.length;
      });
    });
}

function tick() {
  return Promise.all([sendD1Reminders(), sendH2Reminders()])
    .then(function(counts) {
      if (counts[0] > 0 || counts[1] > 0) {
        console.log('[event-reminders] D-1: ' + counts[0] + ', H-2: ' + counts[1]);
      }
    })
    .catch(function(err) {
      console.error('[event-reminders] erreur:', err.message);
    });
}

// Démarrage : toutes les 30 minutes. Suffisant pour la fenêtre H-2 (±15 min)
// et largement assez pour D-1 (±1h). Premier run après 90s pour ne pas tourner
// pendant le boot du serveur.
function start(intervalMs) {
  var ms = intervalMs || 30 * 60 * 1000;
  setTimeout(function() {
    tick();
    setInterval(tick, ms);
  }, 90 * 1000);
  console.log('[event-reminders] worker actif (toutes les ' + (ms / 60000) + ' min)');
}

module.exports = { start: start, tick: tick };
