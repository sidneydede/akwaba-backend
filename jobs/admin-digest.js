// jobs/admin-digest.js — Digest quotidien des KPIs J-1 envoyé aux admins.
//
// Pourquoi : un admin n'a pas à se logger sur le portail chaque matin pour
// savoir ce qui s'est passé hier. Reçoit un email à 8h locale Abidjan
// (= 8h UTC, CI étant en UTC+0) avec : bookings J-1, revenu, nouveaux users,
// events en attente de modération, anomalies de refund.
//
// Stratégie :
//   - Tick toutes les 10 min. Si l'heure UTC >= 8 ET aucun digest pour
//     aujourd'hui en DB → génère, sauve, envoie email.
//   - UNIQUE sur admin_digests.digest_date garantit qu'un seul digest part
//     par jour même si plusieurs ticks tombent dans la même journée.
//   - Render free tier endort le service après 15 min sans HTTP. Si le boot
//     se fait à 14h, le digest du jour est skip (déjà passé 8h). On accepte
//     ce trade-off pour V1. Solution future : Render Cron ($1/mo) ou
//     scheduler externe (GitHub Actions / cron-job.org) qui ping
//     /admin/digest/send-now à 8h.
//   - Si RESEND_API_KEY absent : digest généré + sauvé en DB sans email
//     (admin peut le voir via /admin/digests/today si on ajoute la route).

var pool = require('../db/pool');

var DIGEST_HOUR_UTC = 8; // 8h Abidjan
var DIGEST_FROM = 'Akwaba Digest <digest@akwaba.app>';

// ============================================================
// Génération du contenu
// ============================================================

// Récupère les KPIs J-1 et anomalies. Retourne un objet structuré
// utilisé à la fois pour rendre l'email et stocker en DB (data JSONB).
function computeData() {
  var sqls = [
    // 0. Bookings J-1 (count + revenue)
    pool.query(
      "SELECT COUNT(*)::int AS n, COALESCE(SUM(total_amount), 0)::bigint AS revenue " +
      "FROM bookings WHERE statut = 'confirme' " +
      "AND created_at >= (CURRENT_DATE - INTERVAL '1 day') " +
      'AND created_at < CURRENT_DATE'
    ),
    // 1. Nouveaux users J-1
    pool.query(
      "SELECT COUNT(*)::int AS n FROM users " +
      "WHERE created_at >= (CURRENT_DATE - INTERVAL '1 day') " +
      'AND created_at < CURRENT_DATE'
    ),
    // 2. Events soumis (pending) actuellement
    pool.query("SELECT COUNT(*)::int AS n FROM events WHERE status = 'pending'"),
    // 3. Refunds J-1
    pool.query(
      "SELECT COUNT(*)::int AS n, COALESCE(SUM(refund_amount), 0)::bigint AS refunded " +
      'FROM bookings WHERE cancelled_at IS NOT NULL ' +
      "AND cancelled_at >= (CURRENT_DATE - INTERVAL '1 day') " +
      'AND cancelled_at < CURRENT_DATE'
    ),
    // 4. Top 3 events de la semaine (ventes 7 derniers jours)
    pool.query(
      'SELECT e.id, e.title, e.emoji, ' +
      'COUNT(b.id)::int AS bookings_count, ' +
      'COALESCE(SUM(b.total_amount), 0)::bigint AS revenue ' +
      'FROM events e ' +
      "LEFT JOIN bookings b ON b.event_id = e.id AND b.statut = 'confirme' " +
      "AND b.created_at >= NOW() - INTERVAL '7 days' " +
      "WHERE e.status = 'approved' " +
      'GROUP BY e.id, e.title, e.emoji ' +
      'HAVING COUNT(b.id) > 0 ' +
      'ORDER BY bookings_count DESC LIMIT 3'
    ),
    // 5. Anomalie 1 : events avec refund rate > 10% sur J-7
    pool.query(
      'SELECT e.id, e.title, e.emoji, ' +
      'COUNT(b.id)::int AS bookings_count, ' +
      'COUNT(b.cancelled_at)::int AS refunds_count, ' +
      "ROUND(COUNT(b.cancelled_at)::numeric / NULLIF(COUNT(b.id), 0) * 100, 1) AS refund_rate " +
      'FROM events e JOIN bookings b ON b.event_id = e.id ' +
      "WHERE b.created_at >= NOW() - INTERVAL '7 days' " +
      'GROUP BY e.id, e.title, e.emoji ' +
      'HAVING COUNT(b.id) >= 5 AND ' +
      'COUNT(b.cancelled_at)::numeric / NULLIF(COUNT(b.id), 0) > 0.10 ' +
      'ORDER BY refund_rate DESC LIMIT 5'
    ),
    // 6. Payments J-1 par status (succès vs échec)
    pool.query(
      'SELECT status, COUNT(*)::int AS n FROM payments ' +
      "WHERE created_at >= (CURRENT_DATE - INTERVAL '1 day') " +
      'AND created_at < CURRENT_DATE GROUP BY status'
    ),
  ];

  return Promise.all(sqls).then(function(r) {
    var paymentsByStatus = {};
    r[6].rows.forEach(function(row) { paymentsByStatus[row.status] = row.n; });

    return {
      digest_date: new Date(Date.now() - 24 * 3600 * 1000).toISOString().split('T')[0],
      bookings_j1: {
        count: r[0].rows[0].n,
        revenue: parseInt(r[0].rows[0].revenue) || 0,
      },
      new_users_j1: r[1].rows[0].n,
      events_pending: r[2].rows[0].n,
      refunds_j1: {
        count: r[3].rows[0].n,
        amount: parseInt(r[3].rows[0].refunded) || 0,
      },
      top_events_week: r[4].rows.map(function(row) {
        return {
          id: row.id.toString(),
          title: row.title,
          emoji: row.emoji,
          bookings_count: row.bookings_count,
          revenue: parseInt(row.revenue) || 0,
        };
      }),
      anomalies_refund: r[5].rows.map(function(row) {
        return {
          id: row.id.toString(),
          title: row.title,
          emoji: row.emoji,
          bookings_count: row.bookings_count,
          refunds_count: row.refunds_count,
          refund_rate: parseFloat(row.refund_rate),
        };
      }),
      payments_j1: paymentsByStatus,
    };
  });
}

// ============================================================
// Rendu HTML (inline styles — pas de CSS externe possible en email)
// ============================================================

function formatFCFA(n) {
  return new Intl.NumberFormat('fr-FR').format(n || 0) + ' FCFA';
}

function renderHTML(d, baseUrl) {
  var b = baseUrl || 'https://akwaba-admin.vercel.app';
  var date = new Date(d.digest_date).toLocaleDateString('fr-FR', {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
  });

  var anomaliesHtml = '';
  if (d.anomalies_refund.length > 0) {
    anomaliesHtml =
      '<h3 style="font-family:Georgia,serif;color:#0E0B08;margin:32px 0 12px;font-size:16px">' +
      '⚠️ Anomalies refund (>10% sur 7j, min 5 bookings)</h3>' +
      '<table style="width:100%;border-collapse:collapse">';
    d.anomalies_refund.forEach(function(a) {
      anomaliesHtml +=
        '<tr><td style="padding:8px 0;border-bottom:1px solid #E5DDD0;font-size:14px">' +
        (a.emoji || '🎵') + ' <strong>' + a.title + '</strong></td>' +
        '<td style="padding:8px 0;border-bottom:1px solid #E5DDD0;text-align:right;font-size:13px;color:#A8431F">' +
        a.refund_rate + '% (' + a.refunds_count + '/' + a.bookings_count + ')</td></tr>';
    });
    anomaliesHtml += '</table>';
  }

  var topHtml = '';
  if (d.top_events_week.length > 0) {
    topHtml = '<table style="width:100%;border-collapse:collapse">';
    d.top_events_week.forEach(function(e, i) {
      topHtml +=
        '<tr><td style="padding:8px 0;border-bottom:1px solid #E5DDD0;font-size:14px">' +
        '<strong style="color:#D85A2C;font-family:Georgia,serif">' + (i + 1) + '.</strong> ' +
        (e.emoji || '🎵') + ' ' + e.title + '</td>' +
        '<td style="padding:8px 0;border-bottom:1px solid #E5DDD0;text-align:right;font-size:13px;color:#666">' +
        e.bookings_count + ' billets · ' + formatFCFA(e.revenue) + '</td></tr>';
    });
    topHtml += '</table>';
  }

  return [
    '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">',
    '<title>Akwaba Digest — ' + date + '</title></head>',
    '<body style="margin:0;padding:24px;background:#F4EBDD;font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;color:#0E0B08">',
    '<div style="max-width:560px;margin:0 auto;background:#fff;padding:32px;border-radius:8px">',
    '<div style="border-bottom:2px solid #D85A2C;padding-bottom:16px;margin-bottom:24px">',
    '<h1 style="font-family:Georgia,serif;font-size:24px;margin:0;font-weight:500">Akwaba <span style="color:#D85A2C">Digest</span></h1>',
    '<p style="margin:4px 0 0;font-size:13px;color:#666">' + date + '</p>',
    '</div>',

    '<h3 style="font-family:Georgia,serif;color:#0E0B08;margin:0 0 12px;font-size:16px">KPIs J-1</h3>',
    '<table style="width:100%;border-collapse:collapse;margin-bottom:24px">',
    '<tr><td style="padding:10px 0;border-bottom:1px solid #E5DDD0;font-size:14px">Réservations confirmées</td>',
    '<td style="padding:10px 0;border-bottom:1px solid #E5DDD0;text-align:right;font-size:14px;font-weight:600">' + d.bookings_j1.count + '</td></tr>',
    '<tr><td style="padding:10px 0;border-bottom:1px solid #E5DDD0;font-size:14px">Revenu brut</td>',
    '<td style="padding:10px 0;border-bottom:1px solid #E5DDD0;text-align:right;font-size:14px;font-weight:600">' + formatFCFA(d.bookings_j1.revenue) + '</td></tr>',
    '<tr><td style="padding:10px 0;border-bottom:1px solid #E5DDD0;font-size:14px">Nouveaux utilisateurs</td>',
    '<td style="padding:10px 0;border-bottom:1px solid #E5DDD0;text-align:right;font-size:14px;font-weight:600">' + d.new_users_j1 + '</td></tr>',
    '<tr><td style="padding:10px 0;border-bottom:1px solid #E5DDD0;font-size:14px">Annulations / remboursements</td>',
    '<td style="padding:10px 0;border-bottom:1px solid #E5DDD0;text-align:right;font-size:14px;font-weight:600">' + d.refunds_j1.count + ' · ' + formatFCFA(d.refunds_j1.amount) + '</td></tr>',
    '<tr><td style="padding:10px 0;font-size:14px">Events en attente de modération</td>',
    '<td style="padding:10px 0;text-align:right;font-size:14px;font-weight:600;color:' + (d.events_pending > 0 ? '#D85A2C' : '#666') + '">' + d.events_pending + '</td></tr>',
    '</table>',

    (d.events_pending > 0
      ? '<p style="margin:0 0 24px"><a href="' + b + '/events?status=pending" style="background:#D85A2C;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:500;display:inline-block">Modérer les ' + d.events_pending + ' events en attente →</a></p>'
      : ''),

    (d.top_events_week.length > 0
      ? '<h3 style="font-family:Georgia,serif;color:#0E0B08;margin:32px 0 12px;font-size:16px">Top events de la semaine</h3>' + topHtml
      : ''),

    anomaliesHtml,

    '<div style="margin-top:32px;padding-top:16px;border-top:1px solid #E5DDD0;font-size:11px;color:#999">',
    'Tu reçois ce mail parce que tu es admin Akwaba. Consulte le détail sur ',
    '<a href="' + b + '" style="color:#D85A2C">' + b + '</a>.',
    '</div>',
    '</div></body></html>',
  ].join('');
}

// ============================================================
// Envoi email via Resend (fetch direct, pas de SDK)
// ============================================================

function sendEmail(recipients, subject, html) {
  var apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.log('[admin-digest] RESEND_API_KEY absent — email skip, digest généré et sauvé en DB');
    return Promise.resolve({ skipped: true });
  }
  if (recipients.length === 0) {
    return Promise.resolve({ skipped: true, reason: 'no_recipients' });
  }

  return fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + apiKey,
    },
    body: JSON.stringify({
      from: process.env.RESEND_FROM || DIGEST_FROM,
      to: recipients,
      subject: subject,
      html: html,
    }),
  }).then(function(res) {
    if (!res.ok) {
      return res.text().then(function(body) {
        throw new Error('Resend HTTP ' + res.status + ': ' + body.slice(0, 200));
      });
    }
    return res.json();
  });
}

// ============================================================
// Tick : vérifie si on doit envoyer aujourd'hui, et envoie si oui
// ============================================================

function tick() {
  var now = new Date();
  if (now.getUTCHours() < DIGEST_HOUR_UTC) {
    return Promise.resolve({ skipped: true, reason: 'too_early' });
  }
  var today = now.toISOString().split('T')[0];

  // Idempotent : si on a déjà sauvé un digest pour aujourd'hui, on ne refait pas.
  return pool.query('SELECT id FROM admin_digests WHERE digest_date = $1', [today])
    .then(function(r) {
      if (r.rows.length > 0) {
        return { skipped: true, reason: 'already_sent_today' };
      }
      return sendDigestForToday();
    })
    .catch(function(err) {
      console.error('[admin-digest] erreur tick:', err.message);
      return { error: err.message };
    });
}

// Génère + sauve + envoie. Utilisé par tick() automatique ET par
// l'endpoint POST /admin/digest/send-now (manuel).
function sendDigestForToday() {
  var today = new Date().toISOString().split('T')[0];

  return Promise.all([
    computeData(),
    pool.query("SELECT email FROM users WHERE role = 'admin' AND suspended_at IS NULL AND email IS NOT NULL"),
  ]).then(function(results) {
    var data = results[0];
    var recipients = results[1].rows.map(function(r) { return r.email; });
    var html = renderHTML(data);
    var subject = 'Akwaba — résumé du ' + new Date(data.digest_date).toLocaleDateString('fr-FR');

    return sendEmail(recipients, subject, html).then(
      function(emailResult) {
        var emailSentAt = emailResult.skipped ? null : new Date();
        return pool.query(
          'INSERT INTO admin_digests (digest_date, data, html, email_sent_at, email_recipients) ' +
          'VALUES ($1, $2, $3, $4, $5) ' +
          'ON CONFLICT (digest_date) DO UPDATE SET ' +
          'data = $2, html = $3, email_sent_at = $4, email_recipients = $5, email_error = NULL ' +
          'RETURNING id',
          [today, JSON.stringify(data), html, emailSentAt, recipients]
        ).then(function(insRes) {
          console.log('[admin-digest] digest ' + today + ' OK — id=' + insRes.rows[0].id +
            ', recipients=' + recipients.length + ', email=' + (emailSentAt ? 'sent' : 'skipped'));
          return { id: insRes.rows[0].id, recipients: recipients.length, email_sent: !!emailSentAt };
        });
      },
      function(err) {
        // Email a échoué — on sauve quand même le digest (utile pour debug)
        return pool.query(
          'INSERT INTO admin_digests (digest_date, data, html, email_recipients, email_error) ' +
          'VALUES ($1, $2, $3, $4, $5) ' +
          'ON CONFLICT (digest_date) DO UPDATE SET ' +
          'data = $2, html = $3, email_recipients = $4, email_error = $5 ' +
          'RETURNING id',
          [today, JSON.stringify(data), html, recipients, err.message]
        ).then(function() {
          console.error('[admin-digest] digest sauvé mais email failed:', err.message);
          throw err;
        });
      }
    );
  });
}

// ============================================================
// Démarrage : tick toutes les 10 min
// ============================================================

function start(intervalMs) {
  var ms = intervalMs || 10 * 60 * 1000;
  setTimeout(function() {
    tick();
    setInterval(tick, ms);
  }, 120 * 1000); // premier run après 2 min pour ne pas tourner pendant boot
  console.log('[admin-digest] worker actif (tick toutes les ' + (ms / 60000) + ' min, envoie à ' + DIGEST_HOUR_UTC + 'h UTC)');
}

module.exports = {
  start: start,
  tick: tick,
  sendDigestForToday: sendDigestForToday,
  computeData: computeData,
  renderHTML: renderHTML,
};
