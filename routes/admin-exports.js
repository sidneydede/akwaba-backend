// routes/admin-exports.js — Export CSV/JSON des tables Akwaba pour l'admin.
// Protégé par adminAuthMiddleware + requireAdmin (montage dans server.js).
// Bound sur created_at universel. Limite hard à MAX_ROWS pour ne pas saturer
// le free tier Render (30s timeout). Chaque export est tracé dans admin_audit_log.

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');

// Whitelist des tables exportables avec leur SQL pré-construit (joints inclus
// pour rendre les exports lisibles sans avoir à recouper avec d'autres tables).
// $1 = from, $2 = to (exclusive), $3 = LIMIT.
var TABLES = {
  users: {
    label: 'Utilisateurs',
    sql:
      'SELECT id, nom, prenom, phone, email, role, ville, ' +
      'date_naissance::text AS date_naissance, photo_url, ' +
      'suspended_at, suspended_reason, last_login_at, points, referral_code, ' +
      'created_at ' +
      'FROM users ' +
      'WHERE created_at >= $1 AND created_at < $2 ' +
      'ORDER BY created_at ASC LIMIT $3',
  },
  events: {
    label: 'Événements',
    sql:
      'SELECT e.id, e.title, e.category, e.date AS date_display, e.lieu, ' +
      'e.prix, e.prix_display, e.places_total, e.places_restantes, ' +
      'e.status, e.start_at, e.end_at, e.is_featured, e.featured_until, ' +
      'e.latitude, e.longitude, ' +
      'e.organizer_id, u.nom AS organizer_nom, u.prenom AS organizer_prenom, ' +
      'u.phone AS organizer_phone, ' +
      'e.moderated_at, e.created_at ' +
      'FROM events e LEFT JOIN users u ON u.id = e.organizer_id ' +
      'WHERE e.created_at >= $1 AND e.created_at < $2 ' +
      'ORDER BY e.created_at ASC LIMIT $3',
  },
  bookings: {
    label: 'Réservations',
    sql:
      'SELECT b.id, b.ref, ' +
      'b.user_id, u.nom AS user_nom, u.prenom AS user_prenom, u.phone AS user_phone, ' +
      'b.event_id, e.title AS event_title, ' +
      'b.quantity, b.total_amount, b.paiement_method, b.statut, ' +
      'b.transaction_id, b.utilise_at, b.cancelled_at, ' +
      'b.refund_amount, b.refund_ratio, b.cancellation_reason, ' +
      'b.created_at ' +
      'FROM bookings b ' +
      'LEFT JOIN users u ON u.id = b.user_id ' +
      'LEFT JOIN events e ON e.id = b.event_id ' +
      'WHERE b.created_at >= $1 AND b.created_at < $2 ' +
      'ORDER BY b.created_at ASC LIMIT $3',
  },
  payments: {
    label: 'Paiements CinetPay',
    sql:
      'SELECT p.id, p.transaction_id, ' +
      'p.booking_id, b.ref AS booking_ref, ' +
      'b.user_id, u.nom AS user_nom, u.prenom AS user_prenom, ' +
      'p.amount, p.currency, p.method, p.status, ' +
      'p.created_at, p.updated_at ' +
      'FROM payments p ' +
      'LEFT JOIN bookings b ON b.id = p.booking_id ' +
      'LEFT JOIN users u ON u.id = b.user_id ' +
      'WHERE p.created_at >= $1 AND p.created_at < $2 ' +
      'ORDER BY p.created_at ASC LIMIT $3',
  },
  payouts: {
    label: 'Reversements organisateurs',
    sql:
      'SELECT p.id, ' +
      'p.organizer_id, u.nom AS organizer_nom, u.prenom AS organizer_prenom, ' +
      'u.phone AS organizer_phone, ' +
      'p.event_id, e.title AS event_title, ' +
      'p.bookings_count, p.gross_amount, p.commission_amount, ' +
      'p.cinetpay_fees, p.net_amount, p.status, ' +
      'p.scheduled_at, p.released_at, p.transfer_status, p.transfer_reference, ' +
      'p.block_reason, p.created_at ' +
      'FROM payouts p ' +
      'LEFT JOIN users u ON u.id = p.organizer_id ' +
      'LEFT JOIN events e ON e.id = p.event_id ' +
      'WHERE p.created_at >= $1 AND p.created_at < $2 ' +
      'ORDER BY p.created_at ASC LIMIT $3',
  },
  feedback: {
    label: 'NPS Feedback (privé)',
    sql:
      'SELECT f.id, ' +
      'f.user_id, u.nom AS user_nom, u.prenom AS user_prenom, ' +
      'f.booking_id, b.ref AS booking_ref, ' +
      'f.event_id, e.title AS event_title, ' +
      'f.rating, f.comment, f.created_at ' +
      'FROM feedback f ' +
      'LEFT JOIN users u ON u.id = f.user_id ' +
      'LEFT JOIN bookings b ON b.id = f.booking_id ' +
      'LEFT JOIN events e ON e.id = f.event_id ' +
      'WHERE f.created_at >= $1 AND f.created_at < $2 ' +
      'ORDER BY f.created_at ASC LIMIT $3',
  },
  reviews: {
    label: 'Avis publics',
    sql:
      'SELECT r.id, ' +
      'r.user_id, u.nom AS user_nom, u.prenom AS user_prenom, ' +
      'r.event_id, e.title AS event_title, ' +
      'r.rating, r.comment, r.created_at ' +
      'FROM reviews r ' +
      'LEFT JOIN users u ON u.id = r.user_id ' +
      'LEFT JOIN events e ON e.id = r.event_id ' +
      'WHERE r.created_at >= $1 AND r.created_at < $2 ' +
      'ORDER BY r.created_at ASC LIMIT $3',
  },
};

var MAX_ROWS = 100000;

// Convertit un tableau de rows en CSV avec BOM UTF-8 (pour Excel sans tracas
// d'encoding) + escape RFC 4180 (guillemets doublés, champs quotés si virgule
// / guillemet / newline). Valeurs null/undefined → vide. Objets → JSON.stringify.
function rowsToCSV(rows) {
  if (rows.length === 0) {
    return '﻿';
  }
  var headers = Object.keys(rows[0]);
  function escape(v) {
    if (v === null || v === undefined) return '';
    var s;
    if (v instanceof Date) {
      s = v.toISOString();
    } else if (typeof v === 'object') {
      s = JSON.stringify(v);
    } else {
      s = String(v);
    }
    if (/[,"\n\r]/.test(s)) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }
  var lines = [headers.join(',')];
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    var line = [];
    for (var j = 0; j < headers.length; j++) {
      line.push(escape(row[headers[j]]));
    }
    lines.push(line.join(','));
  }
  return '﻿' + lines.join('\n');
}

// Authentification admin requise sur toutes les routes ci-dessous.
router.use(auth.adminAuthMiddleware, auth.requireAdmin);

// GET /admin/exports — Liste les tables exportables (pour peupler le dropdown UI).
router.get('/', function(req, res) {
  var list = [];
  for (var key in TABLES) {
    list.push({ key: key, label: TABLES[key].label });
  }
  res.json({ success: true, tables: list, max_rows: MAX_ROWS });
});

// GET /admin/exports/:table?from=YYYY-MM-DD&to=YYYY-MM-DD&format=csv|json
// Réponse : fichier téléchargeable (Content-Disposition: attachment).
router.get('/:table', function(req, res) {
  var tableName = req.params.table;
  var def = TABLES[tableName];
  if (!def) {
    return res.status(400).json({
      success: false,
      message: 'Table inconnue. Disponibles: ' + Object.keys(TABLES).join(', '),
    });
  }

  // 'from' inclusif, 'to' inclusif côté UX → on ajoute 1 jour pour le bound SQL exclusif.
  var from = req.query.from || '1970-01-01';
  var to;
  if (req.query.to) {
    var d = new Date(req.query.to);
    if (isNaN(d.getTime())) {
      return res.status(400).json({ success: false, message: 'Date "to" invalide (format YYYY-MM-DD)' });
    }
    d.setUTCDate(d.getUTCDate() + 1);
    to = d.toISOString();
  } else {
    to = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  }

  var format = req.query.format === 'json' ? 'json' : 'csv';
  var t0 = Date.now();

  pool.query(def.sql, [from, to, MAX_ROWS])
    .then(function(result) {
      var rows = result.rows;
      var elapsedMs = Date.now() - t0;
      var dateStamp = new Date().toISOString().split('T')[0];
      var filename = 'akwaba-' + tableName + '-' + dateStamp + '.' + format;

      // Audit log fire-and-forget — trace qui exporte quoi quand. RGPD-friendly :
      // on garde la trace mais le contenu reste dans le download direct.
      pool.query(
        'INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, metadata) ' +
        'VALUES ($1, $2, $3, $4, $5)',
        [
          req.admin.id,
          'export.' + tableName,
          'table',
          tableName,
          JSON.stringify({
            from: from,
            to: req.query.to || null,
            format: format,
            rows: rows.length,
            truncated: rows.length === MAX_ROWS,
            elapsed_ms: elapsedMs,
          }),
        ]
      ).catch(function(err) {
        console.error('Erreur audit export:', err.message);
      });

      if (format === 'json') {
        res.set('Content-Type', 'application/json; charset=utf-8');
        res.set('Content-Disposition', 'attachment; filename="' + filename + '"');
        return res.json({
          table: tableName,
          from: from,
          to: to,
          count: rows.length,
          truncated: rows.length === MAX_ROWS,
          rows: rows,
        });
      }

      res.set('Content-Type', 'text/csv; charset=utf-8');
      res.set('Content-Disposition', 'attachment; filename="' + filename + '"');
      res.send(rowsToCSV(rows));
    })
    .catch(function(err) {
      console.error('Erreur export ' + tableName + ':', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
