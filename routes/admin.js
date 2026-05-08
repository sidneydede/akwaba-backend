// routes/admin.js — Endpoints administrateur (dashboard web)
// Tous protégés par authMiddleware + requireAdmin sauf /admin/auth/login.
// Auth : email + password (scrypt) — distinct du flux OTP/SMS du mobile.

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');

// Pagination par défaut. Limite haute volontairement modeste pour
// éviter qu'un admin ne charge accidentellement 10k lignes.
var DEFAULT_PAGE_SIZE = 50;
var MAX_PAGE_SIZE = 200;

// Helpers ----------------------------------------------------------------

// Inscrit une action admin dans admin_audit_log (fire-and-forget : on logue
// les erreurs mais on ne casse pas la requête principale si l'audit échoue).
// @param {number} adminId
// @param {string} action - ex: 'event.approve', 'user.suspend', 'payment.refund_manual'
// @param {string} targetType - ex: 'event', 'user', 'payment'
// @param {string|number} targetId
// @param {object} metadata - payload JSON arbitraire
function logAudit(adminId, action, targetType, targetId, metadata) {
  pool.query(
    'INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, metadata) VALUES ($1, $2, $3, $4, $5)',
    [adminId, action, targetType || null, targetId !== undefined ? String(targetId) : null, metadata ? JSON.stringify(metadata) : null]
  ).catch(function(err) { console.error('Erreur logAudit:', err.message); });
}

// Lit page/page_size depuis req.query, clampe sur [1, MAX_PAGE_SIZE].
// @returns {{ page: number, pageSize: number, offset: number }}
function readPagination(req) {
  var page = parseInt(req.query.page) || 1;
  if (page < 1) page = 1;
  var pageSize = parseInt(req.query.page_size) || DEFAULT_PAGE_SIZE;
  if (pageSize < 1) pageSize = DEFAULT_PAGE_SIZE;
  if (pageSize > MAX_PAGE_SIZE) pageSize = MAX_PAGE_SIZE;
  return { page: page, pageSize: pageSize, offset: (page - 1) * pageSize };
}

// Auth -------------------------------------------------------------------

// POST /admin/auth/login — Login admin par email + password
// @body {string} email, password
router.post('/auth/login', function(req, res) {
  var email = (req.body.email || '').trim().toLowerCase();
  var password = req.body.password || '';

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email et mot de passe requis' });
  }

  pool.query(
    "SELECT id, nom, prenom, email, role, password_hash, suspended_at FROM users WHERE LOWER(email) = $1 AND role = 'admin'",
    [email]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        // Message générique pour ne pas révéler si l'email existe.
        return res.status(401).json({ success: false, message: 'Identifiants invalides' });
      }
      var user = result.rows[0];
      if (user.suspended_at) {
        return res.status(403).json({ success: false, message: 'Compte suspendu' });
      }
      if (!user.password_hash) {
        return res.status(401).json({ success: false, message: 'Identifiants invalides' });
      }

      auth.verifyPassword(password, user.password_hash).then(function(ok) {
        if (!ok) {
          return res.status(401).json({ success: false, message: 'Identifiants invalides' });
        }
        pool.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id])
          .catch(function(err) { console.error('Erreur update last_login:', err.message); });
        var token = auth.generateToken(user.id);
        logAudit(user.id, 'admin.login', 'user', user.id, null);
        res.json({
          success: true,
          token: token,
          admin: {
            id: user.id.toString(),
            nom: user.nom,
            prenom: user.prenom,
            email: user.email,
            role: user.role
          }
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur admin/auth/login:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// Toutes les routes ci-dessous exigent un admin authentifié.
router.use(auth.authMiddleware, auth.requireAdmin);

// GET /admin/me — Profil admin courant
router.get('/me', function(req, res) {
  res.json({
    success: true,
    admin: {
      id: req.admin.id.toString(),
      nom: req.admin.nom,
      prenom: req.admin.prenom,
      email: req.admin.email,
      phone: req.admin.phone,
      role: req.admin.role
    }
  });
});

// Stats ------------------------------------------------------------------

// GET /admin/stats — KPIs globaux pour la homepage du dashboard
// Retourne : counts users/events/bookings, revenu plateforme, MAU 30j,
// events à modérer, bookings 30 derniers jours (série quotidienne), top 5 events.
router.get('/stats', function(req, res) {
  var queries = [
    pool.query('SELECT COUNT(*)::int AS n FROM users'),
    pool.query("SELECT COUNT(*)::int AS n FROM users WHERE last_login_at >= NOW() - INTERVAL '30 days'"),
    pool.query('SELECT COUNT(*)::int AS n FROM events'),
    pool.query("SELECT COUNT(*)::int AS n FROM events WHERE status = 'pending'"),
    pool.query('SELECT COUNT(*)::int AS n FROM bookings'),
    pool.query("SELECT COALESCE(SUM(total_amount), 0)::bigint AS total FROM bookings WHERE statut = 'confirme'"),
    pool.query(
      "SELECT DATE(created_at) AS day, COUNT(*)::int AS n " +
      "FROM bookings WHERE created_at >= NOW() - INTERVAL '30 days' " +
      "GROUP BY DATE(created_at) ORDER BY day ASC"
    ),
    pool.query(
      'SELECT e.id, e.title, e.emoji, e.color, ' +
      '(e.places_total - e.places_restantes) AS places_vendues, ' +
      "COALESCE((SELECT SUM(total_amount) FROM bookings WHERE event_id = e.id AND statut = 'confirme'), 0)::bigint AS revenue " +
      "FROM events e WHERE e.status = 'approved' ORDER BY places_vendues DESC LIMIT 5"
    )
  ];

  Promise.all(queries)
    .then(function(results) {
      res.json({
        success: true,
        stats: {
          users_total: results[0].rows[0].n,
          users_mau: results[1].rows[0].n,
          events_total: results[2].rows[0].n,
          events_pending: results[3].rows[0].n,
          bookings_total: results[4].rows[0].n,
          revenue_total: parseInt(results[5].rows[0].total) || 0,
          bookings_30d: results[6].rows.map(function(r) {
            return { day: r.day, n: r.n };
          }),
          top_events: results[7].rows.map(function(r) {
            return {
              id: r.id.toString(),
              title: r.title,
              emoji: r.emoji,
              color: r.color,
              places_vendues: r.places_vendues,
              revenue: parseInt(r.revenue) || 0
            };
          })
        }
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/stats:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// Events / modération ----------------------------------------------------

// GET /admin/events — Liste paginée des events avec filtres status + search
// @query {string} status - 'pending' | 'approved' | 'rejected' | 'all' (défaut: 'all')
// @query {string} search - filtre titre/lieu (optionnel)
// @query {number} page, page_size
router.get('/events', function(req, res) {
  var status = req.query.status || 'all';
  var search = req.query.search || '';
  var pag = readPagination(req);

  var clauses = [];
  var params = [];

  if (status !== 'all') {
    params.push(status);
    clauses.push('e.status = $' + params.length);
  }
  if (search) {
    params.push('%' + search + '%');
    clauses.push('(LOWER(e.title) LIKE LOWER($' + params.length + ') OR LOWER(e.lieu) LIKE LOWER($' + params.length + '))');
  }

  var where = clauses.length > 0 ? ' WHERE ' + clauses.join(' AND ') : '';

  var listSql =
    'SELECT e.id, e.title, e.category, e.date, e.lieu, e.prix_display, e.emoji, e.color, ' +
    'e.places_total, e.places_restantes, e.status, e.rejection_reason, e.created_at, ' +
    'e.organizer_id, u.nom AS organizer_nom, u.prenom AS organizer_prenom, u.phone AS organizer_phone ' +
    'FROM events e LEFT JOIN users u ON u.id = e.organizer_id' + where +
    ' ORDER BY e.created_at DESC LIMIT ' + pag.pageSize + ' OFFSET ' + pag.offset;

  var countSql = 'SELECT COUNT(*)::int AS n FROM events e' + where;

  Promise.all([pool.query(listSql, params), pool.query(countSql, params)])
    .then(function(results) {
      res.json({
        success: true,
        page: pag.page,
        page_size: pag.pageSize,
        total: results[1].rows[0].n,
        events: results[0].rows.map(function(row) {
          return {
            id: row.id.toString(),
            title: row.title,
            category: row.category,
            date: row.date,
            lieu: row.lieu,
            prix: row.prix_display,
            emoji: row.emoji,
            color: row.color,
            places_total: row.places_total,
            places_restantes: row.places_restantes,
            status: row.status,
            rejection_reason: row.rejection_reason,
            created_at: row.created_at,
            organizer: row.organizer_id ? {
              id: row.organizer_id.toString(),
              nom: row.organizer_nom,
              prenom: row.organizer_prenom,
              phone: row.organizer_phone
            } : null
          };
        })
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/events:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /admin/events/:id — Détail event + organisateur + ventes
router.get('/events/:id', function(req, res) {
  pool.query(
    'SELECT e.*, u.nom AS organizer_nom, u.prenom AS organizer_prenom, u.phone AS organizer_phone, ' +
    '(e.places_total - e.places_restantes) AS places_vendues, ' +
    "COALESCE((SELECT SUM(total_amount) FROM bookings WHERE event_id = e.id AND statut = 'confirme'), 0)::bigint AS revenue " +
    'FROM events e LEFT JOIN users u ON u.id = e.organizer_id WHERE e.id = $1',
    [req.params.id]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Événement non trouvé' });
      }
      var row = result.rows[0];
      res.json({
        success: true,
        event: {
          id: row.id.toString(),
          title: row.title,
          description: row.description,
          category: row.category,
          date: row.date,
          lieu: row.lieu,
          prix: row.prix_display,
          prix_num: row.prix,
          emoji: row.emoji,
          color: row.color,
          chaud: row.chaud,
          image_url: row.image_url,
          places_total: row.places_total,
          places_restantes: row.places_restantes,
          places_vendues: row.places_vendues,
          revenue: parseInt(row.revenue) || 0,
          latitude: row.latitude !== null ? parseFloat(row.latitude) : null,
          longitude: row.longitude !== null ? parseFloat(row.longitude) : null,
          status: row.status,
          rejection_reason: row.rejection_reason,
          moderated_at: row.moderated_at,
          created_at: row.created_at,
          organizer: row.organizer_id ? {
            id: row.organizer_id.toString(),
            nom: row.organizer_nom,
            prenom: row.organizer_prenom,
            phone: row.organizer_phone
          } : null
        }
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/events/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /admin/events/:id/approve — Approuver un event (le rend visible publiquement)
router.patch('/events/:id/approve', function(req, res) {
  pool.query(
    "UPDATE events SET status = 'approved', moderated_by = $1, moderated_at = NOW(), rejection_reason = NULL WHERE id = $2 RETURNING id, title, status",
    [req.admin.id, req.params.id]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Événement non trouvé' });
      }
      logAudit(req.admin.id, 'event.approve', 'event', result.rows[0].id, { title: result.rows[0].title });
      res.json({ success: true, event: { id: result.rows[0].id.toString(), status: 'approved' } });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /admin/events/:id/approve:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /admin/events/:id/reject — Rejeter un event avec raison
// @body {string} reason
router.patch('/events/:id/reject', function(req, res) {
  var reason = (req.body.reason || '').trim();
  if (!reason) {
    return res.status(400).json({ success: false, message: 'Raison du rejet requise' });
  }

  pool.query(
    "UPDATE events SET status = 'rejected', moderated_by = $1, moderated_at = NOW(), rejection_reason = $2 WHERE id = $3 RETURNING id, title, status",
    [req.admin.id, reason, req.params.id]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Événement non trouvé' });
      }
      logAudit(req.admin.id, 'event.reject', 'event', result.rows[0].id, { title: result.rows[0].title, reason: reason });
      res.json({ success: true, event: { id: result.rows[0].id.toString(), status: 'rejected', rejection_reason: reason } });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /admin/events/:id/reject:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// Users / modération ------------------------------------------------------

// GET /admin/users — Liste paginée des users avec filtres role + suspended + search
// @query {string} role - 'all' | 'participant' | 'organisateur' | 'admin' (défaut: 'all')
// @query {string} suspended - 'all' | 'true' | 'false' (défaut: 'all')
// @query {string} search - filtre nom/prénom/téléphone/email
router.get('/users', function(req, res) {
  var role = req.query.role || 'all';
  var suspended = req.query.suspended || 'all';
  var search = req.query.search || '';
  var pag = readPagination(req);

  var clauses = [];
  var params = [];

  if (role !== 'all') {
    params.push(role);
    clauses.push('role = $' + params.length);
  }
  if (suspended === 'true') clauses.push('suspended_at IS NOT NULL');
  else if (suspended === 'false') clauses.push('suspended_at IS NULL');

  if (search) {
    params.push('%' + search + '%');
    var i = params.length;
    clauses.push('(LOWER(nom) LIKE LOWER($' + i + ') OR LOWER(prenom) LIKE LOWER($' + i +
      ') OR phone LIKE $' + i + ' OR LOWER(COALESCE(email, \'\')) LIKE LOWER($' + i + '))');
  }

  var where = clauses.length > 0 ? ' WHERE ' + clauses.join(' AND ') : '';

  var listSql =
    'SELECT id, nom, prenom, phone, email, role, suspended_at, suspended_reason, last_login_at, created_at ' +
    'FROM users' + where +
    ' ORDER BY created_at DESC LIMIT ' + pag.pageSize + ' OFFSET ' + pag.offset;

  var countSql = 'SELECT COUNT(*)::int AS n FROM users' + where;

  Promise.all([pool.query(listSql, params), pool.query(countSql, params)])
    .then(function(results) {
      res.json({
        success: true,
        page: pag.page,
        page_size: pag.pageSize,
        total: results[1].rows[0].n,
        users: results[0].rows.map(function(row) {
          return {
            id: row.id.toString(),
            nom: row.nom,
            prenom: row.prenom,
            phone: row.phone,
            email: row.email,
            role: row.role,
            suspended_at: row.suspended_at,
            suspended_reason: row.suspended_reason,
            last_login_at: row.last_login_at,
            created_at: row.created_at
          };
        })
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/users:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /admin/users/:id — Détail user + ses events (si organisateur) + ses bookings
router.get('/users/:id', function(req, res) {
  var userId = req.params.id;

  Promise.all([
    pool.query(
      'SELECT id, nom, prenom, phone, email, role, suspended_at, suspended_reason, last_login_at, created_at FROM users WHERE id = $1',
      [userId]
    ),
    pool.query(
      'SELECT id, title, status, date, lieu, prix_display, places_total, places_restantes, created_at FROM events WHERE organizer_id = $1 ORDER BY created_at DESC LIMIT 50',
      [userId]
    ),
    pool.query(
      'SELECT b.id, b.ref, b.quantity, b.total_amount, b.statut, b.created_at, e.title AS event_title ' +
      'FROM bookings b LEFT JOIN events e ON e.id = b.event_id WHERE b.user_id = $1 ORDER BY b.created_at DESC LIMIT 50',
      [userId]
    )
  ])
    .then(function(results) {
      if (results[0].rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
      }
      var u = results[0].rows[0];
      res.json({
        success: true,
        user: {
          id: u.id.toString(),
          nom: u.nom,
          prenom: u.prenom,
          phone: u.phone,
          email: u.email,
          role: u.role,
          suspended_at: u.suspended_at,
          suspended_reason: u.suspended_reason,
          last_login_at: u.last_login_at,
          created_at: u.created_at
        },
        events: results[1].rows.map(function(r) {
          return {
            id: r.id.toString(),
            title: r.title,
            status: r.status,
            date: r.date,
            lieu: r.lieu,
            prix: r.prix_display,
            places_vendues: r.places_total - r.places_restantes,
            created_at: r.created_at
          };
        }),
        bookings: results[2].rows.map(function(r) {
          return {
            id: r.id.toString(),
            ref: r.ref,
            quantity: r.quantity,
            total_amount: r.total_amount,
            statut: r.statut,
            event_title: r.event_title,
            created_at: r.created_at
          };
        })
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/users/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /admin/users/:id/suspend — Suspendre un compte (refus connexion)
// @body {string} reason
router.patch('/users/:id/suspend', function(req, res) {
  var reason = (req.body.reason || '').trim();
  if (!reason) {
    return res.status(400).json({ success: false, message: 'Raison de suspension requise' });
  }
  // Empêche un admin de se suspendre lui-même.
  if (parseInt(req.params.id) === req.admin.id) {
    return res.status(400).json({ success: false, message: 'Impossible de suspendre votre propre compte' });
  }

  pool.query(
    'UPDATE users SET suspended_at = NOW(), suspended_reason = $1 WHERE id = $2 AND suspended_at IS NULL RETURNING id, nom, prenom',
    [reason, req.params.id]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Utilisateur non trouvé ou déjà suspendu' });
      }
      logAudit(req.admin.id, 'user.suspend', 'user', result.rows[0].id, { reason: reason });
      res.json({ success: true, user: { id: result.rows[0].id.toString(), suspended: true } });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /admin/users/:id/suspend:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /admin/users/:id/reactivate — Lève la suspension
router.patch('/users/:id/reactivate', function(req, res) {
  pool.query(
    'UPDATE users SET suspended_at = NULL, suspended_reason = NULL WHERE id = $1 AND suspended_at IS NOT NULL RETURNING id',
    [req.params.id]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Utilisateur non trouvé ou déjà actif' });
      }
      logAudit(req.admin.id, 'user.reactivate', 'user', result.rows[0].id, null);
      res.json({ success: true, user: { id: result.rows[0].id.toString(), suspended: false } });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /admin/users/:id/reactivate:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// Payments ----------------------------------------------------------------

// GET /admin/payments — Liste transactions CinetPay avec filtres status + période + méthode
// @query {string} status - statut CinetPay (ex: 'ACCEPTED', 'PENDING', 'FAILED')
// @query {string} method - 'orange', 'mtn', 'wave', 'card', etc.
// @query {string} from, to - bornes ISO date (optionnelles)
router.get('/payments', function(req, res) {
  var status = req.query.status;
  var method = req.query.method;
  var from = req.query.from;
  var to = req.query.to;
  var pag = readPagination(req);

  var clauses = [];
  var params = [];

  if (status) { params.push(status); clauses.push('p.status = $' + params.length); }
  if (method) { params.push(method); clauses.push('p.method = $' + params.length); }
  if (from)   { params.push(from);   clauses.push('p.created_at >= $' + params.length); }
  if (to)     { params.push(to);     clauses.push('p.created_at <= $' + params.length); }

  var where = clauses.length > 0 ? ' WHERE ' + clauses.join(' AND ') : '';

  var listSql =
    'SELECT p.id, p.transaction_id, p.amount, p.currency, p.method, p.status, p.created_at, ' +
    'p.booking_id, b.ref AS booking_ref, b.user_id, u.nom AS user_nom, u.prenom AS user_prenom, ' +
    'b.event_id, e.title AS event_title ' +
    'FROM payments p ' +
    'LEFT JOIN bookings b ON b.id = p.booking_id ' +
    'LEFT JOIN users u ON u.id = b.user_id ' +
    'LEFT JOIN events e ON e.id = b.event_id' + where +
    ' ORDER BY p.created_at DESC LIMIT ' + pag.pageSize + ' OFFSET ' + pag.offset;

  var countSql = 'SELECT COUNT(*)::int AS n FROM payments p' + where;

  Promise.all([pool.query(listSql, params), pool.query(countSql, params)])
    .then(function(results) {
      res.json({
        success: true,
        page: pag.page,
        page_size: pag.pageSize,
        total: results[1].rows[0].n,
        payments: results[0].rows.map(function(r) {
          return {
            id: r.id.toString(),
            transaction_id: r.transaction_id,
            amount: r.amount,
            currency: r.currency,
            method: r.method,
            status: r.status,
            created_at: r.created_at,
            booking: r.booking_id ? {
              id: r.booking_id.toString(),
              ref: r.booking_ref,
              user: r.user_id ? { id: r.user_id.toString(), nom: r.user_nom, prenom: r.user_prenom } : null,
              event: r.event_id ? { id: r.event_id.toString(), title: r.event_title } : null
            } : null
          };
        })
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/payments:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /admin/payments/:id — Détail paiement + payload CinetPay brut
router.get('/payments/:id', function(req, res) {
  pool.query(
    'SELECT p.*, b.ref AS booking_ref, b.user_id, b.event_id, ' +
    'u.nom AS user_nom, u.prenom AS user_prenom, u.phone AS user_phone, ' +
    'e.title AS event_title ' +
    'FROM payments p ' +
    'LEFT JOIN bookings b ON b.id = p.booking_id ' +
    'LEFT JOIN users u ON u.id = b.user_id ' +
    'LEFT JOIN events e ON e.id = b.event_id ' +
    'WHERE p.id = $1',
    [req.params.id]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Paiement non trouvé' });
      }
      var r = result.rows[0];
      res.json({
        success: true,
        payment: {
          id: r.id.toString(),
          transaction_id: r.transaction_id,
          amount: r.amount,
          currency: r.currency,
          method: r.method,
          status: r.status,
          cinetpay_data: r.cinetpay_data,
          created_at: r.created_at,
          updated_at: r.updated_at,
          booking: r.booking_id ? {
            id: r.booking_id.toString(),
            ref: r.booking_ref,
            user: r.user_id ? {
              id: r.user_id.toString(),
              nom: r.user_nom,
              prenom: r.user_prenom,
              phone: r.user_phone
            } : null,
            event: r.event_id ? { id: r.event_id.toString(), title: r.event_title } : null
          } : null
        }
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/payments/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/payments/:id/manual-refund — Marque un paiement remboursé manuellement
// (audit-log only ; le vrai remboursement se fait via le back-office CinetPay).
// @body {string} reason
router.post('/payments/:id/manual-refund', function(req, res) {
  var reason = (req.body.reason || '').trim();
  if (!reason) {
    return res.status(400).json({ success: false, message: 'Raison requise' });
  }

  pool.query('SELECT id, transaction_id FROM payments WHERE id = $1', [req.params.id])
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Paiement non trouvé' });
      }
      var p = result.rows[0];
      logAudit(req.admin.id, 'payment.refund_manual', 'payment', p.id, {
        reason: reason,
        transaction_id: p.transaction_id
      });
      res.json({ success: true, message: 'Remboursement manuel enregistré dans le journal d\'audit' });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/payments/:id/manual-refund:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
