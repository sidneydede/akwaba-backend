// routes/admin.js — Endpoints administrateur (dashboard web)
// Tous protégés par authMiddleware + requireAdmin sauf /admin/auth/login.
// Auth : email + password (scrypt) — distinct du flux OTP/SMS du mobile.

var express = require('express');
var rateLimit = require('express-rate-limit');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var push = require('../services/push');
var cinetpay = require('../services/cinetpay');
var followsRouter = require('./follows');

// Rate limit sur le login admin : 5 tentatives / 15 min par IP.
// Compte uniquement les échecs (skipSuccessfulRequests) — un admin qui se
// reconnecte plein de fois ne se fera pas bloquer. En back-office on accepte
// un faux positif occasionnel : mieux qu'autoriser un brute force.
var adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { success: false, message: 'Trop de tentatives. Réessayez dans 15 minutes.' }
});

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

// POST /admin/auth/login — Étape 1 : email + password.
// Si l'admin a déjà activé son 2FA → retourne un challenge_token court (5 min)
// que le front doit ré-envoyer à /admin/auth/login/verify avec le code TOTP.
// Sinon (admin pas encore 2FA-isé) → retourne le token complet + must_setup_2fa=true
// pour que le front pousse direct sur l'écran de setup.
// @body {string} email, password
router.post('/auth/login', adminLoginLimiter, function(req, res) {
  var email = (req.body.email || '').trim().toLowerCase();
  var password = req.body.password || '';

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email et mot de passe requis' });
  }

  pool.query(
    "SELECT id, nom, prenom, email, role, password_hash, suspended_at, totp_enabled_at " +
    "FROM users WHERE LOWER(email) = $1 AND role = 'admin'",
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

        // Si 2FA déjà activé → étape password validée mais on ne livre PAS le token de session.
        // On délivre un challenge_token signé qui ne sert qu'à /admin/auth/login/verify.
        if (user.totp_enabled_at) {
          var challengeToken = auth.generateChallengeToken(user.id, 'totp_challenge');
          return res.json({
            success: true,
            requires_totp: true,
            challenge_token: challengeToken,
            expires_in_sec: Math.floor(auth.CHALLENGE_TOKEN_TTL_MS / 1000)
          });
        }

        // Premier login (admin existant pré-2FA, ou nouveau seed) : token complet
        // + flag must_setup_2fa pour que le front force l'écran de configuration.
        pool.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id])
          .catch(function(err) { console.error('Erreur update last_login:', err.message); });
        var token = auth.generateToken(user.id);
        logAudit(user.id, 'admin.login', 'user', user.id, { must_setup_2fa: true });
        res.json({
          success: true,
          token: token,
          must_setup_2fa: true,
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

// POST /admin/auth/login/verify — Étape 2 : code TOTP.
// Reçoit le challenge_token issu de l'étape 1 + le code à 6 chiffres.
// Si OK → retourne le token de session 8h.
// @body {string} challenge_token, code
router.post('/auth/login/verify', adminLoginLimiter, function(req, res) {
  var challengeToken = req.body.challenge_token || '';
  var code = (req.body.code || '').trim();
  if (!challengeToken || !code) {
    return res.status(400).json({ success: false, message: 'challenge_token et code requis' });
  }
  if (!/^\d{6}$/.test(code)) {
    return res.status(400).json({ success: false, message: 'Code TOTP invalide (6 chiffres)' });
  }

  var userId = auth.decodeChallengeToken(challengeToken, 'totp_challenge', auth.CHALLENGE_TOKEN_TTL_MS);
  if (!userId) {
    return res.status(401).json({
      success: false,
      code: 'challenge_expired',
      message: 'Challenge expiré ou invalide, recommencez le login'
    });
  }

  pool.query(
    "SELECT id, nom, prenom, email, role, totp_secret, totp_enabled_at, suspended_at " +
    "FROM users WHERE id = $1 AND role = 'admin'",
    [userId]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(401).json({ success: false, message: 'Utilisateur introuvable' });
      }
      var user = result.rows[0];
      if (user.suspended_at) {
        return res.status(403).json({ success: false, message: 'Compte suspendu' });
      }
      if (!user.totp_enabled_at || !user.totp_secret) {
        return res.status(400).json({ success: false, message: '2FA non configuré pour ce compte' });
      }

      var speakeasy = require('speakeasy');
      var verified = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token: code,
        window: 1 // tolérance ±30s pour absorber un léger décalage d'horloge
      });

      if (!verified) {
        logAudit(user.id, 'admin.login.totp_fail', 'user', user.id, null);
        return res.status(401).json({ success: false, message: 'Code incorrect' });
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
    })
    .catch(function(err) {
      console.error('Erreur admin/auth/login/verify:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// Toutes les routes ci-dessous exigent un admin authentifié.
// adminAuthMiddleware (vs authMiddleware) applique en plus une expiration de 8h
// sur le token (back-office sensible). Mobile reste sans TTL.
router.use(auth.adminAuthMiddleware, auth.requireAdmin);

// GET /admin/me — Profil admin courant
router.get('/me', function(req, res) {
  pool.query('SELECT totp_enabled_at FROM users WHERE id = $1', [req.admin.id])
    .then(function(r) {
      var totpEnabled = r.rows.length > 0 && r.rows[0].totp_enabled_at;
      res.json({
        success: true,
        admin: {
          id: req.admin.id.toString(),
          nom: req.admin.nom,
          prenom: req.admin.prenom,
          email: req.admin.email,
          phone: req.admin.phone,
          role: req.admin.role,
          totp_enabled: !!totpEnabled,
          must_setup_2fa: !totpEnabled
        }
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/me:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// 2FA setup ---------------------------------------------------------------

// POST /admin/2fa/setup — Génère un nouveau secret TOTP en attente d'activation.
// Le secret est stocké dans totp_pending_secret (pas encore actif). L'admin
// doit scanner le QR avec son authenticator puis appeler /admin/2fa/activate
// avec un code valide pour confirmer (sinon le secret reste en pending et
// peut être régénéré).
// @returns {object} { secret, otpauth_url, qr_data_url }
router.post('/2fa/setup', function(req, res) {
  var speakeasy = require('speakeasy');
  var QRCode = require('qrcode');

  // 20 octets = 160 bits d'entropie en base32, standard RFC 6238.
  // On reconstruit l'otpauth URL avec issuer en query pour que les apps
  // (Google Authenticator, Authy, 1Password) groupent les comptes proprement.
  var secretObj = speakeasy.generateSecret({ length: 20 });
  var otpauthUrl = speakeasy.otpauthURL({
    secret: secretObj.base32,
    label: req.admin.email,
    issuer: 'Akwaba Admin',
    encoding: 'base32'
  });

  pool.query(
    'UPDATE users SET totp_pending_secret = $1, updated_at = NOW() WHERE id = $2',
    [secretObj.base32, req.admin.id]
  )
    .then(function() {
      // QR PNG en data URL — affichable direct dans une <img src=...>.
      return QRCode.toDataURL(otpauthUrl);
    })
    .then(function(qrDataUrl) {
      logAudit(req.admin.id, 'admin.2fa.setup', 'user', req.admin.id, null);
      res.json({
        success: true,
        secret: secretObj.base32,
        otpauth_url: otpauthUrl,
        qr_data_url: qrDataUrl
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/2fa/setup:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/2fa/activate — Confirme le secret pending avec un premier code valide.
// Une fois activé, le prochain login devra fournir un code TOTP.
// @body {string} code - 6 chiffres
router.post('/2fa/activate', function(req, res) {
  var code = (req.body.code || '').trim();
  if (!/^\d{6}$/.test(code)) {
    return res.status(400).json({ success: false, message: 'Code TOTP invalide (6 chiffres)' });
  }

  pool.query('SELECT totp_pending_secret FROM users WHERE id = $1', [req.admin.id])
    .then(function(r) {
      if (r.rows.length === 0 || !r.rows[0].totp_pending_secret) {
        return res.status(400).json({
          success: false,
          message: 'Aucun setup en attente. Appelle /admin/2fa/setup d\'abord.'
        });
      }
      var pending = r.rows[0].totp_pending_secret;

      var speakeasy = require('speakeasy');
      var verified = speakeasy.totp.verify({
        secret: pending,
        encoding: 'base32',
        token: code,
        window: 1
      });

      if (!verified) {
        return res.status(401).json({ success: false, message: 'Code incorrect' });
      }

      return pool.query(
        'UPDATE users SET totp_secret = $1, totp_pending_secret = NULL, ' +
        'totp_enabled_at = NOW(), updated_at = NOW() WHERE id = $2',
        [pending, req.admin.id]
      ).then(function() {
        logAudit(req.admin.id, 'admin.2fa.activate', 'user', req.admin.id, null);
        res.json({ success: true, message: '2FA activé' });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/2fa/activate:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
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
      // FOLLOW-01 : push notif aux followers de l'orga (best effort, ne bloque pas).
      // Idempotent via flag events.followers_notified_at — si admin reject puis re-approve,
      // pas de re-notif.
      followsRouter.notifyFollowersOfNewEvent(result.rows[0].id);
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

// ============================================================
// Payouts / Reversements organisateurs (ADM-05)
// ============================================================

// Helper : lit un setting numérique depuis app_settings (ou default si absent).
function getSetting(key, defaultValue) {
  return pool.query('SELECT value FROM app_settings WHERE key = $1', [key])
    .then(function(r) {
      if (r.rows.length === 0) return defaultValue;
      // value est JSONB — soit un nombre soit un objet
      var v = r.rows[0].value;
      return v;
    });
}

// GET /admin/payouts — Liste paginée des reversements
// @query {string} status - 'all' | 'scheduled' | 'released' | 'blocked' | 'cancelled'
// @query {number} organizer_id - filtrer par organisateur
// @query {string} from, to - bornes ISO date sur scheduled_at
router.get('/payouts', function(req, res) {
  var status = req.query.status || 'all';
  var organizerId = req.query.organizer_id ? parseInt(req.query.organizer_id) : null;
  var from = req.query.from;
  var to = req.query.to;
  var pag = readPagination(req);

  var clauses = [];
  var params = [];

  if (status !== 'all') {
    params.push(status);
    clauses.push('p.status = $' + params.length);
  }
  if (organizerId) {
    params.push(organizerId);
    clauses.push('p.organizer_id = $' + params.length);
  }
  if (from) { params.push(from); clauses.push('p.scheduled_at >= $' + params.length); }
  if (to)   { params.push(to);   clauses.push('p.scheduled_at <= $' + params.length); }

  var where = clauses.length > 0 ? ' WHERE ' + clauses.join(' AND ') : '';

  var listSql =
    'SELECT p.id, p.organizer_id, p.event_id, p.bookings_count, p.gross_amount, ' +
    'p.commission_amount, p.cinetpay_fees, p.net_amount, p.status, ' +
    'p.auto_release_eligible, p.transfer_status, ' +
    'p.scheduled_at, p.released_at, p.created_at, ' +
    'u.nom AS organizer_nom, u.prenom AS organizer_prenom, u.phone AS organizer_phone, ' +
    'e.title AS event_title ' +
    'FROM payouts p ' +
    'LEFT JOIN users u ON u.id = p.organizer_id ' +
    'LEFT JOIN events e ON e.id = p.event_id' + where +
    ' ORDER BY p.created_at DESC LIMIT ' + pag.pageSize + ' OFFSET ' + pag.offset;

  var countSql = 'SELECT COUNT(*)::int AS n FROM payouts p' + where;

  // Counts par statut pour les compteurs UI (sidebar badge etc.)
  var statusCountsSql =
    "SELECT status, COUNT(*)::int AS n FROM payouts GROUP BY status";

  Promise.all([pool.query(listSql, params), pool.query(countSql, params), pool.query(statusCountsSql)])
    .then(function(results) {
      var statusCounts = { scheduled: 0, released: 0, blocked: 0, cancelled: 0 };
      results[2].rows.forEach(function(r) { statusCounts[r.status] = r.n; });

      res.json({
        success: true,
        page: pag.page,
        page_size: pag.pageSize,
        total: results[1].rows[0].n,
        status_counts: statusCounts,
        payouts: results[0].rows.map(function(r) {
          return {
            id: r.id.toString(),
            organizer: {
              id: r.organizer_id.toString(),
              nom: r.organizer_nom,
              prenom: r.organizer_prenom,
              phone: r.organizer_phone,
            },
            event: r.event_id ? { id: r.event_id.toString(), title: r.event_title } : null,
            bookings_count: r.bookings_count,
            gross_amount: parseInt(r.gross_amount) || 0,
            commission_amount: parseInt(r.commission_amount) || 0,
            cinetpay_fees: parseInt(r.cinetpay_fees) || 0,
            net_amount: parseInt(r.net_amount) || 0,
            status: r.status,
            auto_release_eligible: !!r.auto_release_eligible,
            transfer_status: r.transfer_status,
            scheduled_at: r.scheduled_at,
            released_at: r.released_at,
            created_at: r.created_at,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/payouts:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /admin/payouts/:id — Détail d'un reversement avec orga + event + payment account
router.get('/payouts/:id', function(req, res) {
  pool.query(
    'SELECT p.*, ' +
    'u.nom AS organizer_nom, u.prenom AS organizer_prenom, u.phone AS organizer_phone, ' +
    'u.email AS organizer_email, u.payout_account, ' +
    'e.title AS event_title, e.start_at AS event_start_at, e.lieu AS event_lieu, ' +
    'r.nom AS released_by_nom, r.prenom AS released_by_prenom ' +
    'FROM payouts p ' +
    'LEFT JOIN users u ON u.id = p.organizer_id ' +
    'LEFT JOIN events e ON e.id = p.event_id ' +
    'LEFT JOIN users r ON r.id = p.released_by ' +
    'WHERE p.id = $1',
    [req.params.id]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Reversement non trouvé' });
      }
      var r = result.rows[0];
      res.json({
        success: true,
        payout: {
          id: r.id.toString(),
          organizer: {
            id: r.organizer_id.toString(),
            nom: r.organizer_nom,
            prenom: r.organizer_prenom,
            phone: r.organizer_phone,
            email: r.organizer_email,
            payout_account: r.payout_account,
          },
          event: r.event_id ? {
            id: r.event_id.toString(),
            title: r.event_title,
            start_at: r.event_start_at,
            lieu: r.event_lieu,
          } : null,
          period_start: r.period_start,
          period_end: r.period_end,
          bookings_count: r.bookings_count,
          gross_amount: parseInt(r.gross_amount) || 0,
          commission_amount: parseInt(r.commission_amount) || 0,
          cinetpay_fees: parseInt(r.cinetpay_fees) || 0,
          net_amount: parseInt(r.net_amount) || 0,
          status: r.status,
          auto_release_eligible: !!r.auto_release_eligible,
          transfer_status: r.transfer_status,
          transfer_reference: r.transfer_reference,
          transfer_data: r.transfer_data,
          scheduled_at: r.scheduled_at,
          released_at: r.released_at,
          released_by: r.released_by ? {
            id: r.released_by.toString(),
            nom: r.released_by_nom,
            prenom: r.released_by_prenom,
          } : null,
          block_reason: r.block_reason,
          account_info: r.account_info,
          notes: r.notes,
          created_at: r.created_at,
          updated_at: r.updated_at,
        },
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/payouts/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/events/:id/schedule-payout — Crée un reversement pour un event
// Calcule gross/commission/fees/net depuis les bookings 'confirme' et insère un payout
// 'scheduled' avec scheduled_at = end_at + escrow_hours (défaut 48h).
router.post('/events/:id/schedule-payout', function(req, res) {
  var eventId = req.params.id;

  Promise.all([
    pool.query(
      'SELECT id, organizer_id, title, start_at, end_at FROM events WHERE id = $1',
      [eventId]
    ),
    pool.query(
      "SELECT COUNT(*)::int AS n, COALESCE(SUM(total_amount), 0)::bigint AS gross " +
      "FROM bookings WHERE event_id = $1 AND statut = 'confirme'",
      [eventId]
    ),
    pool.query(
      "SELECT id FROM payouts WHERE event_id = $1 AND status != 'cancelled' LIMIT 1",
      [eventId]
    ),
    getSetting('commission_rate', 0.06),
    getSetting('cinetpay_fee_rate', 0.015),
    getSetting('escrow_hours', 48),
  ])
    .then(function(results) {
      if (results[0].rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Événement non trouvé' });
      }
      if (results[2].rows.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Un reversement existe déjà pour cet événement',
          existing_payout_id: results[2].rows[0].id.toString(),
        });
      }

      var event = results[0].rows[0];
      var stats = results[1].rows[0];
      var gross = parseInt(stats.gross) || 0;
      var bookingsCount = stats.n;

      if (gross === 0) {
        return res.status(400).json({
          success: false,
          message: 'Aucun booking confirmé sur cet événement, rien à reverser',
        });
      }
      if (!event.organizer_id) {
        return res.status(400).json({
          success: false,
          message: 'Événement sans organisateur défini',
        });
      }

      var commissionRate = parseFloat(results[3]);
      var feeRate = parseFloat(results[4]);
      var escrowHours = parseInt(results[5]);

      var commission = Math.ceil(gross * commissionRate);
      var fees = Math.ceil(gross * feeRate);
      var net = gross - commission - fees;

      // scheduled_at = end_at (ou start_at si end_at null) + escrow
      var basis = event.end_at || event.start_at;
      var scheduledAt;
      if (basis) {
        scheduledAt = new Date(new Date(basis).getTime() + escrowHours * 3600 * 1000);
      } else {
        // Pas de date parsable : on schedule maintenant + escrow (admin pourra forcer release)
        scheduledAt = new Date(Date.now() + escrowHours * 3600 * 1000);
      }

      return pool.query(
        'INSERT INTO payouts (organizer_id, event_id, period_start, period_end, ' +
        'bookings_count, gross_amount, commission_amount, cinetpay_fees, net_amount, ' +
        "status, scheduled_at, notes) " +
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'scheduled', $10, $11) RETURNING id",
        [
          event.organizer_id, event.id,
          event.start_at, event.end_at || event.start_at,
          bookingsCount, gross, commission, fees, net,
          scheduledAt,
          'Reversement créé par admin pour l\'événement « ' + event.title + ' »',
        ]
      ).then(function(insRes) {
        var payoutId = insRes.rows[0].id;
        logAudit(req.admin.id, 'payout.schedule', 'payout', payoutId, {
          event_id: event.id, gross: gross, net: net,
        });
        res.status(201).json({
          success: true,
          payout: { id: payoutId.toString(), gross_amount: gross, net_amount: net, scheduled_at: scheduledAt },
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/events/:id/schedule-payout:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/payouts/:id/release — Marque le payout comme releasé.
// Si CINETPAY_TRANSFER_ENABLED=true et payout_account valide, déclenche aussi
// le transfer mobile money via CinetPay Transfer API. Sinon mode manuel : l'admin
// finance fait le virement via back-office CinetPay et cette route ne trace que.
// @body {string} notes - Note optionnelle
router.post('/payouts/:id/release', function(req, res) {
  var notes = (req.body.notes || '').trim();

  pool.query(
    'SELECT p.id, p.status, p.organizer_id, p.net_amount, p.event_id, ' +
    'u.payout_account, u.email AS organizer_email ' +
    'FROM payouts p LEFT JOIN users u ON u.id = p.organizer_id WHERE p.id = $1',
    [req.params.id]
  )
    .then(function(r) {
      if (r.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Reversement non trouvé' });
      }
      var p = r.rows[0];
      if (p.status === 'released') {
        return res.status(409).json({ success: false, message: 'Reversement déjà releasé' });
      }
      if (p.status === 'cancelled') {
        return res.status(409).json({ success: false, message: 'Reversement annulé, impossible à releaser' });
      }

      // Snapshot du payout_account au moment du release (au cas où il change après).
      var accountSnapshot = p.payout_account;
      var netAmount = parseInt(p.net_amount);

      // Si CinetPay Transfer activé + compte renseigné, déclenche le transfer.
      var transferPromise;
      if (cinetpay.isTransferEnabled() && accountSnapshot && accountSnapshot.provider) {
        transferPromise = cinetpay.transferPayout({
          amount: netAmount,
          account: Object.assign({}, accountSnapshot, { email: p.organizer_email }),
          reference: 'AKWABA-PAYOUT-' + p.id,
        });
      } else {
        transferPromise = Promise.resolve({
          ok: false,
          status: 'manual_required',
          raw: { message: 'Transfer manuel — CinetPay Transfer non activé ou compte absent' },
        });
      }

      return transferPromise.then(function(transferResult) {
        // Le release est tracé en DB que le transfer ait réussi ou non — c'est l'admin
        // qui décide. transfer_status laisse trace de ce qui s'est passé.
        return pool.query(
          "UPDATE payouts SET status = 'released', released_at = NOW(), released_by = $1, " +
          'account_info = $2, notes = COALESCE($3, notes), ' +
          'transfer_status = $4, transfer_reference = $5, transfer_data = $6, ' +
          'updated_at = NOW() WHERE id = $7 RETURNING id',
          [
            req.admin.id, accountSnapshot, notes || null,
            transferResult.status, transferResult.transfer_reference || null,
            JSON.stringify(transferResult.raw || {}),
            req.params.id,
          ]
        ).then(function(upd) {
          logAudit(req.admin.id, 'payout.release', 'payout', upd.rows[0].id, {
            net_amount: netAmount,
            account: accountSnapshot,
            transfer_status: transferResult.status,
            transfer_ref: transferResult.transfer_reference,
          });
          res.json({
            success: true,
            payout: {
              id: upd.rows[0].id.toString(),
              status: 'released',
              transfer_status: transferResult.status,
              transfer_reference: transferResult.transfer_reference,
            },
          });
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/payouts/:id/release:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/payouts/:id/block — Bloque un reversement suspect avec raison
// @body {string} reason
router.post('/payouts/:id/block', function(req, res) {
  var reason = (req.body.reason || '').trim();
  if (!reason) {
    return res.status(400).json({ success: false, message: 'Raison du blocage requise' });
  }

  pool.query(
    "UPDATE payouts SET status = 'blocked', block_reason = $1, updated_at = NOW() " +
    "WHERE id = $2 AND status IN ('scheduled') RETURNING id",
    [reason, req.params.id]
  )
    .then(function(r) {
      if (r.rowCount === 0) {
        return res.status(409).json({
          success: false,
          message: 'Reversement non trouvé ou déjà releasé/annulé',
        });
      }
      logAudit(req.admin.id, 'payout.block', 'payout', r.rows[0].id, { reason: reason });
      res.json({ success: true, payout: { id: r.rows[0].id.toString(), status: 'blocked' } });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/payouts/:id/block:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/payouts/:id/unblock — Débloque (remet en 'scheduled')
router.post('/payouts/:id/unblock', function(req, res) {
  pool.query(
    "UPDATE payouts SET status = 'scheduled', block_reason = NULL, updated_at = NOW() " +
    "WHERE id = $1 AND status = 'blocked' RETURNING id",
    [req.params.id]
  )
    .then(function(r) {
      if (r.rowCount === 0) {
        return res.status(409).json({ success: false, message: 'Reversement non bloqué ou inexistant' });
      }
      logAudit(req.admin.id, 'payout.unblock', 'payout', r.rows[0].id, null);
      res.json({ success: true, payout: { id: r.rows[0].id.toString(), status: 'scheduled' } });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/payouts/:id/unblock:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// ============================================================
// Marketing : banners + featured events + broadcasts (ADM-06)
// ============================================================

// GET /admin/banners — Liste toutes les bannières (actives + futures + expirées)
router.get('/banners', function(req, res) {
  pool.query(
    'SELECT id, title, subtitle, image_url, link_type, link_target, position, ' +
    'active_from, active_until, created_at FROM banners ORDER BY position ASC, created_at DESC'
  )
    .then(function(result) {
      res.json({
        success: true,
        banners: result.rows.map(function(r) {
          return {
            id: r.id.toString(),
            title: r.title,
            subtitle: r.subtitle,
            image_url: r.image_url,
            link_type: r.link_type,
            link_target: r.link_target,
            position: r.position,
            active_from: r.active_from,
            active_until: r.active_until,
            created_at: r.created_at,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/banners:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/banners — Crée une bannière
// @body {string} title, {string} image_url, {string} link_type ('event'|'url'|'category'),
//        {string} link_target, {number} position, {string?} subtitle, {string?} active_from, active_until
router.post('/banners', function(req, res) {
  var b = req.body;
  if (!b.title || !b.image_url) {
    return res.status(400).json({ success: false, message: 'title et image_url requis' });
  }
  pool.query(
    'INSERT INTO banners (title, subtitle, image_url, link_type, link_target, position, ' +
    'active_from, active_until, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id',
    [
      b.title, b.subtitle || null, b.image_url,
      b.link_type || 'event', b.link_target || null,
      parseInt(b.position) || 0,
      b.active_from || null, b.active_until || null,
      req.admin.id,
    ]
  )
    .then(function(r) {
      logAudit(req.admin.id, 'banner.create', 'banner', r.rows[0].id, { title: b.title });
      res.status(201).json({ success: true, banner: { id: r.rows[0].id.toString() } });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/banners:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /admin/banners/:id — Met à jour une bannière (champs partiels)
router.patch('/banners/:id', function(req, res) {
  var fields = [];
  var params = [];
  var allowed = ['title', 'subtitle', 'image_url', 'link_type', 'link_target',
    'position', 'active_from', 'active_until'];
  allowed.forEach(function(key) {
    if (req.body[key] !== undefined) {
      params.push(req.body[key]);
      fields.push(key + ' = $' + params.length);
    }
  });
  if (fields.length === 0) {
    return res.status(400).json({ success: false, message: 'Aucun champ à modifier' });
  }
  params.push(req.params.id);
  pool.query(
    'UPDATE banners SET ' + fields.join(', ') + ', updated_at = NOW() ' +
    'WHERE id = $' + params.length + ' RETURNING id',
    params
  )
    .then(function(r) {
      if (r.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'Bannière non trouvée' });
      }
      logAudit(req.admin.id, 'banner.update', 'banner', r.rows[0].id, null);
      res.json({ success: true });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /admin/banners/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// DELETE /admin/banners/:id — Supprime une bannière
router.delete('/banners/:id', function(req, res) {
  pool.query('DELETE FROM banners WHERE id = $1 RETURNING id', [req.params.id])
    .then(function(r) {
      if (r.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'Bannière non trouvée' });
      }
      logAudit(req.admin.id, 'banner.delete', 'banner', r.rows[0].id, null);
      res.json({ success: true });
    })
    .catch(function(err) {
      console.error('Erreur DELETE /admin/banners/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /admin/events/:id/feature — Active/désactive le badge "À la une"
// @body {boolean} is_featured, {string?} featured_until - ISO date (défaut: +7j)
router.patch('/events/:id/feature', function(req, res) {
  var isFeatured = !!req.body.is_featured;
  var until = req.body.featured_until;
  if (isFeatured && !until) {
    until = new Date(Date.now() + 7 * 24 * 3600 * 1000); // défaut: 7 jours
  }
  pool.query(
    'UPDATE events SET is_featured = $1, featured_until = $2, updated_at = NOW() ' +
    'WHERE id = $3 RETURNING id, title, is_featured',
    [isFeatured, isFeatured ? until : null, req.params.id]
  )
    .then(function(r) {
      if (r.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'Événement non trouvé' });
      }
      logAudit(req.admin.id, isFeatured ? 'event.feature' : 'event.unfeature',
        'event', r.rows[0].id, { until: until });
      res.json({ success: true, event: { id: r.rows[0].id.toString(), is_featured: isFeatured } });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /admin/events/:id/feature:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/notifications/broadcast — Envoie une notification push à un segment
// @body {string} title, {string} body, {string} segment ('all'|'role'),
//        {string?} segment_value, {object?} data
router.post('/notifications/broadcast', function(req, res) {
  var title = (req.body.title || '').trim();
  var body = (req.body.body || '').trim();
  var segment = req.body.segment || 'all';
  var segmentValue = req.body.segment_value || null;
  var data = req.body.data || {};

  if (!title || !body) {
    return res.status(400).json({ success: false, message: 'title et body requis' });
  }
  if (title.length > 120 || body.length > 500) {
    return res.status(400).json({ success: false, message: 'title <= 120, body <= 500 chars' });
  }
  if (segment !== 'all' && segment !== 'role' && segment !== 'category') {
    return res.status(400).json({
      success: false,
      message: 'segment doit être "all", "role" ou "category"',
    });
  }
  if ((segment === 'role' || segment === 'category') && !segmentValue) {
    return res.status(400).json({
      success: false,
      message: 'segment_value requis pour segment=' + segment,
    });
  }

  push.notifySegment(segment, segmentValue, { title: title, body: body, data: data })
    .then(function(stats) {
      // Log dans la table broadcasts
      return pool.query(
        'INSERT INTO broadcasts (title, body, segment, segment_value, recipients_count, ' +
        'sent_count, failed_count, data, sent_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id',
        [title, body, segment, segmentValue,
          stats.recipients_count, stats.sent_count, stats.failed_count,
          JSON.stringify(data), req.admin.id]
      ).then(function(r) {
        logAudit(req.admin.id, 'broadcast.send', 'broadcast', r.rows[0].id, {
          segment: segment, segment_value: segmentValue,
          recipients: stats.recipients_count, sent: stats.sent_count,
        });
        res.status(201).json({
          success: true,
          broadcast: {
            id: r.rows[0].id.toString(),
            recipients_count: stats.recipients_count,
            sent_count: stats.sent_count,
            failed_count: stats.failed_count,
          },
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/notifications/broadcast:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /admin/broadcasts — Historique des broadcasts envoyés
router.get('/broadcasts', function(req, res) {
  var pag = readPagination(req);
  Promise.all([
    pool.query(
      'SELECT b.id, b.title, b.body, b.segment, b.segment_value, ' +
      'b.recipients_count, b.sent_count, b.failed_count, b.sent_at, ' +
      'u.nom AS sent_by_nom, u.prenom AS sent_by_prenom ' +
      'FROM broadcasts b LEFT JOIN users u ON u.id = b.sent_by ' +
      'ORDER BY b.sent_at DESC LIMIT ' + pag.pageSize + ' OFFSET ' + pag.offset
    ),
    pool.query('SELECT COUNT(*)::int AS n FROM broadcasts'),
  ])
    .then(function(results) {
      res.json({
        success: true,
        page: pag.page,
        page_size: pag.pageSize,
        total: results[1].rows[0].n,
        broadcasts: results[0].rows.map(function(r) {
          return {
            id: r.id.toString(),
            title: r.title,
            body: r.body,
            segment: r.segment,
            segment_value: r.segment_value,
            recipients_count: r.recipients_count,
            sent_count: r.sent_count,
            failed_count: r.failed_count,
            sent_at: r.sent_at,
            sent_by: r.sent_by_nom ? r.sent_by_prenom + ' ' + r.sent_by_nom : null,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/broadcasts:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// ============================================================
// Upload signatures (v2-D) — pour Cloudinary direct upload
// ============================================================

// POST /admin/upload-signature — Génère une signature Cloudinary pour upload direct
// depuis le navigateur. Le fichier ne transite jamais par notre backend (économise
// bandwidth Render + élimine la limite de body size).
// @body {string} folder (optionnel) - dossier Cloudinary (défaut: akwaba/banners)
// @returns {object} { signature, timestamp, api_key, cloud_name, folder }
router.post('/upload-signature', function(req, res) {
  var crypto = require('crypto');
  var apiKey = process.env.CLOUDINARY_API_KEY;
  var apiSecret = process.env.CLOUDINARY_API_SECRET;
  var cloudName = process.env.CLOUDINARY_CLOUD_NAME;

  if (!apiKey || !apiSecret || !cloudName) {
    return res.status(503).json({
      success: false,
      message: 'Cloudinary non configuré (CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET requis)',
    });
  }

  var folder = req.body.folder || 'akwaba/banners';
  // Whitelist des dossiers pour éviter écriture arbitraire.
  if (!/^akwaba\/(banners|events|users)(\/[a-zA-Z0-9_-]+)?$/.test(folder)) {
    return res.status(400).json({ success: false, message: 'folder invalide' });
  }

  var timestamp = Math.floor(Date.now() / 1000);
  // Cloudinary signe les params triés alphabétiquement, joints par &, + apiSecret en suffixe.
  var paramsToSign = 'folder=' + folder + '&timestamp=' + timestamp;
  var signature = crypto.createHash('sha1').update(paramsToSign + apiSecret).digest('hex');

  logAudit(req.admin.id, 'upload.signature', 'cloudinary', folder, null);

  res.json({
    success: true,
    signature: signature,
    timestamp: timestamp,
    api_key: apiKey,
    cloud_name: cloudName,
    folder: folder,
    upload_url: 'https://api.cloudinary.com/v1_1/' + cloudName + '/image/upload',
  });
});

// ============================================================
// Platform settings (ADM-07) — clé/valeur typée en JSONB
// ============================================================

// GET /admin/settings — Liste tous les paramètres plateforme
router.get('/settings', function(req, res) {
  pool.query(
    'SELECT key, value, description, updated_at, ' +
    '(SELECT prenom || \' \' || nom FROM users WHERE id = updated_by) AS updated_by_name ' +
    'FROM app_settings ORDER BY key ASC'
  )
    .then(function(result) {
      res.json({
        success: true,
        settings: result.rows.map(function(r) {
          return {
            key: r.key,
            value: r.value,
            description: r.description,
            updated_at: r.updated_at,
            updated_by_name: r.updated_by_name,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/settings:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /admin/settings/:key — Met à jour la valeur d'un paramètre
// @body {any} value - JSON quelconque (number, string, bool, object)
router.patch('/settings/:key', function(req, res) {
  if (req.body.value === undefined) {
    return res.status(400).json({ success: false, message: 'value requis' });
  }
  // Validation basique selon la clé (évite de pousser n'importe quoi).
  var key = req.params.key;
  var value = req.body.value;
  var validators = {
    commission_rate: function(v) { return typeof v === 'number' && v >= 0 && v <= 1; },
    cinetpay_fee_rate: function(v) { return typeof v === 'number' && v >= 0 && v <= 1; },
    escrow_hours: function(v) { return typeof v === 'number' && v >= 0 && v <= 720; },
    tva_rate: function(v) { return typeof v === 'number' && v >= 0 && v <= 1; },
    payout_review_threshold_amount: function(v) { return typeof v === 'number' && v >= 0; },
    payout_review_refund_ratio: function(v) { return typeof v === 'number' && v >= 0 && v <= 1; },
    refund_policy_default: function(v) {
      return v && typeof v === 'object'
        && typeof v.more_than_48h === 'number'
        && typeof v.between_24_and_48h === 'number'
        && typeof v.less_than_24h === 'number';
    },
  };
  if (validators[key] && !validators[key](value)) {
    return res.status(400).json({
      success: false,
      message: 'Valeur invalide pour la clé ' + key,
    });
  }

  pool.query(
    'UPDATE app_settings SET value = $1, updated_by = $2, updated_at = NOW() ' +
    'WHERE key = $3 RETURNING key',
    [JSON.stringify(value), req.admin.id, key]
  )
    .then(function(r) {
      if (r.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'Paramètre inconnu' });
      }
      logAudit(req.admin.id, 'setting.update', 'setting', key, { value: value });
      res.json({ success: true });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /admin/settings/:key:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /admin/users/:id/payout-account — Définit le compte de reversement d'un orga
// @body {object} payout_account - { provider, number, name, ...}
router.patch('/users/:id/payout-account', function(req, res) {
  var account = req.body.payout_account;
  if (!account || typeof account !== 'object') {
    return res.status(400).json({ success: false, message: 'payout_account requis (objet JSON)' });
  }
  if (!account.provider || !account.number || !account.name) {
    return res.status(400).json({ success: false, message: 'provider, number, name obligatoires' });
  }

  pool.query(
    "UPDATE users SET payout_account = $1, updated_at = NOW() WHERE id = $2 AND role = 'organisateur' RETURNING id",
    [JSON.stringify(account), req.params.id]
  )
    .then(function(r) {
      if (r.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'Organisateur non trouvé' });
      }
      logAudit(req.admin.id, 'user.payout_account_update', 'user', r.rows[0].id, {
        provider: account.provider,
      });
      res.json({ success: true });
    })
    .catch(function(err) {
      console.error('Erreur PATCH payout-account:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// ============================================================
// ADM-AUDIT : Journal d'audit (lecture)
// ============================================================
// La table admin_audit_log se remplit automatiquement via logAudit() à chaque
// action admin sensible. Ces routes exposent la lecture en lecture seule.

// GET /admin/audit-log — Journal paginé avec filtres.
// @query {string} admin_id - filtrer par admin
// @query {string} action - préfixe LIKE (ex: 'event.', 'payout.')
// @query {string} target_type - 'event' | 'user' | 'payment' | 'payout' | 'banner' | etc.
// @query {string} from, to - bornes ISO date sur created_at
// @query {number} page, page_size
router.get('/audit-log', function(req, res) {
  var pag = readPagination(req);
  var clauses = [];
  var params = [];

  if (req.query.admin_id) {
    params.push(parseInt(req.query.admin_id));
    clauses.push('al.admin_id = $' + params.length);
  }
  if (req.query.action) {
    params.push(req.query.action + '%');
    clauses.push('al.action LIKE $' + params.length);
  }
  if (req.query.target_type) {
    params.push(req.query.target_type);
    clauses.push('al.target_type = $' + params.length);
  }
  if (req.query.from) {
    params.push(req.query.from);
    clauses.push('al.created_at >= $' + params.length);
  }
  if (req.query.to) {
    params.push(req.query.to);
    clauses.push('al.created_at <= $' + params.length);
  }

  var where = clauses.length > 0 ? ' WHERE ' + clauses.join(' AND ') : '';

  var listSql =
    'SELECT al.id, al.admin_id, ' +
    "u.prenom || ' ' || u.nom AS admin_name, u.email AS admin_email, " +
    'al.action, al.target_type, al.target_id, al.metadata, al.created_at ' +
    'FROM admin_audit_log al ' +
    'LEFT JOIN users u ON u.id = al.admin_id' + where +
    ' ORDER BY al.created_at DESC LIMIT ' + pag.pageSize + ' OFFSET ' + pag.offset;

  var countSql = 'SELECT COUNT(*)::int AS n FROM admin_audit_log al' + where;

  Promise.all([pool.query(listSql, params), pool.query(countSql, params)])
    .then(function(results) {
      res.json({
        success: true,
        page: pag.page,
        page_size: pag.pageSize,
        total: results[1].rows[0].n,
        entries: results[0].rows.map(function(r) {
          return {
            id: r.id.toString(),
            admin: r.admin_id ? {
              id: r.admin_id.toString(),
              name: r.admin_name,
              email: r.admin_email,
            } : null,
            action: r.action,
            target_type: r.target_type,
            target_id: r.target_id,
            metadata: r.metadata,
            created_at: r.created_at,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/audit-log:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /admin/audit-log/facets — Listes pour les dropdowns de filtre UI :
// actions distinctes, target_types distincts, admins ayant déjà loggé.
router.get('/audit-log/facets', function(req, res) {
  Promise.all([
    pool.query('SELECT DISTINCT action FROM admin_audit_log ORDER BY action ASC'),
    pool.query("SELECT DISTINCT target_type FROM admin_audit_log WHERE target_type IS NOT NULL ORDER BY target_type ASC"),
    pool.query(
      'SELECT DISTINCT al.admin_id, ' +
      "u.prenom || ' ' || u.nom AS admin_name, u.email " +
      'FROM admin_audit_log al LEFT JOIN users u ON u.id = al.admin_id ' +
      'WHERE al.admin_id IS NOT NULL ORDER BY admin_name ASC'
    ),
  ])
    .then(function(r) {
      res.json({
        success: true,
        actions: r[0].rows.map(function(x) { return x.action; }),
        target_types: r[1].rows.map(function(x) { return x.target_type; }),
        admins: r[2].rows.map(function(x) {
          return { id: x.admin_id.toString(), name: x.admin_name, email: x.email };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/audit-log/facets:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
