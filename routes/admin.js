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
          admin_role: req.admin.admin_role || 'super_admin',
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
    "COALESCE((SELECT SUM(total_amount) FROM bookings WHERE event_id = e.id AND statut = 'confirme'), 0)::bigint AS revenue, " +
    "(SELECT (value::text)::numeric FROM app_settings WHERE key = 'commission_rate') AS global_commission_rate " +
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
          commission_rate: row.commission_rate !== null ? parseFloat(row.commission_rate) : null,
          global_commission_rate: row.global_commission_rate !== null
            ? parseFloat(row.global_commission_rate) : 0.06,
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

// PATCH /admin/events/:id/commission-rate — Override le taux de commission
// d'un event. Body { commission_rate: number|null }. null = revient au défaut
// global (app_settings.commission_rate). N'affecte que les futurs payouts.
// Réservé finance + super_admin.
router.patch('/events/:id/commission-rate', auth.requireAdminRole(['finance']), function(req, res) {
  var rate = req.body.commission_rate;
  if (rate !== null && rate !== undefined) {
    if (typeof rate !== 'number' || rate < 0 || rate > 1) {
      return res.status(400).json({
        success: false,
        message: 'commission_rate doit être entre 0 et 1 (ex: 0.06 pour 6%)',
      });
    }
  } else {
    rate = null;
  }

  pool.query(
    'UPDATE events SET commission_rate = $1, updated_at = NOW() WHERE id = $2 ' +
    'RETURNING id, title, commission_rate',
    [rate, req.params.id]
  )
    .then(function(r) {
      if (r.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'Événement non trouvé' });
      }
      logAudit(req.admin.id, 'event.commission_rate_update', 'event', r.rows[0].id, {
        title: r.rows[0].title,
        new_rate: rate,
      });
      res.json({
        success: true,
        event: {
          id: r.rows[0].id.toString(),
          commission_rate: r.rows[0].commission_rate !== null
            ? parseFloat(r.rows[0].commission_rate) : null,
        },
      });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /admin/events/:id/commission-rate:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /admin/events/:id/approve — Approuver un event (le rend visible publiquement)
router.patch('/events/:id/approve', auth.requireAdminRole(['moderator']), function(req, res) {
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
router.patch('/events/:id/reject', auth.requireAdminRole(['moderator']), function(req, res) {
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
    'SELECT id, nom, prenom, phone, email, role, admin_role, suspended_at, suspended_reason, last_login_at, created_at ' +
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
            admin_role: row.admin_role,
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
      'SELECT id, nom, prenom, phone, email, role, admin_role, suspended_at, suspended_reason, last_login_at, created_at FROM users WHERE id = $1',
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
          admin_role: u.admin_role,
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
router.patch('/users/:id/suspend', auth.requireAdminRole(['moderator']), function(req, res) {
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
router.patch('/users/:id/reactivate', auth.requireAdminRole(['moderator']), function(req, res) {
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
router.post('/payments/:id/manual-refund', auth.requireAdminRole(['finance']), function(req, res) {
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
router.post('/events/:id/schedule-payout', auth.requireAdminRole(['finance']), function(req, res) {
  var eventId = req.params.id;

  Promise.all([
    pool.query(
      'SELECT id, organizer_id, title, start_at, end_at, commission_rate FROM events WHERE id = $1',
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

      // Override per-event prend précédence sur le défaut global.
      var globalRate = parseFloat(results[3]);
      var commissionRate = event.commission_rate !== null
        ? parseFloat(event.commission_rate)
        : globalRate;
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
router.post('/payouts/:id/release', auth.requireAdminRole(['finance']), function(req, res) {
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
router.post('/payouts/:id/block', auth.requireAdminRole(['finance']), function(req, res) {
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
router.post('/payouts/:id/unblock', auth.requireAdminRole(['finance']), function(req, res) {
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
router.post('/banners', auth.requireAdminRole(['moderator']), function(req, res) {
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
router.patch('/banners/:id', auth.requireAdminRole(['moderator']), function(req, res) {
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
router.delete('/banners/:id', auth.requireAdminRole(['moderator']), function(req, res) {
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
router.patch('/events/:id/feature', auth.requireAdminRole(['moderator']), function(req, res) {
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
router.post('/notifications/broadcast', auth.requireAdminRole(['moderator']), function(req, res) {
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
router.patch('/settings/:key', auth.requireAdminRole([]), function(req, res) {
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

// PATCH /admin/users/:id/admin-role — Change le rôle admin d'un user.
// Réservé super_admin. Set 'super_admin'|'moderator'|'finance'|'support' OU
// null (révoque l'admin). Auto-protection : un super_admin ne peut pas se
// dégrader lui-même (sinon plus aucun super_admin dans le système).
// @body {string|null} admin_role
router.patch('/users/:id/admin-role', auth.requireAdminRole([]), function(req, res) {
  var ALLOWED = ['super_admin', 'moderator', 'finance', 'support'];
  var newRole = req.body.admin_role === null || req.body.admin_role === ''
    ? null
    : req.body.admin_role;
  if (newRole !== null && ALLOWED.indexOf(newRole) === -1) {
    return res.status(400).json({
      success: false,
      message: 'admin_role doit être null ou un de : ' + ALLOWED.join(', '),
    });
  }
  if (parseInt(req.params.id) === req.admin.id && newRole !== 'super_admin') {
    return res.status(400).json({
      success: false,
      message: 'Un super_admin ne peut pas dégrader son propre compte',
    });
  }

  pool.query(
    "UPDATE users SET admin_role = $1, role = CASE WHEN $1 IS NULL THEN 'participant' ELSE 'admin' END, " +
    'updated_at = NOW() WHERE id = $2 RETURNING id, role, admin_role',
    [newRole, req.params.id]
  )
    .then(function(r) {
      if (r.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
      }
      logAudit(req.admin.id, 'user.admin_role_update', 'user', req.params.id, {
        new_role: newRole,
      });
      res.json({
        success: true,
        user: {
          id: r.rows[0].id.toString(),
          role: r.rows[0].role,
          admin_role: r.rows[0].admin_role,
        },
      });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /admin/users/:id/admin-role:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /admin/users/:id/payout-account — Définit le compte de reversement d'un orga
// @body {object} payout_account - { provider, number, name, ...}
router.patch('/users/:id/payout-account', auth.requireAdminRole(['finance']), function(req, res) {
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
// ADM-ANALYTICS : Cohort retention + funnel conversion
// ============================================================
// V1 sans tracking PostHog server-side : on calcule à partir des tables
// users + bookings uniquement. Cohort = mois d'inscription, retention =
// % d'users qui ont fait 1+ booking au mois M+N. Funnel = inscrits →
// 1+ booking créé → 1+ booking confirmé.
// V2 : intégrer event_view depuis PostHog pour un funnel complet (visite
// fiche event → start checkout → confirmed).

// GET /admin/analytics/cohort — Matrice cohort retention sur 12 mois.
router.get('/analytics/cohort', function(req, res) {
  // Cohort = mois d'inscription. Retention = users qui ont fait un
  // booking confirmé au mois M+N. On limite à 12 cohortes pour ne pas
  // ramener une grille géante.
  pool.query(
    "WITH user_cohorts AS ( " +
    "  SELECT id AS user_id, DATE_TRUNC('month', created_at) AS cohort_month " +
    "  FROM users " +
    "  WHERE role = 'participant' " +
    "    AND created_at >= DATE_TRUNC('month', NOW()) - INTERVAL '11 months' " +
    "), " +
    "active_months AS ( " +
    "  SELECT DISTINCT b.user_id, DATE_TRUNC('month', b.created_at) AS booking_month " +
    "  FROM bookings b WHERE b.statut = 'confirme' " +
    "), " +
    "retention AS ( " +
    "  SELECT " +
    "    uc.cohort_month, " +
    "    am.booking_month, " +
    "    COUNT(DISTINCT uc.user_id) AS active_count " +
    "  FROM user_cohorts uc " +
    "  LEFT JOIN active_months am ON am.user_id = uc.user_id " +
    "    AND am.booking_month >= uc.cohort_month " +
    "  GROUP BY uc.cohort_month, am.booking_month " +
    ") " +
    "SELECT " +
    "  r.cohort_month, " +
    "  r.booking_month, " +
    "  r.active_count, " +
    "  (SELECT COUNT(*)::int FROM user_cohorts WHERE cohort_month = r.cohort_month) AS cohort_size " +
    "FROM retention r " +
    "ORDER BY r.cohort_month ASC, r.booking_month ASC"
  )
    .then(function(r) {
      // Transforme en matrice : map cohortMonth → { size, retention: { '0': %, '1': %, ... } }
      // M0 = mois d'inscription lui-même, M1 = mois suivant, etc.
      var matrix = {};
      r.rows.forEach(function(row) {
        var cohortKey = row.cohort_month.toISOString().split('T')[0];
        if (!matrix[cohortKey]) {
          matrix[cohortKey] = {
            cohort_month: cohortKey,
            cohort_size: row.cohort_size,
            retention: {},
          };
        }
        if (row.booking_month && row.active_count) {
          var months_diff = Math.round(
            (new Date(row.booking_month).getTime() - new Date(row.cohort_month).getTime())
            / (30 * 24 * 3600 * 1000)
          );
          if (months_diff >= 0 && months_diff <= 11) {
            matrix[cohortKey].retention[months_diff] = {
              active: row.active_count,
              pct: row.cohort_size > 0
                ? Math.round((row.active_count / row.cohort_size) * 1000) / 10
                : 0,
            };
          }
        }
      });

      var cohorts = Object.keys(matrix)
        .sort()
        .reverse() // plus récente en haut
        .map(function(k) { return matrix[k]; });

      res.json({
        success: true,
        cohorts: cohorts,
        max_months: 12,
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/analytics/cohort:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /admin/analytics/funnel — Funnel de conversion users → bookings.
// 3 étapes : Inscrits, Ont créé 1+ booking (intent), Ont confirmé 1+
// booking (paying). Calculé sur tous les users 'participant' (lifetime).
router.get('/analytics/funnel', function(req, res) {
  Promise.all([
    // Funnel global (lifetime)
    pool.query(
      "SELECT " +
      "  COUNT(DISTINCT u.id)::int AS total_users, " +
      "  COUNT(DISTINCT b.user_id) FILTER (WHERE b.id IS NOT NULL)::int AS users_with_booking, " +
      "  COUNT(DISTINCT b.user_id) FILTER (WHERE b.statut = 'confirme')::int AS users_paid " +
      "FROM users u LEFT JOIN bookings b ON b.user_id = u.id " +
      "WHERE u.role = 'participant'"
    ),
    // Funnel 30 derniers jours (nouveaux users + leurs bookings dans la fenêtre)
    pool.query(
      "WITH new_users AS ( " +
      "  SELECT id FROM users WHERE role = 'participant' " +
      "  AND created_at >= NOW() - INTERVAL '30 days' " +
      ") " +
      "SELECT " +
      "  (SELECT COUNT(*)::int FROM new_users) AS total_users, " +
      "  (SELECT COUNT(DISTINCT b.user_id)::int FROM bookings b " +
      "    WHERE b.user_id IN (SELECT id FROM new_users)) AS users_with_booking, " +
      "  (SELECT COUNT(DISTINCT b.user_id)::int FROM bookings b " +
      "    WHERE b.user_id IN (SELECT id FROM new_users) AND b.statut = 'confirme') AS users_paid"
    ),
  ])
    .then(function(r) {
      var lifetime = r[0].rows[0];
      var last30d = r[1].rows[0];

      function pct(part, total) {
        return total > 0 ? Math.round((part / total) * 1000) / 10 : 0;
      }

      res.json({
        success: true,
        funnels: {
          lifetime: {
            steps: [
              { name: 'Inscrits', count: lifetime.total_users, pct: 100 },
              {
                name: 'Ont créé un booking',
                count: lifetime.users_with_booking,
                pct: pct(lifetime.users_with_booking, lifetime.total_users),
              },
              {
                name: 'Ont confirmé (payé)',
                count: lifetime.users_paid,
                pct: pct(lifetime.users_paid, lifetime.total_users),
              },
            ],
          },
          last_30_days: {
            steps: [
              { name: 'Inscrits', count: last30d.total_users, pct: 100 },
              {
                name: 'Ont créé un booking',
                count: last30d.users_with_booking,
                pct: pct(last30d.users_with_booking, last30d.total_users),
              },
              {
                name: 'Ont confirmé (payé)',
                count: last30d.users_paid,
                pct: pct(last30d.users_paid, last30d.total_users),
              },
            ],
          },
        },
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/analytics/funnel:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// ============================================================
// ADM-SUPPORT : Gestion tickets support côté admin
// ============================================================
// Les participants créent leurs tickets via /support/* (cf. routes/support.js).
// Ces routes permettent à l'admin de lister, lire, répondre, assigner, fermer.
// Toute action admin sur un ticket déclenche notif push au user.

// GET /admin/support/tickets — Liste paginée + filtres
// @query {string} status - 'open' | 'waiting' | 'resolved' | 'closed' | 'all' (défaut: 'open')
// @query {string} assigned_admin_id - filtrer par admin assigné OR 'unassigned' OR 'mine'
// @query {string} search - filtre sur subject OR nom user
router.get('/support/tickets', function(req, res) {
  var status = req.query.status || 'open';
  var assigned = req.query.assigned_admin_id || '';
  var search = req.query.search || '';
  var pag = readPagination(req);

  var clauses = [];
  var params = [];

  if (status && status !== 'all') {
    params.push(status);
    clauses.push('t.status = $' + params.length);
  }
  if (assigned === 'unassigned') {
    clauses.push('t.assigned_admin_id IS NULL');
  } else if (assigned === 'mine') {
    params.push(req.admin.id);
    clauses.push('t.assigned_admin_id = $' + params.length);
  } else if (assigned) {
    params.push(parseInt(assigned));
    clauses.push('t.assigned_admin_id = $' + params.length);
  }
  if (search) {
    params.push('%' + search + '%');
    var idx = params.length;
    clauses.push('(LOWER(t.subject) LIKE LOWER($' + idx + ') OR LOWER(u.nom) LIKE LOWER($' + idx + ') OR LOWER(u.prenom) LIKE LOWER($' + idx + '))');
  }

  var where = clauses.length > 0 ? ' WHERE ' + clauses.join(' AND ') : '';

  var listSql =
    'SELECT t.id, t.user_id, u.nom AS user_nom, u.prenom AS user_prenom, u.phone AS user_phone, ' +
    't.subject, t.status, t.assigned_admin_id, ' +
    "a.prenom || ' ' || a.nom AS assigned_admin_name, " +
    't.last_message_at, t.created_at, ' +
    'COALESCE((SELECT COUNT(*)::int FROM support_messages WHERE ticket_id = t.id), 0) AS messages_count ' +
    'FROM support_tickets t ' +
    'JOIN users u ON u.id = t.user_id ' +
    'LEFT JOIN users a ON a.id = t.assigned_admin_id' + where +
    ' ORDER BY t.last_message_at DESC LIMIT ' + pag.pageSize + ' OFFSET ' + pag.offset;

  var countSql =
    'SELECT COUNT(*)::int AS n FROM support_tickets t ' +
    'JOIN users u ON u.id = t.user_id' + where;

  // Compteurs par statut pour la sidebar/tabs (sans appliquer status filter).
  var noStatusClauses = clauses.filter(function(c) { return !c.startsWith('t.status'); });
  var noStatusParams = params.slice(0, noStatusClauses.length);
  var statusCountSql =
    'SELECT status, COUNT(*)::int AS n FROM support_tickets t ' +
    (clauses.indexOf('t.status') !== -1
      ? 'WHERE ' + clauses.filter(function(c) { return !c.startsWith('t.status'); }).join(' AND ')
      : '') +
    ' GROUP BY status';

  Promise.all([
    pool.query(listSql, params),
    pool.query(countSql, params),
    pool.query('SELECT status, COUNT(*)::int AS n FROM support_tickets GROUP BY status'),
  ])
    .then(function(r) {
      var statusCounts = { open: 0, waiting: 0, resolved: 0, closed: 0 };
      r[2].rows.forEach(function(row) { statusCounts[row.status] = row.n; });

      res.json({
        success: true,
        page: pag.page,
        page_size: pag.pageSize,
        total: r[1].rows[0].n,
        status_counts: statusCounts,
        tickets: r[0].rows.map(function(t) {
          return {
            id: t.id.toString(),
            user: {
              id: t.user_id.toString(),
              nom: t.user_nom,
              prenom: t.user_prenom,
              phone: t.user_phone,
            },
            subject: t.subject,
            status: t.status,
            assigned_admin: t.assigned_admin_id ? {
              id: t.assigned_admin_id.toString(),
              name: t.assigned_admin_name,
            } : null,
            messages_count: t.messages_count,
            last_message_at: t.last_message_at,
            created_at: t.created_at,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/support/tickets:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /admin/support/tickets/:id — Thread complet + détails ticket.
router.get('/support/tickets/:id', function(req, res) {
  Promise.all([
    pool.query(
      'SELECT t.id, t.user_id, u.nom AS user_nom, u.prenom AS user_prenom, ' +
      'u.phone AS user_phone, u.email AS user_email, ' +
      't.subject, t.status, t.assigned_admin_id, ' +
      "a.prenom || ' ' || a.nom AS assigned_admin_name, " +
      't.last_message_at, t.created_at, t.updated_at ' +
      'FROM support_tickets t JOIN users u ON u.id = t.user_id ' +
      'LEFT JOIN users a ON a.id = t.assigned_admin_id ' +
      'WHERE t.id = $1',
      [req.params.id]
    ),
    pool.query(
      'SELECT m.id, m.author_id, m.author_role, ' +
      "u.prenom || ' ' || u.nom AS author_name, " +
      'm.body, m.created_at ' +
      'FROM support_messages m LEFT JOIN users u ON u.id = m.author_id ' +
      'WHERE m.ticket_id = $1 ORDER BY m.created_at ASC',
      [req.params.id]
    ),
  ])
    .then(function(r) {
      if (r[0].rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Ticket non trouvé' });
      }
      var t = r[0].rows[0];
      res.json({
        success: true,
        ticket: {
          id: t.id.toString(),
          user: {
            id: t.user_id.toString(),
            nom: t.user_nom,
            prenom: t.user_prenom,
            phone: t.user_phone,
            email: t.user_email,
          },
          subject: t.subject,
          status: t.status,
          assigned_admin: t.assigned_admin_id ? {
            id: t.assigned_admin_id.toString(),
            name: t.assigned_admin_name,
          } : null,
          last_message_at: t.last_message_at,
          created_at: t.created_at,
          updated_at: t.updated_at,
        },
        messages: r[1].rows.map(function(m) {
          return {
            id: m.id.toString(),
            author_id: m.author_id.toString(),
            author_role: m.author_role,
            author_name: m.author_name,
            body: m.body,
            created_at: m.created_at,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/support/tickets/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/support/tickets/:id/messages — Admin répond au ticket.
// Change auto le status en 'waiting' (attend retour user) + assigne le ticket
// à l'admin qui répond s'il n'est pas déjà assigné.
// @body {string} body
router.post('/support/tickets/:id/messages', function(req, res) {
  var body = (req.body.body || '').trim();
  if (!body) {
    return res.status(400).json({ success: false, message: 'body requis' });
  }
  if (body.length > 5000) {
    return res.status(400).json({ success: false, message: 'body trop long (5000 chars max)' });
  }

  pool.query(
    'SELECT id, user_id, status, assigned_admin_id FROM support_tickets WHERE id = $1',
    [req.params.id]
  )
    .then(function(r) {
      if (r.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Ticket non trouvé' });
      }
      var t = r.rows[0];

      return Promise.all([
        pool.query(
          "INSERT INTO support_messages (ticket_id, author_id, author_role, body) " +
          "VALUES ($1, $2, 'admin', $3) RETURNING id, created_at",
          [req.params.id, req.admin.id, body]
        ),
        pool.query(
          "UPDATE support_tickets SET status = 'waiting', " +
          "assigned_admin_id = COALESCE(assigned_admin_id, $1), " +
          "last_message_at = NOW(), updated_at = NOW() WHERE id = $2",
          [req.admin.id, req.params.id]
        ),
      ]).then(function(results) {
        logAudit(req.admin.id, 'support.reply', 'ticket', req.params.id, null);
        // Push au user qui a ouvert le ticket
        push.notifyUser(t.user_id, {
          title: 'Réponse Akwaba à ton ticket 💬',
          body: body.length > 80 ? body.slice(0, 80) + '…' : body,
          data: {
            type: 'support_admin_reply',
            ticketId: req.params.id,
          },
        });

        res.status(201).json({
          success: true,
          message: {
            id: results[0].rows[0].id.toString(),
            created_at: results[0].rows[0].created_at,
          },
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/support/tickets/:id/messages:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /admin/support/tickets/:id — Met à jour status ou assigned_admin_id.
// @body {string?} status, {number|null?} assigned_admin_id
router.patch('/support/tickets/:id', function(req, res) {
  var STATUS_OK = ['open', 'waiting', 'resolved', 'closed'];
  var fields = [];
  var params = [];

  if (req.body.status !== undefined) {
    if (STATUS_OK.indexOf(req.body.status) === -1) {
      return res.status(400).json({
        success: false,
        message: 'status invalide. Disponibles: ' + STATUS_OK.join(', '),
      });
    }
    params.push(req.body.status);
    fields.push('status = $' + params.length);
  }
  if (req.body.assigned_admin_id !== undefined) {
    var aid = req.body.assigned_admin_id;
    if (aid === null || aid === '') {
      params.push(null);
    } else {
      params.push(parseInt(aid));
    }
    fields.push('assigned_admin_id = $' + params.length);
  }
  if (fields.length === 0) {
    return res.status(400).json({ success: false, message: 'Aucun champ à modifier' });
  }

  params.push(req.params.id);
  pool.query(
    'UPDATE support_tickets SET ' + fields.join(', ') +
    ', updated_at = NOW() WHERE id = $' + params.length + ' RETURNING id, status, assigned_admin_id',
    params
  )
    .then(function(r) {
      if (r.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'Ticket non trouvé' });
      }
      logAudit(req.admin.id, 'support.update', 'ticket', req.params.id, req.body);
      res.json({
        success: true,
        ticket: {
          id: r.rows[0].id.toString(),
          status: r.rows[0].status,
          assigned_admin_id: r.rows[0].assigned_admin_id
            ? r.rows[0].assigned_admin_id.toString()
            : null,
        },
      });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /admin/support/tickets/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// ============================================================
// ADM-FINANCE : Dashboard financier
// ============================================================
// Vue agrégée pour le pilotage cash : mois courant vs précédent, à reverser,
// commissions, refunds, breakdown méthodes, série quotidienne 30j.

router.get('/finance', function(req, res) {
  // Pre-fetch settings pour avoir le taux global avant de lancer les queries
  // bookings (qui doivent passer le taux comme param SQL pour le COALESCE
  // per-event).
  pool.query(
    "SELECT key, value FROM app_settings " +
    "WHERE key IN ('commission_rate', 'cinetpay_fee_rate', 'tva_rate')"
  ).then(function(settingsResult) {
    var settings = {};
    settingsResult.rows.forEach(function(s) { settings[s.key] = parseFloat(s.value); });
    var commissionRate = settings.commission_rate || 0.06;
    var feeRate = settings.cinetpay_fee_rate || 0.015;
    var tvaRate = settings.tva_rate || 0.18;

  return Promise.all([
    // 1. Bookings confirmed : mois courant + précédent.
    //    Commission calculée per-event via COALESCE(e.commission_rate, $1).
    pool.query(
      "SELECT " +
      "COUNT(*) FILTER (WHERE b.created_at >= date_trunc('month', NOW()))::int AS bookings_this, " +
      "COALESCE(SUM(b.total_amount) FILTER (WHERE b.created_at >= date_trunc('month', NOW())), 0)::bigint AS revenue_this, " +
      "COALESCE(SUM(b.total_amount * COALESCE(e.commission_rate, $1)) " +
      "  FILTER (WHERE b.created_at >= date_trunc('month', NOW())), 0)::bigint AS commission_this, " +
      "COUNT(*) FILTER (WHERE b.created_at >= date_trunc('month', NOW() - INTERVAL '1 month') " +
      "  AND b.created_at < date_trunc('month', NOW()))::int AS bookings_prev, " +
      "COALESCE(SUM(b.total_amount) FILTER (WHERE b.created_at >= date_trunc('month', NOW() - INTERVAL '1 month') " +
      "  AND b.created_at < date_trunc('month', NOW())), 0)::bigint AS revenue_prev, " +
      "COALESCE(SUM(b.total_amount * COALESCE(e.commission_rate, $1)) " +
      "  FILTER (WHERE b.created_at >= date_trunc('month', NOW() - INTERVAL '1 month') " +
      "    AND b.created_at < date_trunc('month', NOW())), 0)::bigint AS commission_prev " +
      "FROM bookings b JOIN events e ON e.id = b.event_id " +
      "WHERE b.statut = 'confirme'",
      [commissionRate]
    ),
    // 2. Payouts par statut : à reverser (scheduled + blocked) et déjà reversé ce mois
    pool.query(
      "SELECT " +
      "COUNT(*) FILTER (WHERE status = 'scheduled')::int AS scheduled_count, " +
      "COALESCE(SUM(net_amount) FILTER (WHERE status = 'scheduled'), 0)::bigint AS scheduled_amount, " +
      "COUNT(*) FILTER (WHERE status = 'blocked')::int AS blocked_count, " +
      "COALESCE(SUM(net_amount) FILTER (WHERE status = 'blocked'), 0)::bigint AS blocked_amount, " +
      "COUNT(*) FILTER (WHERE status = 'released' AND released_at >= date_trunc('month', NOW()))::int AS released_count_this, " +
      "COALESCE(SUM(net_amount) FILTER (WHERE status = 'released' AND released_at >= date_trunc('month', NOW())), 0)::bigint AS released_amount_this " +
      'FROM payouts'
    ),
    // 3. Refunds ce mois
    pool.query(
      'SELECT COUNT(*)::int AS count, ' +
      'COALESCE(SUM(refund_amount), 0)::bigint AS amount ' +
      'FROM bookings WHERE cancelled_at IS NOT NULL ' +
      "AND cancelled_at >= date_trunc('month', NOW())"
    ),
    // 4. Breakdown par méthode (paiements ACCEPTED ce mois)
    pool.query(
      "SELECT COALESCE(p.method, 'unknown') AS method, " +
      'COUNT(*)::int AS count, ' +
      'COALESCE(SUM(p.amount), 0)::bigint AS amount ' +
      'FROM payments p ' +
      "WHERE p.created_at >= date_trunc('month', NOW()) " +
      "AND p.status = 'ACCEPTED' " +
      'GROUP BY p.method ORDER BY amount DESC'
    ),
    // 5. Revenue quotidien 30 derniers jours (line chart)
    pool.query(
      'SELECT DATE(created_at) AS day, ' +
      'COUNT(*)::int AS count, ' +
      'COALESCE(SUM(total_amount), 0)::bigint AS revenue ' +
      'FROM bookings ' +
      "WHERE statut = 'confirme' " +
      "AND created_at >= NOW() - INTERVAL '30 days' " +
      'GROUP BY DATE(created_at) ORDER BY day ASC'
    ),
  ])
    .then(function(r) {
      var bk = r[0].rows[0];
      var po = r[1].rows[0];
      var rf = r[2].rows[0];
      var methods = r[3].rows;
      var daily = r[4].rows;

      var revenueThis = parseInt(bk.revenue_this) || 0;
      var revenuePrev = parseInt(bk.revenue_prev) || 0;
      // Commission per-event déjà sommée en SQL via COALESCE(e.commission_rate, $globalRate).
      var commissionThis = parseInt(bk.commission_this) || 0;
      var commissionPrev = parseInt(bk.commission_prev) || 0;
      var feesThis = Math.ceil(revenueThis * feeRate);
      var refundsAmount = parseInt(rf.amount) || 0;

      // Variation % vs mois précédent. Si prev=0, +100% si this>0, sinon 0.
      function delta(a, b) {
        if (!b) return a > 0 ? 1 : 0;
        return (a - b) / b;
      }

      res.json({
        success: true,
        finance: {
          month: {
            revenue_this: revenueThis,
            revenue_prev: revenuePrev,
            revenue_delta_pct: delta(revenueThis, revenuePrev),
            bookings_this: bk.bookings_this,
            bookings_prev: bk.bookings_prev,
            commission_this: commissionThis,
            commission_prev: commissionPrev,
            fees_this: feesThis,
            refunds_count: rf.count,
            refunds_amount: refundsAmount,
            net_for_orgas_this: revenueThis - commissionThis - feesThis - refundsAmount,
          },
          payouts: {
            scheduled_count: po.scheduled_count,
            scheduled_amount: parseInt(po.scheduled_amount) || 0,
            blocked_count: po.blocked_count,
            blocked_amount: parseInt(po.blocked_amount) || 0,
            released_count_this: po.released_count_this,
            released_amount_this: parseInt(po.released_amount_this) || 0,
          },
          rates: {
            commission: commissionRate,
            cinetpay_fee: feeRate,
            tva: tvaRate,
          },
          methods: methods.map(function(m) {
            return {
              method: m.method,
              count: m.count,
              amount: parseInt(m.amount) || 0,
            };
          }),
          daily_revenue: daily.map(function(d) {
            return {
              day: d.day,
              count: d.count,
              revenue: parseInt(d.revenue) || 0,
            };
          }),
        },
      });
    });
  }).catch(function(err) {
    console.error('Erreur GET /admin/finance:', err.message);
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  });
});

// ============================================================
// ADM-NOTES : Notes internes polymorphiques
// ============================================================
// 4 target_types autorisés : user, event, payment, payout. Whitelist côté
// API pour éviter d'écrire n'importe quoi via JSON forgé.

var ALLOWED_NOTE_TARGETS = ['user', 'event', 'payment', 'payout'];

// GET /admin/notes?target_type=X&target_id=Y — Liste des notes sur une entité.
router.get('/notes', function(req, res) {
  var targetType = req.query.target_type;
  var targetId = req.query.target_id;
  if (!targetType || !targetId) {
    return res.status(400).json({ success: false, message: 'target_type et target_id requis' });
  }
  if (ALLOWED_NOTE_TARGETS.indexOf(targetType) === -1) {
    return res.status(400).json({ success: false, message: 'target_type invalide' });
  }

  pool.query(
    'SELECT n.id, n.author_id, ' +
    "u.prenom || ' ' || u.nom AS author_name, u.email AS author_email, " +
    'n.body, n.created_at, n.updated_at ' +
    'FROM admin_notes n JOIN users u ON u.id = n.author_id ' +
    'WHERE n.target_type = $1 AND n.target_id = $2 ' +
    'ORDER BY n.created_at DESC',
    [targetType, targetId]
  )
    .then(function(r) {
      res.json({
        success: true,
        notes: r.rows.map(function(n) {
          return {
            id: n.id.toString(),
            author: { id: n.author_id.toString(), name: n.author_name, email: n.author_email },
            body: n.body,
            created_at: n.created_at,
            updated_at: n.updated_at,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/notes:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/notes — Crée une note.
// @body {string} target_type, target_id, body
router.post('/notes', function(req, res) {
  var targetType = req.body.target_type;
  var targetId = String(req.body.target_id || '');
  var body = (req.body.body || '').trim();
  if (!targetType || !targetId || !body) {
    return res.status(400).json({ success: false, message: 'target_type, target_id, body requis' });
  }
  if (ALLOWED_NOTE_TARGETS.indexOf(targetType) === -1) {
    return res.status(400).json({ success: false, message: 'target_type invalide' });
  }
  if (body.length > 5000) {
    return res.status(400).json({ success: false, message: 'Note trop longue (5000 chars max)' });
  }

  pool.query(
    'INSERT INTO admin_notes (author_id, target_type, target_id, body) ' +
    'VALUES ($1, $2, $3, $4) RETURNING id, created_at',
    [req.admin.id, targetType, targetId, body]
  )
    .then(function(r) {
      logAudit(req.admin.id, 'note.create', targetType, targetId, { note_id: r.rows[0].id });
      res.status(201).json({
        success: true,
        note: {
          id: r.rows[0].id.toString(),
          created_at: r.rows[0].created_at,
        },
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/notes:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// DELETE /admin/notes/:id — Supprime une note. L'auteur peut toujours
// supprimer sa propre note. Un autre admin ne peut pas (audit trail).
// V2 : super_admin pourra forcer la suppression de toute note.
router.delete('/notes/:id', function(req, res) {
  pool.query('SELECT author_id, target_type, target_id FROM admin_notes WHERE id = $1', [req.params.id])
    .then(function(r) {
      if (r.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Note non trouvée' });
      }
      var note = r.rows[0];
      if (note.author_id !== req.admin.id) {
        return res.status(403).json({
          success: false,
          message: 'Seul l\'auteur peut supprimer sa note',
        });
      }
      return pool.query('DELETE FROM admin_notes WHERE id = $1', [req.params.id])
        .then(function() {
          logAudit(req.admin.id, 'note.delete', note.target_type, note.target_id, {
            note_id: parseInt(req.params.id),
          });
          res.json({ success: true });
        });
    })
    .catch(function(err) {
      console.error('Erreur DELETE /admin/notes/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// ============================================================
// ADM-BULK : Actions en masse (modération events + suspension users)
// ============================================================
// Limite hard 100 items par batch pour éviter timeout Render + UPDATE qui
// touche trop de rows d'un coup. Côté UI on devrait toujours rester sous
// la limite — pagination 50 par page max.

var BULK_MAX = 100;

// POST /admin/events/bulk-approve — Approuve plusieurs events en attente.
// Skip ceux qui ne sont pas 'pending' (status != pending → ignoré silencieusement).
// @body {number[]} event_ids
router.post('/events/bulk-approve', auth.requireAdminRole(['moderator']), function(req, res) {
  var ids = (req.body.event_ids || []).map(function(x) { return parseInt(x); }).filter(Boolean);
  if (ids.length === 0) {
    return res.status(400).json({ success: false, message: 'event_ids requis (array non vide)' });
  }
  if (ids.length > BULK_MAX) {
    return res.status(400).json({
      success: false,
      message: 'Max ' + BULK_MAX + ' events par batch',
    });
  }

  pool.query(
    "UPDATE events SET status = 'approved', moderated_by = $1, " +
    "moderated_at = NOW(), rejection_reason = NULL " +
    "WHERE id = ANY($2::int[]) AND status = 'pending' RETURNING id",
    [req.admin.id, ids]
  )
    .then(function(result) {
      var approvedIds = result.rows.map(function(r) { return r.id; });
      logAudit(req.admin.id, 'event.bulk_approve', 'event', null, {
        requested: ids.length, approved: approvedIds.length, ids: approvedIds,
      });
      // Push followers pour chaque event approuvé (fire-and-forget, ignore erreurs)
      approvedIds.forEach(function(id) {
        followsRouter.notifyFollowersOfNewEvent(id);
      });
      res.json({
        success: true,
        approved_count: approvedIds.length,
        skipped_count: ids.length - approvedIds.length,
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/events/bulk-approve:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/events/bulk-reject — Rejette plusieurs events en attente
// avec la même raison. Skip ceux pas 'pending'.
// @body {number[]} event_ids, {string} reason
router.post('/events/bulk-reject', auth.requireAdminRole(['moderator']), function(req, res) {
  var ids = (req.body.event_ids || []).map(function(x) { return parseInt(x); }).filter(Boolean);
  var reason = (req.body.reason || '').trim();
  if (ids.length === 0 || !reason) {
    return res.status(400).json({ success: false, message: 'event_ids et reason requis' });
  }
  if (ids.length > BULK_MAX) {
    return res.status(400).json({ success: false, message: 'Max ' + BULK_MAX + ' events par batch' });
  }

  pool.query(
    "UPDATE events SET status = 'rejected', moderated_by = $1, moderated_at = NOW(), " +
    "rejection_reason = $2 WHERE id = ANY($3::int[]) AND status = 'pending' RETURNING id",
    [req.admin.id, reason, ids]
  )
    .then(function(result) {
      var rejectedIds = result.rows.map(function(r) { return r.id; });
      logAudit(req.admin.id, 'event.bulk_reject', 'event', null, {
        requested: ids.length, rejected: rejectedIds.length, reason: reason, ids: rejectedIds,
      });
      res.json({
        success: true,
        rejected_count: rejectedIds.length,
        skipped_count: ids.length - rejectedIds.length,
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/events/bulk-reject:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /admin/users/bulk-suspend — Suspend plusieurs users avec la même raison.
// Skip ceux déjà suspendus + refuse de suspendre l'admin qui fait la requête.
// @body {number[]} user_ids, {string} reason
router.post('/users/bulk-suspend', auth.requireAdminRole(['moderator']), function(req, res) {
  var ids = (req.body.user_ids || []).map(function(x) { return parseInt(x); }).filter(Boolean);
  var reason = (req.body.reason || '').trim();
  if (ids.length === 0 || !reason) {
    return res.status(400).json({ success: false, message: 'user_ids et reason requis' });
  }
  if (ids.length > BULK_MAX) {
    return res.status(400).json({ success: false, message: 'Max ' + BULK_MAX + ' users par batch' });
  }
  if (ids.indexOf(req.admin.id) !== -1) {
    return res.status(400).json({
      success: false,
      message: 'Impossible de se suspendre soi-même dans un batch',
    });
  }

  pool.query(
    'UPDATE users SET suspended_at = NOW(), suspended_reason = $1 ' +
    'WHERE id = ANY($2::int[]) AND suspended_at IS NULL RETURNING id',
    [reason, ids]
  )
    .then(function(result) {
      var suspendedIds = result.rows.map(function(r) { return r.id; });
      logAudit(req.admin.id, 'user.bulk_suspend', 'user', null, {
        requested: ids.length, suspended: suspendedIds.length, reason: reason, ids: suspendedIds,
      });
      res.json({
        success: true,
        suspended_count: suspendedIds.length,
        skipped_count: ids.length - suspendedIds.length,
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/users/bulk-suspend:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// ============================================================
// ADM-HEALTH : Score santé organisateur
// ============================================================
// Score composite 0-100 sur 4 axes pondérés :
//   - Note moyenne reviews (max 50 pts)         → satisfaction client
//   - Taux refund inverse (max 20 pts)          → discipline annulations
//   - Taux approval (max 15 pts)                → qualité des soumissions
//   - Taux check-in (max 15 pts)                → no-show inverse
//
// Total max = 100. Bucket :
//   80+   = excellent     (vert)
//   60-79 = bon           (vert clair)
//   40-59 = moyen         (ocre)
//   <40   = à surveiller  (rose)
//   N/A   = pas assez de données (orga < 3 events ou 0 booking)

// GET /admin/users/:id/health — Stats agrégées + score pour un organisateur.
// Renvoie 400 si l'user n'est pas organisateur (pas pertinent).
router.get('/users/:id/health', function(req, res) {
  var userId = req.params.id;

  pool.query("SELECT id, role FROM users WHERE id = $1", [userId])
    .then(function(r) {
      if (r.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
      }
      if (r.rows[0].role !== 'organisateur') {
        return res.status(400).json({
          success: false,
          message: 'Health score réservé aux organisateurs',
        });
      }

      return Promise.all([
        // Events stats
        pool.query(
          "SELECT " +
          "COUNT(*) FILTER (WHERE status = 'approved')::int AS events_approved, " +
          "COUNT(*) FILTER (WHERE status = 'rejected')::int AS events_rejected, " +
          "COUNT(*) FILTER (WHERE status = 'pending')::int AS events_pending, " +
          "COUNT(*)::int AS events_total " +
          "FROM events WHERE organizer_id = $1",
          [userId]
        ),
        // Bookings stats sur tous ses events
        pool.query(
          'SELECT ' +
          'COUNT(b.id)::int AS bookings_total, ' +
          "COUNT(b.id) FILTER (WHERE b.statut = 'confirme' AND b.cancelled_at IS NULL)::int AS bookings_confirmed, " +
          'COUNT(b.id) FILTER (WHERE b.cancelled_at IS NOT NULL)::int AS bookings_cancelled, ' +
          'COUNT(b.id) FILTER (WHERE b.utilise_at IS NOT NULL)::int AS bookings_used ' +
          'FROM bookings b JOIN events e ON e.id = b.event_id ' +
          'WHERE e.organizer_id = $1',
          [userId]
        ),
        // Reviews stats sur tous ses events
        pool.query(
          'SELECT ' +
          'COUNT(*)::int AS reviews_count, ' +
          'AVG(rating)::numeric(3,2) AS avg_rating ' +
          'FROM reviews r JOIN events e ON e.id = r.event_id ' +
          'WHERE e.organizer_id = $1',
          [userId]
        ),
      ]).then(function(results) {
        var ev = results[0].rows[0];
        var bk = results[1].rows[0];
        var rv = results[2].rows[0];

        var avgRating = rv.avg_rating !== null ? parseFloat(rv.avg_rating) : null;
        var refundRate = bk.bookings_total > 0
          ? bk.bookings_cancelled / bk.bookings_total : null;
        var rejectionRate = ev.events_total > 0
          ? ev.events_rejected / ev.events_total : null;
        var checkinRate = bk.bookings_confirmed > 0
          ? bk.bookings_used / bk.bookings_confirmed : null;

        // Score N/A si insuffisant de données (moins de 3 events OU 0 booking)
        var canScore = ev.events_total >= 3 && bk.bookings_total > 0;
        var score = null;
        var bucket = 'insufficient';
        if (canScore) {
          var ratingPart = avgRating !== null ? avgRating * 10 : 35; // baseline 3.5/5 si pas de reviews
          var refundPart = (1 - (refundRate || 0)) * 20;
          var approvalPart = (1 - (rejectionRate || 0)) * 15;
          var checkinPart = (checkinRate !== null ? checkinRate : 0.7) * 15; // baseline 70% si null
          score = Math.round(ratingPart + refundPart + approvalPart + checkinPart);
          if (score >= 80) bucket = 'excellent';
          else if (score >= 60) bucket = 'good';
          else if (score >= 40) bucket = 'fair';
          else bucket = 'at_risk';
        }

        res.json({
          success: true,
          health: {
            score: score,
            bucket: bucket,
            metrics: {
              events_total: ev.events_total,
              events_approved: ev.events_approved,
              events_rejected: ev.events_rejected,
              events_pending: ev.events_pending,
              bookings_total: bk.bookings_total,
              bookings_confirmed: bk.bookings_confirmed,
              bookings_cancelled: bk.bookings_cancelled,
              bookings_used: bk.bookings_used,
              reviews_count: rv.reviews_count,
              avg_rating: avgRating,
              refund_rate: refundRate,
              rejection_rate: rejectionRate,
              checkin_rate: checkinRate,
            },
          },
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/users/:id/health:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// ============================================================
// ADM-DIGEST : Trigger manuel du digest quotidien
// ============================================================

// POST /admin/digest/send-now — Force la génération + envoi du digest J-1
// immédiatement (au lieu d'attendre 8h UTC). Utile en debug ou si le cron
// a manqué la fenêtre (Render free tier sleep).
router.post('/digest/send-now', auth.requireAdminRole([]), function(req, res) {
  var digest = require('../jobs/admin-digest');
  digest.sendDigestForToday()
    .then(function(result) {
      logAudit(req.admin.id, 'admin.digest.manual_send', null, null, result);
      res.json({ success: true, result: result });
    })
    .catch(function(err) {
      console.error('Erreur POST /admin/digest/send-now:', err.message);
      res.status(500).json({ success: false, message: err.message });
    });
});

// GET /admin/digest/latest — Renvoie le dernier digest généré (data + html).
// Pratique pour preview côté UI sans devoir attendre / forcer un envoi.
router.get('/digest/latest', function(req, res) {
  pool.query(
    'SELECT id, digest_date, data, html, email_sent_at, email_recipients, email_error, created_at ' +
    'FROM admin_digests ORDER BY digest_date DESC LIMIT 1'
  )
    .then(function(r) {
      if (r.rows.length === 0) {
        return res.json({ success: true, digest: null });
      }
      var row = r.rows[0];
      res.json({
        success: true,
        digest: {
          id: row.id.toString(),
          digest_date: row.digest_date,
          data: row.data,
          html: row.html,
          email_sent_at: row.email_sent_at,
          email_recipients: row.email_recipients,
          email_error: row.email_error,
          created_at: row.created_at,
        },
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/digest/latest:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// ============================================================
// ADM-SEARCH : Recherche globale Cmd+K
// ============================================================
// Recherche en parallèle dans 4 tables (users / events / bookings / payments).
// Top 5 par catégorie, ordonné par created_at DESC pour ramener les résultats
// récents en premier. LIKE % insensible à la casse sauf pour les refs/transac
// (qui sont normalisées en UPPER).

// GET /admin/search?q=
// @query {string} q - texte de recherche (min 2 chars sinon empty arrays)
router.get('/search', function(req, res) {
  var q = (req.query.q || '').trim();
  if (q.length < 2) {
    return res.json({
      success: true,
      users: [], events: [], bookings: [], payments: [],
    });
  }
  var like = '%' + q + '%';
  var likeUpper = '%' + q.toUpperCase() + '%';

  Promise.all([
    pool.query(
      'SELECT id, nom, prenom, phone, email, role ' +
      'FROM users ' +
      "WHERE LOWER(nom) LIKE LOWER($1) OR LOWER(prenom) LIKE LOWER($1) " +
      "OR phone LIKE $1 OR LOWER(COALESCE(email, '')) LIKE LOWER($1) " +
      'ORDER BY created_at DESC LIMIT 5',
      [like]
    ),
    pool.query(
      'SELECT id, title, status, date, category ' +
      'FROM events WHERE LOWER(title) LIKE LOWER($1) ' +
      'ORDER BY created_at DESC LIMIT 5',
      [like]
    ),
    pool.query(
      'SELECT b.id, b.ref, b.statut, b.total_amount, b.created_at, ' +
      'u.nom AS user_nom, u.prenom AS user_prenom, ' +
      'e.title AS event_title ' +
      'FROM bookings b ' +
      'LEFT JOIN users u ON u.id = b.user_id ' +
      'LEFT JOIN events e ON e.id = b.event_id ' +
      'WHERE UPPER(b.ref) LIKE $1 OR b.transaction_id LIKE $2 ' +
      'ORDER BY b.created_at DESC LIMIT 5',
      [likeUpper, like]
    ),
    pool.query(
      'SELECT id, transaction_id, amount, currency, status, method ' +
      'FROM payments WHERE transaction_id LIKE $1 ' +
      'ORDER BY created_at DESC LIMIT 5',
      [like]
    ),
  ])
    .then(function(results) {
      res.json({
        success: true,
        users: results[0].rows.map(function(u) {
          return {
            id: u.id.toString(),
            nom: u.nom, prenom: u.prenom, phone: u.phone, email: u.email, role: u.role,
          };
        }),
        events: results[1].rows.map(function(e) {
          return {
            id: e.id.toString(),
            title: e.title, status: e.status, date: e.date, category: e.category,
          };
        }),
        bookings: results[2].rows.map(function(b) {
          return {
            id: b.id.toString(),
            ref: b.ref, statut: b.statut, total_amount: b.total_amount,
            user_nom: b.user_nom, user_prenom: b.user_prenom,
            event_title: b.event_title,
          };
        }),
        payments: results[3].rows.map(function(p) {
          return {
            id: p.id.toString(),
            transaction_id: p.transaction_id, amount: p.amount, currency: p.currency,
            status: p.status, method: p.method,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /admin/search:', err.message);
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
