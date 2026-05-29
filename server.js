// server.js — Point d'entrée du backend Akwaba
// API REST pour la billetterie événementielle

require('dotenv').config();

// Sentry doit être require/init AVANT express et tout autre import qui pourrait throw,
// pour pouvoir capturer ces erreurs au boot. DSN passé via SENTRY_DSN env var ;
// si absent (dev local), Sentry ne capture rien — l'app fonctionne normalement.
var Sentry = require('@sentry/node');
if (process.env.SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV || 'development',
    tracesSampleRate: 0.2,
  });
}

var express = require('express');
var cors = require('cors');
var helmet = require('helmet');
var rateLimit = require('express-rate-limit');

var authRoutes = require('./routes/auth');
var eventsRoutes = require('./routes/events');
var bookingsRoutes = require('./routes/bookings');
var paymentsRoutes = require('./routes/payments');
var devicesRoutes = require('./routes/devices');
var adminRoutes = require('./routes/admin');
var adminExportsRoutes = require('./routes/admin-exports');
var bannersRoutes = require('./routes/banners');
var favoritesRoutes = require('./routes/favorites');
var feedbackRoutes = require('./routes/feedback');
var referralsRoutes = require('./routes/referrals');
var followsRoutes = require('./routes/follows');
var reviewsRoutes = require('./routes/reviews');
var waitlistRoutes = require('./routes/waitlist');
var staffRoutes = require('./routes/staff');
var supportRoutes = require('./routes/support');

var app = express();
var PORT = process.env.PORT || 3000;

// Render / Cloudflare ajoutent un proxy devant l'app. Sans ce flag, req.ip
// vaut toujours l'IP du proxy → le rate-limit lumpe tous les users ensemble.
// '1' = on fait confiance à un seul hop de proxy (suffisant pour Render).
app.set('trust proxy', 1);

// Sprint 0 security : headers HTTP + fingerprinting + body limit.
app.disable('x-powered-by');
app.use(helmet({
  // Pas de CSP par défaut — on n'a pas de surface HTML statique (sauf
  // /payment-success qui est inline et /admin/events/:id/invoice). Si on
  // ajoute du HTML server-rendu plus tard, ajouter une CSP ici.
  contentSecurityPolicy: false,
  // crossOriginEmbedderPolicy bloque les iframes inter-origin → désactivé
  // car CinetPay redirige dans une iframe.
  crossOriginEmbedderPolicy: false,
}));
// Body JSON limité à 100 KB. Routes d'upload utilisent Cloudinary direct
// upload (pas de transit par le backend) donc 100KB suffit largement pour
// tout payload "normal" (formulaires, JSON métier).
app.use(express.json({ limit: '100kb' }));

// CORS strict en production. L'app mobile native envoie sans Origin (Expo Go
// natif) → toujours autorisé. Les domaines web sont whitelistés. En dev
// (NODE_ENV != 'production'), on accepte tout pour permettre ngrok/staging.
app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    var allowed = [
      'https://akwaba.ci',
      'https://www.akwaba.ci',
      'https://akwaba-admin.vercel.app',
      'https://admin.akwaba.app',
      'http://localhost:3000',
      'http://localhost:5173',
      'http://localhost:5174',
      'http://localhost:8081',
      'http://localhost:19006',
    ];
    if (allowed.indexOf(origin) !== -1) return callback(null, true);
    // *.netlify.app — couvre la prod Netlify ET les deploy previews automatiques
    // (deploy-preview-N--site.netlify.app, branch-deploy-foo--site.netlify.app).
    // À resserrer plus tard si on configure un domaine custom akwaba.ci sur
    // Netlify, ou si on veut whitelist un seul site Netlify précis.
    if (origin && /\.netlify\.app$/.test(origin)) return callback(null, true);
    // En dev : permissif (ngrok, cloudflared, staging Vercel preview…)
    if (process.env.NODE_ENV !== 'production') {
      console.log('CORS (dev) accepté:', origin);
      return callback(null, true);
    }
    // En prod : reject strict. Loggué dans Sentry via le error handler.
    console.error('CORS bloqué (prod):', origin);
    callback(new Error('CORS: origin non autorisée'));
  },
}));

// Route santé
app.get('/', function(req, res) {
  res.json({
    message: 'Akwaba API fonctionne !',
    version: '2.0.0',
    database: 'PostgreSQL'
  });
});

// Page de retour CinetPay : où les utilisateurs atterrissent après le paiement
// (success ou cancel). HTML simple — l'app mobile ferme cet onglet et fait un
// polling sur /payments/verify. Doit être HTTPS joignable sinon CinetPay refuse
// d'initier le paiement (code 624). À remplacer par un vrai écran web quand
// akwaba.ci sera déployé.
app.get('/payment-success', function(req, res) {
  var transId = req.query.transaction_id || '';
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(
    '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">' +
    '<title>Paiement Akwaba</title>' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<style>body{font-family:system-ui,sans-serif;background:#0E0B08;color:#F4EBDD;' +
    'display:flex;flex-direction:column;align-items:center;justify-content:center;' +
    'min-height:100vh;margin:0;padding:24px;text-align:center}' +
    'h1{color:#D85A2C;font-size:32px;margin:0 0 16px}p{color:rgba(244,235,221,0.65);max-width:480px;line-height:1.5}' +
    'code{background:#161210;padding:6px 10px;border-radius:6px;font-size:12px;color:#E8A33D;display:inline-block;margin-top:12px}</style>' +
    '</head><body>' +
    '<h1>Paiement traité</h1>' +
    '<p>Tu peux fermer cet onglet et retourner dans l\'application Akwaba pour voir ton billet.</p>' +
    (transId ? '<code>Réf : ' + String(transId).replace(/[^A-Za-z0-9.-]/g, '') + '</code>' : '') +
    '</body></html>'
  );
});

// Sprint 0 security : rate-limit sur les endpoints auth (anti SMS-pumping +
// anti brute force OTP). 5 req/min par IP est large pour un user humain
// légitime, restrictif pour un script.
var authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Trop de tentatives, réessaie dans 1 min.' },
});
// Sur /auth — applique à login, register, request-otp, verify-otp.
// Skip pour les GET (rarissime sur /auth mais on évite de bloquer un /auth/me).
app.use('/auth', function(req, res, next) {
  if (req.method !== 'POST') return next();
  return authLimiter(req, res, next);
});

// Routes API
app.use('/auth', authRoutes);
app.use('/events', eventsRoutes);
app.use('/bookings', bookingsRoutes);
app.use('/payments', paymentsRoutes);
app.use('/devices', devicesRoutes);
// /admin/exports DOIT être monté AVANT /admin sinon le router admin grab le path
// et renvoie 404 (il ne définit pas /exports en interne).
app.use('/admin/exports', adminExportsRoutes);
app.use('/admin', adminRoutes);
app.use('/banners', bannersRoutes);
app.use('/favorites', favoritesRoutes);
app.use('/feedback', feedbackRoutes);
app.use('/referrals', referralsRoutes);
app.use('/follows', followsRoutes);
// Reviews : path nested sous /events/:eventId — le router utilise mergeParams: true
// pour acceder a req.params.eventId.
app.use('/events/:eventId/reviews', reviewsRoutes);
app.use('/waitlist', waitlistRoutes);
app.use('/events/:eventId/staff', staffRoutes);
app.use('/support', supportRoutes);

// Sentry error handler — DOIT être après toutes les routes mais avant
// les autres middlewares de gestion d'erreur. Capture toute exception non gérée.
if (process.env.SENTRY_DSN) {
  Sentry.setupExpressErrorHandler(app);
}

// Catch-all error handler (last resort) — affiche une erreur générique au client
// et logue les détails côté serveur. Sentry a déjà capturé l'erreur ci-dessus.
app.use(function(err, req, res, next) {
  console.error('Erreur non gérée:', err.message, err.stack);
  if (res.headersSent) return next(err);
  res.status(500).json({ success: false, message: 'Erreur serveur interne' });
});

// Démarrage du serveur
app.listen(PORT, function() {
  console.log('Akwaba API démarrée sur le port ' + PORT);

  // Worker de réconciliation paiement CinetPay (PAY-03).
  // Tourne en mémoire avec setInterval. Render free tier endort le serveur après 15min,
  // ce qui mettra le worker en pause aussi — le prochain hit HTTP le réveille.
  // Désactivable via DISABLE_RECONCILE=true (utile en dev local sans creds CinetPay).
  if (process.env.DISABLE_RECONCILE !== 'true' && process.env.CINETPAY_API_KEY) {
    var reconcile = require('./jobs/reconcile-payments');
    reconcile.start();
  }

  // Worker d'auto-scheduling payouts (v2-A). Crée automatiquement un payout
  // 'scheduled' pour chaque event terminé + escrow_hours qui n'en a pas.
  // Pas de dépendance aux creds CinetPay — peut tourner en dev. Désactivable
  // via DISABLE_PAYOUT_SCHEDULING=true.
  if (process.env.DISABLE_PAYOUT_SCHEDULING !== 'true') {
    var schedulePayouts = require('./jobs/schedule-payouts');
    schedulePayouts.start();
  }

  // Worker de rappels push J-1 et H-2 (NOTIF-01). Réduit les no-shows en
  // ré-engageant les utilisateurs avant leur événement. Désactivable via
  // DISABLE_EVENT_REMINDERS=true (utile en dev pour éviter de spammer).
  if (process.env.DISABLE_EVENT_REMINDERS !== 'true') {
    var eventReminders = require('./jobs/event-reminders');
    eventReminders.start();
  }

  // Worker du digest quotidien (ADM-DIGEST). Tick toutes les 10 min, envoie
  // le digest à 8h UTC max 1x/jour. RESEND_API_KEY requis pour l'email ;
  // sans la var, le digest est généré et stocké en DB mais email skip.
  if (process.env.DISABLE_ADMIN_DIGEST !== 'true') {
    var adminDigest = require('./jobs/admin-digest');
    adminDigest.start();
  }

  // Worker de rétention RGPD (SEC NEW-4). Tick toutes les 24h pour purger
  // les données expirées : search_queries (90j), digests (180j), audit_log
  // (365j). Désactivable via DISABLE_DATA_RETENTION=true.
  if (process.env.DISABLE_DATA_RETENTION !== 'true') {
    var dataRetention = require('./jobs/data-retention');
    dataRetention.start();
  }
});
