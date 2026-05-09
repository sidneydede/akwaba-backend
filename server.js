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

var authRoutes = require('./routes/auth');
var eventsRoutes = require('./routes/events');
var bookingsRoutes = require('./routes/bookings');
var paymentsRoutes = require('./routes/payments');
var devicesRoutes = require('./routes/devices');
var adminRoutes = require('./routes/admin');
var bannersRoutes = require('./routes/banners');

var app = express();
var PORT = process.env.PORT || 3000;

// Middlewares
// CORS : autorise l'app mobile (origin null sur Expo Go natif) + le site commercial
// + la webapp orga. En dev on accepte aussi les ports Vite (5173/5174) et Expo web.
app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    var allowed = [
      'https://akwaba.ci',
      'https://www.akwaba.ci',
      'http://localhost:5173',
      'http://localhost:5174',
      'http://localhost:8081',
      'http://localhost:19006'
    ];
    if (allowed.indexOf(origin) !== -1) return callback(null, true);
    // Tunnel ngrok/cloudflared utile pour tester scan QR mobile : on log et on accepte.
    console.log('CORS origin non whitelistée mais acceptée:', origin);
    callback(null, true);
  }
}));
app.use(express.json());

// Route santé
app.get('/', function(req, res) {
  res.json({
    message: 'Akwaba API fonctionne !',
    version: '2.0.0',
    database: 'PostgreSQL'
  });
});

// Routes API
app.use('/auth', authRoutes);
app.use('/events', eventsRoutes);
app.use('/bookings', bookingsRoutes);
app.use('/payments', paymentsRoutes);
app.use('/devices', devicesRoutes);
app.use('/admin', adminRoutes);
app.use('/banners', bannersRoutes);

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
});
