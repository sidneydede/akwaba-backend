// services/userAudit.js — Trace les actions sensibles côté participant.
// Fire-and-forget : un échec d'audit log ne doit jamais casser l'action
// métier en cours. Le log sert pour incident response + transparence RGPD
// (visible via GET /auth/me/activity).

var pool = require('../db/pool');

// Liste des actions normalisées. Les rajouts doivent rester courts (≤40 chars).
var ACTIONS = {
  LOGIN: 'login',                       // OTP validé avec succès
  LOGOUT: 'logout',                     // Déconnexion explicite
  REGISTER: 'register',                 // Création de compte
  OTP_FAIL: 'otp_fail',                 // Tentative OTP incorrecte
  PROFILE_UPDATE: 'profile_update',     // PATCH /auth/me (nom, ville, photo…)
  PREFERENCES_UPDATE: 'preferences_update',
  BOOKING_CREATE: 'booking_create',
  BOOKING_CANCEL: 'booking_cancel',
  REFERRAL_REDEEM: 'referral_redeem',
  DEVICE_REGISTER: 'device_register',
  DEVICE_UNREGISTER: 'device_unregister',
  SUPPORT_TICKET_CREATE: 'support_ticket_create',
};

// Extrait l'IP cliente derrière le proxy Render/Cloudflare. trust proxy = 1
// dans server.js → req.ip fonctionne. Fallback sur les headers si besoin.
function clientIp(req) {
  return req.ip
    || req.headers['cf-connecting-ip']
    || req.headers['x-forwarded-for']
    || req.headers['x-real-ip']
    || null;
}

function clientUserAgent(req) {
  return (req.headers['user-agent'] || '').slice(0, 300);
}

// Logue une action. Fire-and-forget (catch silent).
// @param {number} userId
// @param {string} action - une des constantes ACTIONS ou string libre
// @param {object} req - Express request (pour ip + user_agent)
// @param {object} [metadata] - JSON libre (target ids, ancien/nouveau valeur)
function log(userId, action, req, metadata) {
  if (!userId || !action) return;
  pool.query(
    'INSERT INTO user_audit_log (user_id, action, ip, user_agent, metadata) ' +
    'VALUES ($1, $2, $3, $4, $5)',
    [
      userId,
      String(action).slice(0, 40),
      clientIp(req),
      clientUserAgent(req),
      metadata ? JSON.stringify(metadata) : null,
    ]
  ).catch(function(err) {
    console.error('Erreur userAudit.log:', err.message);
  });
}

module.exports = { log: log, ACTIONS: ACTIONS };
