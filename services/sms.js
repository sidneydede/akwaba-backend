// services/sms.js — Façade SMS multi-provider
//
// Sélectionne dynamiquement le provider SMS via SMS_PROVIDER :
//   - 'hsms'           → services/sms/hsms.js          (préféré, local CI)
//   - 'termii'         → services/sms/termii.js
//   - 'africastalking' → services/sms/africastalking.js
//   - non défini       → auto-détection (premier provider configuré),
//                        sinon mode dev (log de l'OTP).
//
// API publique préservée pour les consommateurs (routes/auth.js) :
//   sendOtp(phone, code)  → { success, dev?, error? }
//   isRealSmsEnabled()    → boolean
//   normalizePhone(phone) → string E.164 +225XXXXXXXXXX
//
// Pour ajouter un nouveau provider :
//   1. Créer services/sms/<name>.js qui exporte { name, isConfigured, sendSms }
//   2. Ajouter une entrée dans PROVIDERS ci-dessous
//   3. C'est tout (la façade gère le reste)

var africastalking = require('./sms/africastalking');
var termii = require('./sms/termii');
var hsms = require('./sms/hsms');

var PROVIDERS = {
  africastalking: africastalking,
  termii: termii,
  hsms: hsms
};

// Ordre d'auto-détection si SMS_PROVIDER n'est pas défini.
// HSMS en premier (provider local CI, paiement MoMo, sender ID local),
// puis Termii (fallback), puis Africa's Talking (legacy).
var AUTO_ORDER = ['hsms', 'termii', 'africastalking'];

// Sélectionne le provider actif au boot. Re-calculé à chaque appel sendOtp
// pour rester réactif à un changement d'env var en runtime (utile en dev).
// @returns {object|null} L'adapter actif, ou null si aucun configuré
function pickProvider() {
  var name = (process.env.SMS_PROVIDER || '').toLowerCase().trim();

  // Cas 1 : SMS_PROVIDER explicite
  if (name && PROVIDERS[name]) {
    if (PROVIDERS[name].isConfigured()) {
      return PROVIDERS[name];
    }
    // Provider explicitement choisi mais mal configuré → on le retourne quand
    // même pour que le log soit clair (au lieu de fallback silencieux).
    console.warn('[SMS] Provider "' + name + '" sélectionné mais credentials manquants.');
    return null;
  }

  // Cas 2 : auto-détection — premier provider configuré gagne
  for (var i = 0; i < AUTO_ORDER.length; i++) {
    var p = PROVIDERS[AUTO_ORDER[i]];
    if (p && p.isConfigured()) {
      return p;
    }
  }

  return null;
}

// Indique si un provider réel est actif (sinon mode dev = log OTP)
// @returns {boolean}
function isRealSmsEnabled() {
  return pickProvider() !== null;
}

// Normalise un numéro ivoirien au format international +225XXXXXXXXXX
// ⚠️ Depuis 2021, les numéros ivoiriens font 10 chiffres et le 0 initial
// fait partie du numéro (ne pas le supprimer). Format final : +225 + 10 chiffres.
// @param {string} phone - Numéro local (ex: 0700000000) ou international
// @returns {string} Numéro au format +225XXXXXXXXXX (13 caractères au total)
function normalizePhone(phone) {
  var clean = phone.replace(/\s/g, '').replace(/^\+/, '');
  if (clean.startsWith('225')) return '+' + clean;
  return '+225' + clean;
}

// Envoie un code OTP par SMS via le provider actif
// @param {string} phone - Numéro destinataire
// @param {string} code - Code OTP à 6 chiffres
// @returns {Promise<{success: boolean, dev?: boolean, error?: any}>}
function sendOtp(phone, code) {
  var normalized = normalizePhone(phone);
  var message = 'EventNextDoor : votre code de verification est ' + code + '. Valable 10 minutes.';

  var provider = pickProvider();

  // Mode dev : aucun provider configuré → log dans la console.
  // SEC H3 : SAUF en prod. Si aucun provider SMS n'est résolu en production
  // (var d'env manquante/mal nommée, solde épuisé), le mode dev mettrait le
  // code OTP en clair dans la réponse HTTP (dev_otp) → prise de contrôle de
  // n'importe quel compte. On refuse explicitement (parité avec email.js).
  if (!provider) {
    if (process.env.NODE_ENV === 'production') {
      console.error('[SMS] Aucun provider SMS configuré en prod — refus envoi pour ' + normalized);
      return Promise.resolve({ success: false, error: 'SMS_NOT_CONFIGURED' });
    }
    console.log('[SMS DEV] OTP pour ' + normalized + ' : ' + code);
    return Promise.resolve({ success: true, dev: true });
  }

  console.log('[SMS] Envoi via ' + provider.name + ' → ' + normalized);
  return provider.sendSms(normalized, message);
}

module.exports = {
  sendOtp: sendOtp,
  isRealSmsEnabled: isRealSmsEnabled,
  normalizePhone: normalizePhone
};
