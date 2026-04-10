// services/sms.js — Envoi de SMS via Africa's Talking
// Mode production : utilise l'API Africa's Talking si AT_USERNAME + AT_API_KEY définis
// Mode dev : log l'OTP dans la console (visible dans Render Logs)

var AT_USERNAME = process.env.AT_USERNAME;
var AT_API_KEY = process.env.AT_API_KEY;
var AT_SENDER_ID = process.env.AT_SENDER_ID || 'AKWABA';

// URL sandbox vs production
// Sandbox = tests gratuits (username doit être 'sandbox')
// Production = vrais SMS payants
var AT_URL = AT_USERNAME === 'sandbox'
  ? 'https://api.sandbox.africastalking.com/version1/messaging'
  : 'https://api.africastalking.com/version1/messaging';

// Détecte si le mode SMS réel est actif
// @returns {boolean}
function isRealSmsEnabled() {
  return Boolean(AT_USERNAME && AT_API_KEY);
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

// Envoie un code OTP par SMS
// @param {string} phone - Numéro destinataire
// @param {string} code - Code OTP à 6 chiffres
// @returns {Promise<object>} { success: boolean, dev?: boolean }
function sendOtp(phone, code) {
  var normalized = normalizePhone(phone);
  var message = 'Akwaba : votre code de verification est ' + code + '. Valable 10 minutes.';

  // Mode dev : log dans la console et retourne success
  if (!isRealSmsEnabled()) {
    console.log('[SMS DEV] OTP pour ' + normalized + ' : ' + code);
    return Promise.resolve({ success: true, dev: true });
  }

  // Mode prod : appel HTTP à Africa's Talking
  // ⚠️ En sandbox, ne PAS envoyer le paramètre `from` : les sender IDs
  // personnalisés ne sont pas autorisés en sandbox et le SMS est rejeté.
  // En production, on utilise AT_SENDER_ID (doit être pré-approuvé par AT).
  var isSandbox = AT_USERNAME === 'sandbox';
  var formBody = 'username=' + encodeURIComponent(AT_USERNAME) +
    '&to=' + encodeURIComponent(normalized) +
    '&message=' + encodeURIComponent(message);
  if (!isSandbox) {
    formBody += '&from=' + encodeURIComponent(AT_SENDER_ID);
  }

  return fetch(AT_URL, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      'apiKey': AT_API_KEY
    },
    body: formBody
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      console.log('[SMS] Réponse Africa\'s Talking :', JSON.stringify(data));
      var recipients = data && data.SMSMessageData && data.SMSMessageData.Recipients;
      if (recipients && recipients.length > 0 && recipients[0].status === 'Success') {
        return { success: true };
      }
      return { success: false, error: data };
    })
    .catch(function(err) {
      console.error('[SMS] Erreur envoi :', err.message);
      return { success: false, error: err.message };
    });
}

module.exports = {
  sendOtp: sendOtp,
  isRealSmsEnabled: isRealSmsEnabled,
  normalizePhone: normalizePhone
};
