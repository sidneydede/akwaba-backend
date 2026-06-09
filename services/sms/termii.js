// services/sms/termii.js — Adapter SMS Termii
// Interface commune multi-provider : { name, isConfigured, sendSms }
//
// Doc API : https://developer.termii.com/docs/send-message
// Endpoint : POST https://api.ng.termii.com/api/sms/send
// Body JSON :
//   { to, from, sms, type: 'plain', channel: 'dnd'|'generic', api_key }
//
// Channel :
//   - 'dnd' = transactional (OTP, alertes) → route directe, prioritaire, ignore
//     les listes Do-Not-Disturb. À utiliser pour les OTP.
//   - 'generic' = promotional → moins cher mais peut être filtré.
//
// Sender ID : doit être pré-approuvé par Termii (3-5j en moyenne pour la CI).
// Format phone : E.164 sans le `+` initial (ex: 225XXXXXXXXXX).

var TERMII_API_KEY = process.env.TERMII_API_KEY;
var TERMII_SENDER_ID = process.env.TERMII_SENDER_ID || 'EVENTND';
var TERMII_CHANNEL = process.env.TERMII_CHANNEL || 'dnd';
var TERMII_BASE_URL = process.env.TERMII_BASE_URL || 'https://api.ng.termii.com';

// Indique si le provider est prêt à envoyer un vrai SMS
// @returns {boolean}
function isConfigured() {
  return Boolean(TERMII_API_KEY);
}

// Envoie un SMS via Termii
// @param {string} phoneE164 - Numéro au format +225XXXXXXXXXX (avec +)
// @param {string} message - Texte du SMS
// @returns {Promise<{success: boolean, error?: any}>}
function sendSms(phoneE164, message) {
  // Termii veut le numéro sans le `+` initial
  var to = phoneE164.replace(/^\+/, '');

  var payload = {
    to: to,
    from: TERMII_SENDER_ID,
    sms: message,
    type: 'plain',
    channel: TERMII_CHANNEL,
    api_key: TERMII_API_KEY
  };

  return fetch(TERMII_BASE_URL + '/api/sms/send', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  })
    .then(function(res) {
      return res.json().then(function(data) {
        return { status: res.status, data: data };
      });
    })
    .then(function(result) {
      console.log('[SMS][termii] Réponse :', JSON.stringify(result.data));
      // Succès : Termii renvoie message_id + "message: Successfully Sent"
      // + balance restant. HTTP 200.
      if (result.status === 200 && result.data && result.data.message_id) {
        return { success: true };
      }
      // Échec : message d'erreur dans data.message ou data.code
      return { success: false, error: result.data };
    })
    .catch(function(err) {
      console.error('[SMS][termii] Erreur envoi :', err.message);
      return { success: false, error: err.message };
    });
}

module.exports = {
  name: 'termii',
  isConfigured: isConfigured,
  sendSms: sendSms
};
