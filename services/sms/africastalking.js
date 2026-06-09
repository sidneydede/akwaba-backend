// services/sms/africastalking.js — Adapter SMS Africa's Talking
// Interface commune multi-provider : { name, isConfigured, sendSms }
// Le sender ID alphanumérique doit être pré-approuvé par AT (revue 1-7j).
// En sandbox (AT_USERNAME='sandbox'), le sender ID est ignoré (sinon SMS rejeté).

var AT_USERNAME = process.env.AT_USERNAME;
var AT_API_KEY = process.env.AT_API_KEY;
var AT_SENDER_ID = process.env.AT_SENDER_ID || 'EVENTND';

var AT_URL = AT_USERNAME === 'sandbox'
  ? 'https://api.sandbox.africastalking.com/version1/messaging'
  : 'https://api.africastalking.com/version1/messaging';

// Indique si le provider est prêt à envoyer un vrai SMS (credentials présents)
// @returns {boolean}
function isConfigured() {
  return Boolean(AT_USERNAME && AT_API_KEY);
}

// Envoie un SMS via Africa's Talking
// @param {string} phoneE164 - Numéro au format +225XXXXXXXXXX (avec +)
// @param {string} message - Texte du SMS
// @returns {Promise<{success: boolean, error?: any}>}
function sendSms(phoneE164, message) {
  // AT accepte le format +225XXXXXXXXXX tel quel
  var isSandbox = AT_USERNAME === 'sandbox';
  var formBody = 'username=' + encodeURIComponent(AT_USERNAME) +
    '&to=' + encodeURIComponent(phoneE164) +
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
      console.log('[SMS][africastalking] Réponse :', JSON.stringify(data));
      var recipients = data && data.SMSMessageData && data.SMSMessageData.Recipients;
      if (recipients && recipients.length > 0 && recipients[0].status === 'Success') {
        return { success: true };
      }
      return { success: false, error: data };
    })
    .catch(function(err) {
      console.error('[SMS][africastalking] Erreur envoi :', err.message);
      return { success: false, error: err.message };
    });
}

module.exports = {
  name: 'africastalking',
  isConfigured: isConfigured,
  sendSms: sendSms
};
