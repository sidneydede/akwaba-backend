// services/sms/hsms.js — Adapter SMS HSMS.CI
// Interface commune multi-provider : { name, isConfigured, sendSms }
//
// Doc API : https://hsms.ci/api/documentation/
// Endpoint envoi : POST https://hsms.ci/api/envoi-sms
// Headers :
//   Authorization: Bearer <token>
//   Content-Type: application/json
// Body JSON :
//   { clientid, clientsecret, telephone, message, unicode? }
//
// Authentification :
//   Token Bearer généré 1 fois via POST /api/token/ (email+password) sur le
//   dashboard HSMS, puis stocké en env var HSMS_TOKEN. Si HSMS impose un TTL
//   et que le token expire, l'envoi renverra 401 — il faudra le regénérer.
//
// Format phone : indicatif pays SANS le `+` initial (ex: 2250700000001).
// Sender ID : configuré côté dashboard HSMS sur l'application (clientid/secret),
//   pas dans le payload de chaque envoi.

var HSMS_TOKEN = process.env.HSMS_TOKEN;
var HSMS_CLIENTID = process.env.HSMS_CLIENTID;
var HSMS_CLIENTSECRET = process.env.HSMS_CLIENTSECRET;
var HSMS_BASE_URL = process.env.HSMS_BASE_URL || 'https://hsms.ci';

// Indique si le provider est prêt à envoyer un vrai SMS (les 3 secrets requis)
// @returns {boolean}
function isConfigured() {
  return Boolean(HSMS_TOKEN && HSMS_CLIENTID && HSMS_CLIENTSECRET);
}

// Envoie un SMS via HSMS.CI
// @param {string} phoneE164 - Numéro au format +225XXXXXXXXXX (avec +)
// @param {string} message - Texte du SMS
// @returns {Promise<{success: boolean, error?: any}>}
function sendSms(phoneE164, message) {
  // HSMS veut le numéro sans le `+` initial (ex: 2250700000001)
  var telephone = phoneE164.replace(/^\+/, '');

  var payload = {
    clientid: HSMS_CLIENTID,
    clientsecret: HSMS_CLIENTSECRET,
    telephone: telephone,
    message: message,
    unicode: false
  };

  return fetch(HSMS_BASE_URL + '/api/envoi-sms', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + HSMS_TOKEN
    },
    body: JSON.stringify(payload)
  })
    .then(function(res) {
      return res.json().then(function(data) {
        return { status: res.status, data: data };
      }).catch(function() {
        return { status: res.status, data: null };
      });
    })
    .then(function(result) {
      console.log('[SMS][hsms] Réponse :', result.status, JSON.stringify(result.data));
      // Succès : HTTP 201 + { success: true, message: 'OK', data: {...} }
      if ((result.status === 201 || result.status === 200) &&
          result.data && result.data.success === true) {
        return { success: true };
      }
      // Échec : message d'erreur dans data.message ou data.errors
      return { success: false, error: result.data || ('HTTP ' + result.status) };
    })
    .catch(function(err) {
      console.error('[SMS][hsms] Erreur envoi :', err.message);
      return { success: false, error: err.message };
    });
}

module.exports = {
  name: 'hsms',
  isConfigured: isConfigured,
  sendSms: sendSms
};
