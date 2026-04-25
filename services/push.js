// services/push.js — Envoi de notifications push via Expo Push API
// Doc: https://docs.expo.dev/push-notifications/sending-notifications/
// Endpoint: https://exp.host/--/api/v2/push/send (HTTP, pas besoin d'auth)
// Node >=18 fournit `fetch` en global, donc pas de dépendance supplémentaire.

var pool = require('../db/pool');

var EXPO_PUSH_URL = 'https://exp.host/--/api/v2/push/send';

// Envoie un batch de notifications à l'API Expo.
// Filtre les tokens invalides (doivent commencer par ExponentPushToken[ ou ExpoPushToken[).
// @param {Array<{to: string, title: string, body: string, data?: object}>} messages
// @returns {Promise<Array>} Résultats par message (cf. format Expo)
function sendExpoPush(messages) {
  var valid = messages.filter(function(m) {
    return m && typeof m.to === 'string'
      && (m.to.indexOf('ExponentPushToken[') === 0 || m.to.indexOf('ExpoPushToken[') === 0);
  });
  if (valid.length === 0) return Promise.resolve([]);

  return fetch(EXPO_PUSH_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Accept-Encoding': 'gzip, deflate'
    },
    body: JSON.stringify(valid)
  })
    .then(function(res) { return res.json(); })
    .then(function(json) {
      // Format: { data: [...] } en cas de succès, { errors: [...] } sinon
      if (json && json.errors) {
        console.error('Expo push errors:', JSON.stringify(json.errors));
      }
      return (json && json.data) || [];
    })
    .catch(function(err) {
      console.error('Erreur sendExpoPush:', err.message);
      return [];
    });
}

// Récupère tous les tokens push d'un utilisateur.
// @param {number} userId
// @returns {Promise<Array<string>>}
function getTokensForUser(userId) {
  return pool.query('SELECT token FROM device_tokens WHERE user_id = $1', [userId])
    .then(function(result) {
      return result.rows.map(function(r) { return r.token; });
    })
    .catch(function(err) {
      console.error('Erreur getTokensForUser:', err.message);
      return [];
    });
}

// Envoie une notification à tous les devices d'un utilisateur.
// Ne bloque jamais : log les erreurs et retourne sans throw.
// @param {number} userId
// @param {{title: string, body: string, data?: object}} payload
// @returns {Promise<void>}
function notifyUser(userId, payload) {
  return getTokensForUser(userId).then(function(tokens) {
    if (tokens.length === 0) return;
    var messages = tokens.map(function(token) {
      return {
        to: token,
        sound: 'default',
        title: payload.title,
        body: payload.body,
        data: payload.data || {}
      };
    });
    return sendExpoPush(messages);
  });
}

module.exports = {
  sendExpoPush: sendExpoPush,
  getTokensForUser: getTokensForUser,
  notifyUser: notifyUser
};
