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

// Envoie une notification push à un segment d'utilisateurs (broadcast).
// Segments supportés :
//   - 'all'     : tous les users avec un token actif
//   - 'role'    : segmentValue = 'participant' | 'organisateur'
// Retourne { recipients_count, sent_count, failed_count }.
// Batch par chunks de 100 (limite Expo).
// @param {string} segment
// @param {string|null} segmentValue
// @param {{title: string, body: string, data?: object}} payload
// @returns {Promise<{recipients_count:number, sent_count:number, failed_count:number}>}
function notifySegment(segment, segmentValue, payload) {
  var sql = 'SELECT DISTINCT dt.token FROM device_tokens dt JOIN users u ON u.id = dt.user_id';
  var clauses = [];
  var params = [];
  if (segment === 'role') {
    if (!segmentValue) return Promise.resolve({ recipients_count: 0, sent_count: 0, failed_count: 0 });
    params.push(segmentValue);
    clauses.push('u.role = $' + params.length);
  }
  // Exclut les comptes suspendus.
  clauses.push('u.suspended_at IS NULL');
  if (clauses.length > 0) sql += ' WHERE ' + clauses.join(' AND ');

  return pool.query(sql, params).then(function(result) {
    var tokens = result.rows.map(function(r) { return r.token; });
    if (tokens.length === 0) {
      return { recipients_count: 0, sent_count: 0, failed_count: 0 };
    }

    // Batch par 100 (limite Expo)
    var batches = [];
    for (var i = 0; i < tokens.length; i += 100) {
      batches.push(tokens.slice(i, i + 100));
    }

    return batches.reduce(function(acc, batch) {
      return acc.then(function(stats) {
        var messages = batch.map(function(token) {
          return {
            to: token,
            sound: 'default',
            title: payload.title,
            body: payload.body,
            data: payload.data || {},
          };
        });
        return sendExpoPush(messages).then(function(results) {
          var sent = results.filter(function(r) { return r.status === 'ok'; }).length;
          var failed = results.length - sent;
          return {
            recipients_count: stats.recipients_count + batch.length,
            sent_count: stats.sent_count + sent,
            failed_count: stats.failed_count + failed,
          };
        });
      });
    }, Promise.resolve({ recipients_count: 0, sent_count: 0, failed_count: 0 }));
  });
}

module.exports = {
  sendExpoPush: sendExpoPush,
  getTokensForUser: getTokensForUser,
  notifyUser: notifyUser,
  notifySegment: notifySegment,
};
