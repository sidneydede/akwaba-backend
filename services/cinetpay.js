// services/cinetpay.js — Helpers de vérification CinetPay
// Deux couches de défense contre la falsification de webhook :
//   1. Vérification HMAC du header x-token (rapide, rejette les appels triviaux)
//   2. Double-check via l'API CinetPay /v2/payment/check (authoritative, infalsifiable)

var crypto = require('crypto');

var CINETPAY_API_KEY = process.env.CINETPAY_API_KEY;
var CINETPAY_SITE_ID = process.env.CINETPAY_SITE_ID;
var CINETPAY_SECRET_KEY = process.env.CINETPAY_SECRET_KEY;

// Sprint 0 security : fail-fast si SECRET_KEY absente en prod. Sinon le
// verifyHmacToken renvoyait true (fail-OPEN) — un attaquant pouvait forger
// des webhooks tant que le double-check API était down.
if (process.env.NODE_ENV === 'production' && !CINETPAY_SECRET_KEY) {
  throw new Error(
    'CINETPAY_SECRET_KEY manquante en production. Configure la var sur Render avant de démarrer.'
  );
}
var CINETPAY_INIT_URL = 'https://api-checkout.cinetpay.com/v2/payment';
var CINETPAY_CHECK_URL = 'https://api-checkout.cinetpay.com/v2/payment/check';
// URL de base de l'API backend (utilisée pour notify_url envoyée à CinetPay)
var BACKEND_URL = process.env.BACKEND_URL || 'https://akwaba-backend.onrender.com';
var FRONT_RETURN_URL = process.env.FRONT_RETURN_URL || 'https://akwaba.ci/billet-confirme';

// Transfer API (produit séparé CinetPay, auth distincte).
// Activable via CINETPAY_TRANSFER_ENABLED=true ; sinon transferPayout retourne 'manual_required'.
var CINETPAY_TRANSFER_ENABLED = process.env.CINETPAY_TRANSFER_ENABLED === 'true';
var CINETPAY_TRANSFER_LOGIN = process.env.CINETPAY_TRANSFER_LOGIN;
var CINETPAY_TRANSFER_PASSWORD = process.env.CINETPAY_TRANSFER_PASSWORD;
var CINETPAY_TRANSFER_AUTH_URL = 'https://client.cinetpay.com/v1/auth/login';
var CINETPAY_TRANSFER_SEND_URL = 'https://client.cinetpay.com/v1/transfer/money/send/contact';

// Token Transfer API en cache mémoire (TTL 23h pour rester sûr — CinetPay donne 24h).
var transferTokenCache = { token: null, expiresAt: 0 };

// Vérifie le HMAC-SHA256 du header x-token envoyé par CinetPay.
// L'algo CinetPay : SHA256(secretKey, concat(champs ordonnés)).
// Retourne true si le token correspond, false sinon. Si SECRET_KEY n'est pas configurée,
// retourne true (skip — on s'appuie sur le double-check API qui est obligatoire).
// @param {object} body - req.body du webhook
// @param {string} token - valeur du header x-token
// @returns {boolean}
function verifyHmacToken(body, token) {
  // Fail-CLOSED : si pas de secret, on REFUSE le webhook (le boot a déjà
  // refusé de démarrer en prod sans la var, donc on ne devrait jamais
  // tomber ici en prod. En dev, ça force à configurer la var localement).
  if (!CINETPAY_SECRET_KEY) {
    console.error('CINETPAY_SECRET_KEY absent — webhook REJECTED (fail-closed)');
    return false;
  }
  if (!token) return false;

  // Ordre officiel des champs concaténés pour calculer le token CinetPay v2.
  // Source : https://docs.cinetpay.com/api/1.0-en/checkout/notification
  var fields = [
    'cpm_site_id', 'cpm_trans_id', 'cpm_trans_date', 'cpm_amount', 'cpm_currency',
    'signature', 'payment_method', 'cel_phone_num', 'cpm_phone_prefixe',
    'cpm_language', 'cpm_version', 'cpm_payment_config', 'cpm_page_action',
    'cpm_custom', 'cpm_designation', 'cpm_error_message'
  ];
  var data = fields.map(function(f) { return body[f] || ''; }).join('');

  var expected = crypto.createHmac('sha256', CINETPAY_SECRET_KEY).update(data).digest('hex');

  // Comparaison timing-safe pour éviter les timing attacks.
  if (expected.length !== token.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(token, 'hex'));
  } catch (e) {
    return false;
  }
}

// Interroge l'API CinetPay pour vérifier le statut réel d'une transaction.
// C'est la défense ultime : même si le webhook est falsifié, on confirme directement
// auprès de CinetPay avec notre apikey privée. Sans paiement réel, l'API renverra "NOT_FOUND".
// @param {string} transactionId
// @returns {Promise<{ok: boolean, status: string, amount?: number, raw: object}>}
function verifyTransactionWithApi(transactionId) {
  if (!CINETPAY_API_KEY || !CINETPAY_SITE_ID) {
    return Promise.reject(new Error('CINETPAY_API_KEY ou CINETPAY_SITE_ID manquant'));
  }

  return fetch(CINETPAY_CHECK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      apikey: CINETPAY_API_KEY,
      site_id: CINETPAY_SITE_ID,
      transaction_id: transactionId,
    }),
  })
    .then(function(res) { return res.json(); })
    .then(function(json) {
      // Format CinetPay : { code: "00" (success) | "601" (not found) | ..., message, data: { status, amount, ... } }
      var data = json.data || {};
      var status = data.status || 'UNKNOWN';
      var amount = data.amount ? parseInt(data.amount) : null;
      // CinetPay renvoie status='ACCEPTED' pour un paiement validé.
      var ok = json.code === '00' && status === 'ACCEPTED';
      return { ok: ok, status: status, amount: amount, raw: json };
    });
}

// Normalise un numéro vers le format international E.164 attendu par CinetPay.
// IMPORTANT : en Côte d'Ivoire, le 0 initial fait partie du numéro local
// (format 10 chiffres depuis 2021), donc on NE STRIPPE PAS le 0 quand on
// préfixe +225. Numéro local "0787906706" → international "+2250787906706".
// CinetPay code 624 vient souvent d'un numéro mal formé qu'ils n'arrivent
// pas à valider auprès des opérateurs mobile money.
function normalizePhone(phone) {
  if (!phone) return '';
  var s = String(phone).trim().replace(/\s/g, '');
  if (s.startsWith('+225')) return s;
  if (s.startsWith('225')) return '+' + s;
  if (s.startsWith('+')) return s;
  // Format local CI 10 chiffres (commence par 0) : on préfixe +225 sans stripper le 0.
  if (s.startsWith('0')) return '+225' + s;
  // 9 chiffres sans 0 (ancien format ou saisie partielle) : on préfixe +2250.
  return '+225' + s;
}

// Initie un paiement CinetPay et retourne l'URL de la page de paiement.
// On utilise la ref booking comme transaction_id : c'est unique, traçable, et nous évite
// d'avoir à mapper transaction_id → booking_id côté webhook.
// @param {object} params
//   - ref: string (ex: 'AKW-A1B2C3D4')   — sert de transaction_id CinetPay
//   - amount: number (FCFA, entier)
//   - description: string                 — apparaît sur la page paiement
//   - customer: { id, name, surname, phone, email? }
//   - channels: 'ALL' | 'MOBILE_MONEY' | 'CREDIT_CARD' (défaut 'ALL')
// @returns {Promise<{ok: boolean, payment_url?: string, payment_token?: string, raw: object}>}
function initPayment(params) {
  if (!CINETPAY_API_KEY || !CINETPAY_SITE_ID) {
    return Promise.reject(new Error('CINETPAY_API_KEY ou CINETPAY_SITE_ID manquant'));
  }

  // site_id doit être un entier (les exemples officiels CinetPay le passent en number).
  var siteId = parseInt(CINETPAY_SITE_ID, 10);
  if (isNaN(siteId)) {
    return Promise.reject(new Error('CINETPAY_SITE_ID doit être un entier numérique'));
  }

  var body = {
    apikey: CINETPAY_API_KEY,
    site_id: siteId,
    transaction_id: params.ref,
    amount: parseInt(params.amount, 10),
    currency: 'XOF',
    description: params.description || 'Billet Akwaba',
    customer_id: String(params.customer.id),
    customer_name: params.customer.name || 'Akwaba',
    customer_surname: params.customer.surname || 'Client',
    customer_phone_number: normalizePhone(params.customer.phone),
    customer_email: params.customer.email || 'client@akwaba.ci',
    customer_address: 'Abidjan',
    customer_city: 'Abidjan',
    customer_country: 'CI',
    customer_state: 'CI',
    customer_zip_code: '00225',
    notify_url: BACKEND_URL + '/payments/notify',
    return_url: FRONT_RETURN_URL,
    channels: params.channels || 'ALL',
    lang: 'fr',
  };

  return fetch(CINETPAY_INIT_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
    .then(function(res) { return res.json(); })
    .then(function(json) {
      var data = json.data || {};
      var ok = json.code === '201' && data.payment_url;
      // Log détaillé en cas d'échec — sans ça on n'a aucune visibilité sur ce
      // que CinetPay reproche (code générique 624 / UNKNOWN_ERROR fréquent).
      if (!ok) {
        console.error('[cinetpay] init refusé. Payload envoyé :', JSON.stringify({
          ref: body.transaction_id,
          amount: body.amount,
          phone: body.customer_phone_number,
          email: body.customer_email,
          notify_url: body.notify_url,
          return_url: body.return_url,
          channels: body.channels,
        }));
        console.error('[cinetpay] réponse :', JSON.stringify(json));
      }
      return {
        ok: ok,
        payment_url: data.payment_url,
        payment_token: data.payment_token,
        raw: json,
      };
    });
}

// ============================================================
// Transfer API (B2C payout vers mobile money / banque)
// ============================================================

// Récupère un token Transfer API frais (cache 23h).
// CinetPay Transfer auth = apikey + login + password (distinct du Checkout).
// @returns {Promise<string>} token
function getTransferToken() {
  if (transferTokenCache.token && transferTokenCache.expiresAt > Date.now()) {
    return Promise.resolve(transferTokenCache.token);
  }
  if (!CINETPAY_API_KEY || !CINETPAY_TRANSFER_LOGIN || !CINETPAY_TRANSFER_PASSWORD) {
    return Promise.reject(new Error(
      'CinetPay Transfer non configuré (CINETPAY_API_KEY, CINETPAY_TRANSFER_LOGIN, CINETPAY_TRANSFER_PASSWORD requis)'
    ));
  }

  var form = new URLSearchParams();
  form.append('apikey', CINETPAY_API_KEY);
  form.append('login', CINETPAY_TRANSFER_LOGIN);
  form.append('password', CINETPAY_TRANSFER_PASSWORD);

  return fetch(CINETPAY_TRANSFER_AUTH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  })
    .then(function(res) { return res.json(); })
    .then(function(json) {
      if (json.code !== 0 || !json.data || !json.data.token) {
        throw new Error('Login Transfer CinetPay échoué: ' + (json.message || 'unknown'));
      }
      transferTokenCache.token = json.data.token;
      transferTokenCache.expiresAt = Date.now() + 23 * 3600 * 1000;
      return json.data.token;
    });
}

// Mappe nos providers internes vers les codes CinetPay Transfer.
// CinetPay attend prefix + phone (ex: prefix="225", phone="0102030405").
function parseProvider(provider) {
  // Tous les mobile money CI passent par prefix '225'. Pour banque on a un autre flow.
  if (provider === 'orange_money') return 'OMCIV2';
  if (provider === 'mtn_momo') return 'FLOOZ';
  if (provider === 'wave') return 'WAVE';
  if (provider === 'moov') return 'FLOOZ';
  return null;
}

// Initie un transfer mobile money via CinetPay Transfer.
// @param {object} params
//   - amount: number (FCFA, entier)
//   - account: { provider, number, name }
//   - reference: string (notre payout id, sert d'identifiant unique côté CinetPay)
// @returns {Promise<{ok: boolean, status: string, transfer_reference?: string, raw: object}>}
function transferPayout(params) {
  if (!CINETPAY_TRANSFER_ENABLED) {
    // Mode manuel : on ne fait rien, l'admin valide via back-office CinetPay.
    return Promise.resolve({
      ok: false,
      status: 'manual_required',
      raw: { message: 'CinetPay Transfer non activé (CINETPAY_TRANSFER_ENABLED=false). Reversement manuel requis.' },
    });
  }

  var providerCode = parseProvider(params.account.provider);
  if (!providerCode) {
    return Promise.resolve({
      ok: false,
      status: 'unsupported_provider',
      raw: { message: 'Provider ' + params.account.provider + ' non supporté par CinetPay Transfer' },
    });
  }

  // Numéro au format E.164 attendu par CinetPay : prefix=225, phone sans le 0 de tête.
  var phone = String(params.account.number).replace(/^\+225/, '').replace(/^225/, '').replace(/^0/, '');

  // Split nom complet en first/last (CinetPay attend les deux).
  var nameParts = (params.account.name || '').trim().split(/\s+/);
  var firstName = nameParts[0] || 'Client';
  var lastName = nameParts.slice(1).join(' ') || 'Akwaba';

  return getTransferToken().then(function(token) {
    var body = [{
      prefix: '225',
      phone: phone,
      amount: String(params.amount),
      client_transaction_id: params.reference,
      payment_method: providerCode,
      notify_url: BACKEND_URL + '/payments/transfer-notify',
      lastname: lastName,
      firstname: firstName,
      email: params.account.email || 'client@akwaba.ci',
    }];

    return fetch(CINETPAY_TRANSFER_SEND_URL + '?token=' + encodeURIComponent(token), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: JSON.stringify(body) }),
    })
      .then(function(res) { return res.json(); })
      .then(function(json) {
        var data = json.data && json.data[0];
        var ok = json.code === 0 && data && (data.status === 'PENDING' || data.status === 'CONFIRM');
        return {
          ok: ok,
          status: data ? data.status : 'ERROR',
          transfer_reference: data ? data.transaction_id : null,
          raw: json,
        };
      });
  })
    .catch(function(err) {
      console.error('Erreur transferPayout:', err.message);
      return { ok: false, status: 'ERROR', raw: { error: err.message } };
    });
}

module.exports = {
  verifyHmacToken: verifyHmacToken,
  verifyTransactionWithApi: verifyTransactionWithApi,
  initPayment: initPayment,
  transferPayout: transferPayout,
  isTransferEnabled: function() { return CINETPAY_TRANSFER_ENABLED; },
};
