// services/cinetpay.js — Helpers de vérification CinetPay
// Deux couches de défense contre la falsification de webhook :
//   1. Vérification HMAC du header x-token (rapide, rejette les appels triviaux)
//   2. Double-check via l'API CinetPay /v2/payment/check (authoritative, infalsifiable)

var crypto = require('crypto');

var CINETPAY_API_KEY = process.env.CINETPAY_API_KEY;
var CINETPAY_SITE_ID = process.env.CINETPAY_SITE_ID;
var CINETPAY_SECRET_KEY = process.env.CINETPAY_SECRET_KEY;
var CINETPAY_INIT_URL = 'https://api-checkout.cinetpay.com/v2/payment';
var CINETPAY_CHECK_URL = 'https://api-checkout.cinetpay.com/v2/payment/check';
// URL de base de l'API backend (utilisée pour notify_url envoyée à CinetPay)
var BACKEND_URL = process.env.BACKEND_URL || 'https://akwaba-backend.onrender.com';
var FRONT_RETURN_URL = process.env.FRONT_RETURN_URL || 'https://akwaba.ci/billet-confirme';

// Vérifie le HMAC-SHA256 du header x-token envoyé par CinetPay.
// L'algo CinetPay : SHA256(secretKey, concat(champs ordonnés)).
// Retourne true si le token correspond, false sinon. Si SECRET_KEY n'est pas configurée,
// retourne true (skip — on s'appuie sur le double-check API qui est obligatoire).
// @param {object} body - req.body du webhook
// @param {string} token - valeur du header x-token
// @returns {boolean}
function verifyHmacToken(body, token) {
  if (!CINETPAY_SECRET_KEY) {
    console.warn('CINETPAY_SECRET_KEY absent — skip HMAC, on s\'appuie sur le double-check API');
    return true;
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

  var body = {
    apikey: CINETPAY_API_KEY,
    site_id: CINETPAY_SITE_ID,
    transaction_id: params.ref,
    amount: params.amount,
    currency: 'XOF',
    description: params.description || 'Billet Akwaba',
    customer_id: String(params.customer.id),
    customer_name: params.customer.name || 'Akwaba',
    customer_surname: params.customer.surname || 'Client',
    customer_phone_number: params.customer.phone || '',
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
      return {
        ok: ok,
        payment_url: data.payment_url,
        payment_token: data.payment_token,
        raw: json,
      };
    });
}

module.exports = {
  verifyHmacToken: verifyHmacToken,
  verifyTransactionWithApi: verifyTransactionWithApi,
  initPayment: initPayment,
};
