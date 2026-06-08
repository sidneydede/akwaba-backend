// services/paystack.js — Wrapper Paystack pour EventNextDoor.
// Remplace services/cinetpay.js (migration 2026-06-07). Surface identique :
//   - initPayment : initie le checkout hosted (POST /transaction/initialize)
//   - verifyTransaction : double-check d'un paiement (GET /transaction/verify/:ref)
//   - verifyWebhookSignature : HMAC-SHA512 du raw body vs header x-paystack-signature
//   - createTransferRecipient + transferPayout : payout B2C orga (mobile money/bank)
//   - initiateRefund : remboursement billet annule
//
// Paystack supporte XOF / CI / Orange Money / MTN / Wave / Moov / Visa /
// Mastercard / Apple Pay — couvre tous les besoins du marche pilote Abidjan.
//
// Doc : https://paystack.com/docs/api/

var crypto = require('crypto');

var PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
var PAYSTACK_BASE = 'https://api.paystack.co';

// Paystack attend TOUS les montants en subunit (×100), y compris XOF qui
// n'a pourtant pas de subunit officiel. Si on envoie 200 FCFA brut, Paystack
// debite 2 FCFA (interprete comme 200/100). La conversion est encapsulee
// ici — toutes les routes appelantes manipulent du FCFA "naturel".
function toSubunit(amount) { return parseInt(amount, 10) * 100; }
function fromSubunit(amount) { return Math.round(parseInt(amount, 10) / 100); }
var BACKEND_URL = process.env.BACKEND_URL || 'https://akwaba-backend.onrender.com';
// Page de retour apres paiement. Le webhook fait foi cote backend ; cette URL
// est juste l'experience visuelle du user en sortie de Paystack hosted page.
var FRONT_RETURN_URL = process.env.FRONT_RETURN_URL || (BACKEND_URL + '/payment-success');

// Fail-fast en prod si la cle secrete est absente. En dev on tolere (les
// tests / boot local fonctionnent sans paiement reel). Meme garde-fou que
// l'ancien services/cinetpay.js pour eviter une regression silencieuse.
if (process.env.NODE_ENV === 'production' && !PAYSTACK_SECRET_KEY) {
  throw new Error(
    'PAYSTACK_SECRET_KEY manquante en production. Configure la var sur Render avant de demarrer.'
  );
}

function authHeaders() {
  return {
    'Authorization': 'Bearer ' + (PAYSTACK_SECRET_KEY || ''),
    'Content-Type': 'application/json',
  };
}

// Normalise un numero CI vers le format international E.164 attendu par
// Paystack pour les recipients mobile money. Strip le 0 de tete car le
// format Paystack mobile_money attend juste 10 chiffres precedes du country
// code (pas de +).
function normalizePhoneE164(phone) {
  if (!phone) return '';
  var s = String(phone).trim().replace(/\s/g, '');
  if (s.startsWith('+225')) return s;
  if (s.startsWith('225')) return '+' + s;
  if (s.startsWith('+')) return s;
  if (s.startsWith('0')) return '+225' + s;
  return '+225' + s;
}

// Numero local CI sans 0 ni country code, format requis par Paystack
// transferrecipient.account_number (10 chiffres).
function localPhone(phone) {
  return String(phone || '')
    .replace(/^\+225/, '')
    .replace(/^225/, '')
    .replace(/^0/, '')
    .replace(/\s/g, '');
}

// ============================================================
// 1. CHECKOUT HOSTED — paiement participant
// ============================================================

// Initie une transaction Paystack et retourne l'URL du checkout hosted.
// Le frontend ouvre cette URL via WebBrowser.openBrowserAsync (cf. EventScreen.js).
//
// Pour XOF, le montant est passe TEL QUEL (pas de subunit comme NGN/kobo).
// Email obligatoire cote Paystack — si l'user n'a pas d'email enregistre
// (cas frequent : login OTP SMS), on genere un placeholder.
//
// @param {object} params
//   - reference: string (ex 'AKW-A1B2C3D4') — devient le reference Paystack
//   - amount: number (FCFA entier)
//   - description: string (apparait dans le dashboard Paystack)
//   - customer: { id, name, phone, email? }
//   - channels: array<string> (defaut ['mobile_money','card'])
// @returns {Promise<{ok, payment_url, payment_token, raw}>}
//   payment_url = authorization_url Paystack, aliase pour compat frontend.
//   payment_token = access_code Paystack (utile pour resumer une transac).
function initPayment(params) {
  if (!PAYSTACK_SECRET_KEY) {
    return Promise.reject(new Error('PAYSTACK_SECRET_KEY manquante'));
  }
  var email = (params.customer && params.customer.email)
    ? params.customer.email
    : ('user-' + (params.customer.id || 'guest') + '@event-next-door.com');

  var body = {
    email: email,
    amount: toSubunit(params.amount),
    currency: 'XOF',
    reference: params.reference,
    callback_url: FRONT_RETURN_URL,
    channels: params.channels || ['mobile_money', 'card'],
    metadata: {
      customer_id: String(params.customer.id || ''),
      customer_name: params.customer.name || '',
      customer_phone: normalizePhoneE164(params.customer.phone),
      description: params.description || 'Billet EventNextDoor',
    },
  };

  return fetch(PAYSTACK_BASE + '/transaction/initialize', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(body),
  })
    .then(function(res) { return res.json(); })
    .then(function(json) {
      var data = json.data || {};
      var ok = json.status === true && !!data.authorization_url;
      if (!ok) {
        console.error('[paystack] init refuse. Payload:', JSON.stringify({
          ref: body.reference,
          amount: body.amount,
          email: body.email,
          channels: body.channels,
        }));
        console.error('[paystack] reponse:', JSON.stringify(json));
      }
      return {
        ok: ok,
        payment_url: data.authorization_url,
        payment_token: data.access_code,
        raw: json,
      };
    });
}

// Verifie l'etat reel d'une transaction aupres de Paystack. Source de verite
// pour le webhook — meme si la signature passe, on confirme la transac en
// queryant directement Paystack.
//
// @param {string} reference — la ref envoyee a initialize
// @returns {Promise<{ok, status, amount, raw}>}
//   ok = true si la transac a ete payee avec succes
//   status = 'success' | 'failed' | 'abandoned' | etc. (string Paystack)
//   amount = montant en XOF
function verifyTransaction(reference) {
  if (!PAYSTACK_SECRET_KEY) {
    return Promise.reject(new Error('PAYSTACK_SECRET_KEY manquante'));
  }
  return fetch(PAYSTACK_BASE + '/transaction/verify/' + encodeURIComponent(reference), {
    headers: authHeaders(),
  })
    .then(function(res) { return res.json(); })
    .then(function(json) {
      var data = json.data || {};
      var status = data.status || 'unknown';
      var amount = data.amount != null ? fromSubunit(data.amount) : 0;
      var ok = json.status === true && status === 'success';
      return { ok: ok, status: status, amount: amount, raw: json };
    });
}

// Verifie la signature HMAC-SHA512 d'un webhook Paystack.
// Paystack signe le RAW body (pas le JSON parse) avec la secret key.
// Cf. server.js : on capture req.rawBody via le verify callback de express.json().
//
// @param {string|Buffer} rawBody — le body brut tel que Paystack l'a envoye
// @param {string} signature — header 'x-paystack-signature'
// @returns {boolean}
function verifyWebhookSignature(rawBody, signature) {
  if (!PAYSTACK_SECRET_KEY) {
    console.error('PAYSTACK_SECRET_KEY absent — webhook REJECTED (fail-closed)');
    return false;
  }
  if (!signature || !rawBody) return false;
  var expected = crypto
    .createHmac('sha512', PAYSTACK_SECRET_KEY)
    .update(typeof rawBody === 'string' ? rawBody : rawBody.toString('utf8'))
    .digest('hex');
  if (expected.length !== signature.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(signature, 'hex'));
  } catch (e) {
    return false;
  }
}

// ============================================================
// 2. TRANSFERS — payout B2C orga
// ============================================================

// Mappe nos providers internes vers les codes Paystack bank_code attendus
// par /transferrecipient pour type=mobile_money.
//
// Codes verifies via GET /bank?currency=XOF&country=cote+d'ivoire&type=mobile_money
// le 2026-06-07. Paystack ne supporte pas Moov mobile money en CI a date
// (seulement Orange, MTN, Wave). Pour un payout vers Moov, l'admin doit
// utiliser un compte bancaire classique (type='nuban' avec bank_code BCEAO).
function parseProvider(provider) {
  if (provider === 'orange_money') return 'ORANGE_CI';
  if (provider === 'mtn_momo' || provider === 'mtn_money') return 'MTN_CI';
  if (provider === 'wave') return 'WAVE_CI';
  return null;
}

// Cree un transfer recipient Paystack et retourne son recipient_code. C'est
// l'identifiant a passer ensuite a /transfer.
//
// @param {object} params
//   - name: string (nom complet du beneficiaire)
//   - account_number: string (numero local CI 10 chiffres pour mobile money)
//   - bank_code: string (code provider, cf. parseProvider)
//   - type: 'mobile_money' | 'nuban' (defaut mobile_money)
// @returns {Promise<{ok, recipient_code, raw}>}
function createTransferRecipient(params) {
  if (!PAYSTACK_SECRET_KEY) {
    return Promise.reject(new Error('PAYSTACK_SECRET_KEY manquante'));
  }
  var body = {
    type: params.type || 'mobile_money',
    name: params.name,
    account_number: params.account_number,
    bank_code: params.bank_code,
    currency: 'XOF',
  };
  return fetch(PAYSTACK_BASE + '/transferrecipient', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(body),
  })
    .then(function(res) { return res.json(); })
    .then(function(json) {
      var data = json.data || {};
      return {
        ok: json.status === true && !!data.recipient_code,
        recipient_code: data.recipient_code,
        raw: json,
      };
    });
}

// Initie un transfer B2C vers un beneficiaire mobile money.
//
// Note OTP : en mode live, Paystack exige une confirmation OTP par defaut.
// Pour automation, desactiver dans dashboard Paystack > Settings > Preferences
// > "Disable OTP for transfers". En mode test, l'OTP est ignore.
//
// @param {object} params
//   - amount: number (FCFA entier)
//   - account: { provider, number, name }
//   - reference: string (ex 'PAYOUT-42')
// @returns {Promise<{ok, status, transfer_reference, raw}>}
function transferPayout(params) {
  if (!PAYSTACK_SECRET_KEY) {
    return Promise.resolve({
      ok: false,
      status: 'manual_required',
      raw: { message: 'PAYSTACK_SECRET_KEY absent — reversement manuel requis.' },
    });
  }
  var bankCode = parseProvider(params.account && params.account.provider);
  if (!bankCode) {
    return Promise.resolve({
      ok: false,
      status: 'unsupported_provider',
      raw: { message: 'Provider ' + (params.account && params.account.provider) + ' non supporte par Paystack.' },
    });
  }

  return createTransferRecipient({
    name: params.account.name || 'Beneficiaire EventNextDoor',
    account_number: localPhone(params.account.number),
    bank_code: bankCode,
  })
    .then(function(recipientResult) {
      if (!recipientResult.ok) {
        return {
          ok: false,
          status: 'recipient_failed',
          raw: recipientResult.raw,
        };
      }
      var body = {
        source: 'balance',
        amount: toSubunit(params.amount),
        recipient: recipientResult.recipient_code,
        reason: 'EventNextDoor payout ' + params.reference,
        reference: params.reference,
        currency: 'XOF',
      };
      return fetch(PAYSTACK_BASE + '/transfer', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(body),
      })
        .then(function(res) { return res.json(); })
        .then(function(json) {
          var data = json.data || {};
          return {
            ok: json.status === true && (data.status === 'success' || data.status === 'pending' || data.status === 'otp'),
            status: data.status || 'error',
            transfer_reference: data.transfer_code || data.reference,
            raw: json,
          };
        });
    })
    .catch(function(err) {
      console.error('Erreur transferPayout Paystack:', err.message);
      return { ok: false, status: 'error', raw: { error: err.message } };
    });
}

// ============================================================
// 3. REFUNDS — remboursement billet annule
// ============================================================

// Declenche un remboursement Paystack pour une transaction passee.
// Refund Paystack est ASYNCHRONE — l'API renvoie status='pending' et le
// webhook refund.processed (ou refund.failed) confirme l'issue.
//
// @param {object} params
//   - transaction: string (reference initiale du paiement, ex 'AKW-A1B2C3D4')
//   - amount: number (FCFA entier, optionnel — defaut = full refund)
//   - reason: string (optionnel, trace dans dashboard Paystack)
// @returns {Promise<{ok, status, raw}>}
function initiateRefund(params) {
  if (!PAYSTACK_SECRET_KEY) {
    return Promise.resolve({
      ok: false,
      status: 'manual_required',
      raw: { message: 'PAYSTACK_SECRET_KEY absent — refund manuel requis.' },
    });
  }
  var body = {
    transaction: params.transaction,
  };
  if (params.amount != null) body.amount = toSubunit(params.amount);
  if (params.reason) body.merchant_note = params.reason;

  return fetch(PAYSTACK_BASE + '/refund', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(body),
  })
    .then(function(res) { return res.json(); })
    .then(function(json) {
      var data = json.data || {};
      return {
        ok: json.status === true,
        status: data.status || (json.status === true ? 'pending' : 'error'),
        raw: json,
      };
    })
    .catch(function(err) {
      console.error('Erreur initiateRefund Paystack:', err.message);
      return { ok: false, status: 'error', raw: { error: err.message } };
    });
}

module.exports = {
  initPayment: initPayment,
  verifyTransaction: verifyTransaction,
  verifyWebhookSignature: verifyWebhookSignature,
  createTransferRecipient: createTransferRecipient,
  transferPayout: transferPayout,
  initiateRefund: initiateRefund,
  parseProvider: parseProvider,
  // Helper pour les routes qui veulent decider du fallback manual
  isConfigured: function() { return !!PAYSTACK_SECRET_KEY; },
};
