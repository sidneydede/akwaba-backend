// services/email.js — Envoi d'emails transactionnels via Resend
// Mode production : utilise l'API Resend si RESEND_API_KEY défini
// Mode dev : log l'OTP dans la console (visible dans Render Logs)
//
// Miroir de services/sms.js pour le canal email du flow OTP multi-canal.

var RESEND_API_KEY = process.env.RESEND_API_KEY;
var RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL || 'noreply@event-next-door.com';
var RESEND_FROM_NAME = process.env.RESEND_FROM_NAME || 'Akwaba';

// Détecte si le mode email réel est actif
// @returns {boolean}
function isRealEmailEnabled() {
  return Boolean(RESEND_API_KEY);
}

// Validation basique d'adresse email. On reste large (RFC 5322 simplifié)
// pour ne pas rejeter des adresses légitimes — la vraie validation = un OTP
// arrive ou pas.
// @param {string} email
// @returns {boolean}
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  if (email.length > 200) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

// Normalise un email (trim + lowercase) pour le store en DB. Évite les doublons
// type "User@Mail.com" vs "user@mail.com" et facilite les lookups.
// @param {string} email
// @returns {string}
function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

// Construit le HTML de l'email OTP. Markup minimal mais rendu correctement
// dans Gmail/Outlook/iOS Mail. Pas de tracker, pas d'image distante (anti
// déclenchement spam filters + privacy).
// @param {string} code
// @returns {string}
function buildOtpHtml(code) {
  return '<!DOCTYPE html><html><head><meta charset="utf-8"></head>' +
    '<body style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;' +
    'background:#fafafa;margin:0;padding:24px;color:#1a1a1a;">' +
    '<div style="max-width:480px;margin:0 auto;background:#fff;border-radius:12px;' +
    'padding:32px 28px;box-shadow:0 1px 3px rgba(0,0,0,0.05);">' +
    '<h1 style="font-size:18px;margin:0 0 16px;color:#1a1a1a;">Code de vérification Akwaba</h1>' +
    '<p style="font-size:15px;line-height:1.5;margin:0 0 24px;color:#555;">' +
    'Voici votre code à 6 chiffres. Il est valable 10 minutes.</p>' +
    '<div style="font-size:32px;font-weight:600;letter-spacing:8px;text-align:center;' +
    'background:#f4f4f5;border-radius:8px;padding:20px;color:#1a1a1a;margin:0 0 24px;">' +
    code + '</div>' +
    '<p style="font-size:13px;line-height:1.5;color:#888;margin:0;">' +
    'Si vous n\'êtes pas à l\'origine de cette demande, ignorez ce message.</p>' +
    '</div></body></html>';
}

// Envoie un code OTP par email
// @param {string} email - Adresse destinataire
// @param {string} code - Code OTP à 6 chiffres
// @returns {Promise<object>} { success: boolean, dev?: boolean, error?: any }
function sendOtp(email, code) {
  var normalized = normalizeEmail(email);

  // Mode dev : log dans la console et retourne success (parité avec sms.js).
  // SAUF en prod : si RESEND_API_KEY est absent en prod, c'est une misconfig
  // dangereuse — le mode dev mettrait dev_otp dans la réponse HTTP (leak).
  // On préfère refuser explicitement et que le client affiche une erreur.
  if (!isRealEmailEnabled()) {
    if (process.env.NODE_ENV === 'production') {
      console.error('[EMAIL] RESEND_API_KEY absent en prod — refus envoi pour ' + normalized);
      return Promise.resolve({ success: false, error: 'EMAIL_NOT_CONFIGURED' });
    }
    console.log('[EMAIL DEV] OTP pour ' + normalized + ' : ' + code);
    return Promise.resolve({ success: true, dev: true });
  }

  if (!isValidEmail(normalized)) {
    return Promise.resolve({ success: false, error: 'INVALID_EMAIL' });
  }

  // Appel HTTP direct à l'API Resend (pas besoin du SDK pour 1 endpoint).
  // Endpoint : POST https://api.resend.com/emails
  // Auth : Bearer RESEND_API_KEY
  var payload = {
    from: RESEND_FROM_NAME + ' <' + RESEND_FROM_EMAIL + '>',
    to: [normalized],
    subject: 'Votre code Akwaba : ' + code,
    html: buildOtpHtml(code),
    text: 'Votre code de vérification Akwaba est : ' + code + '\nValable 10 minutes.',
  };

  return fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + RESEND_API_KEY,
    },
    body: JSON.stringify(payload),
  })
    .then(function(res) {
      return res.json().then(function(data) { return { status: res.status, data: data }; });
    })
    .then(function(result) {
      console.log('[EMAIL] Réponse Resend (' + result.status + ') :', JSON.stringify(result.data));
      if (result.status >= 200 && result.status < 300 && result.data && result.data.id) {
        return { success: true };
      }
      return { success: false, error: result.data };
    })
    .catch(function(err) {
      console.error('[EMAIL] Erreur envoi :', err.message);
      return { success: false, error: err.message };
    });
}

module.exports = {
  sendOtp: sendOtp,
  isRealEmailEnabled: isRealEmailEnabled,
  isValidEmail: isValidEmail,
  normalizeEmail: normalizeEmail,
};
