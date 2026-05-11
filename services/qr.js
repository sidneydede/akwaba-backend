// services/qr.js — Signature HMAC des QR codes billets
// Sans signature, un attaquant qui devine une ref (8 hex = 32 bits) marque le billet
// comme utilisé. Avec HMAC-SHA256, il faudrait deviner 64 bits supplémentaires =
// computationnellement infaisable (2^64 possibilités).
//
// Format du payload signé : AKW-XXXXXXXX.HHHHHHHHHHHHHHHH
//                           ^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^
//                           ref booking   16 hex = 64 bits HMAC tronqué
//
// La clé HMAC_SECRET reste côté serveur, jamais exposée au client.

var crypto = require('crypto');

// QR_HMAC_SECRET dédié recommandé. Fallback sur TOKEN_SECRET si non défini.
// Pas de fallback dev — TOKEN_SECRET est validé au boot dans middleware/auth.js,
// donc on arrive ici avec une valeur garantie sûre.
var HMAC_SECRET = process.env.QR_HMAC_SECRET || process.env.TOKEN_SECRET;
if (!HMAC_SECRET) {
  throw new Error(
    'QR_HMAC_SECRET (ou TOKEN_SECRET) manquant. Configure-le dans .env / Render.'
  );
}
var SIG_LENGTH = 16; // 16 hex chars = 64 bits — collision-resistant pour notre échelle.

// Calcule la signature HMAC tronquée d'une ref booking.
// @param {string} ref - ex: 'AKW-A1B2C3D4'
// @returns {string} Hex tronqué à SIG_LENGTH chars
function signature(ref) {
  return crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(ref)
    .digest('hex')
    .slice(0, SIG_LENGTH);
}

// Construit le payload QR signé prêt à être encodé.
// @param {string} ref
// @returns {string} 'AKW-XXXXXXXX.HHHHHHHHHHHHHHHH'
function signRef(ref) {
  return ref + '.' + signature(ref);
}

// Vérifie un payload signé et retourne la ref si valide.
// Comparaison timing-safe pour éviter les timing attacks.
// @param {string} payload - 'AKW-XXXXXXXX.HHHHHHHHHHHHHHHH' (avec ou sans préfixe AKWABA-BILLET:)
// @returns {{ok: boolean, ref: string|null}}
function parseAndVerify(payload) {
  if (!payload || typeof payload !== 'string') return { ok: false, ref: null };

  // Support du préfixe optionnel utilisé par la lib QR mobile.
  var clean = payload.replace(/^AKWABA-BILLET:/, '');

  var parts = clean.split('.');
  if (parts.length !== 2) return { ok: false, ref: null };

  var ref = parts[0];
  var sig = parts[1];

  if (!/^AKW-[A-F0-9]{8}$/.test(ref)) return { ok: false, ref: null };
  if (sig.length !== SIG_LENGTH) return { ok: false, ref: null };

  var expected = signature(ref);
  // timingSafeEqual exige Buffers de même longueur.
  try {
    var a = Buffer.from(sig, 'hex');
    var b = Buffer.from(expected, 'hex');
    if (a.length !== b.length) return { ok: false, ref: null };
    return crypto.timingSafeEqual(a, b)
      ? { ok: true, ref: ref }
      : { ok: false, ref: null };
  } catch (e) {
    return { ok: false, ref: null };
  }
}

module.exports = {
  signRef: signRef,
  parseAndVerify: parseAndVerify,
};
