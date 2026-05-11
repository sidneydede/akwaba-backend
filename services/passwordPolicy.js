// services/passwordPolicy.js — Validation complexité password admin.
// Sprint 2 SEC M2 : exigences durcies pour les comptes admin.
//
// Règles :
//   - 12 caractères min (vs 8 avant — un attaquant fait ~10^11 essais/sec
//     sur du scrypt cracking offline, 8 chars cassent en jours)
//   - Au moins 1 maj, 1 min, 1 chiffre, 1 spécial
//   - Pas dans la liste des passwords ultra-communs
//   - Pas le username ou l'email (anti-Trinity-style)

var COMMON_PASSWORDS = [
  'password', 'password123', 'admin', 'admin123', 'admin1234',
  'welcome', 'welcome1', 'azerty', 'azerty123', 'qwerty',
  'qwerty123', 'letmein', 'akwaba', 'akwaba123', '123456789',
  '12345678', '987654321', 'iloveyou', 'monkey', 'dragon',
  'football', 'baseball', '11111111', '00000000', 'abc123',
  'sunshine', 'princess', 'shadow', 'master', 'admin@123',
  'changeme', 'p@ssw0rd', 'p@ssword', 'passw0rd', 'rootroot',
];

// @returns {string|null} message d'erreur si invalide, null si OK
function validate(password, context) {
  context = context || {};
  if (!password || typeof password !== 'string') {
    return 'Password requis.';
  }
  if (password.length < 12) {
    return 'Password trop court (12 caractères min).';
  }
  if (password.length > 200) {
    return 'Password trop long (200 caractères max).';
  }
  if (!/[a-z]/.test(password)) {
    return 'Doit contenir au moins une lettre minuscule.';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Doit contenir au moins une lettre majuscule.';
  }
  if (!/[0-9]/.test(password)) {
    return 'Doit contenir au moins un chiffre.';
  }
  if (!/[^a-zA-Z0-9]/.test(password)) {
    return 'Doit contenir au moins un caractère spécial.';
  }
  var lower = password.toLowerCase();
  if (COMMON_PASSWORDS.indexOf(lower) !== -1) {
    return 'Password trop commun. Choisis quelque chose de plus unique.';
  }
  if (context.email && lower.indexOf(context.email.toLowerCase().split('@')[0]) !== -1) {
    return 'Password ne doit pas contenir le local-part de ton email.';
  }
  if (context.nom && lower.indexOf(String(context.nom).toLowerCase()) !== -1) {
    return 'Password ne doit pas contenir ton nom.';
  }
  return null; // OK
}

module.exports = { validate: validate };
