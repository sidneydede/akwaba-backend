// scripts/reset-admin-credentials.js — Reset email + password d'un compte admin existant
// Usage: node scripts/reset-admin-credentials.js <currentEmail> <newEmail> <newPassword>
//
// Cas d'usage typique : un email seedé à l'époque pré-rebrand (@akwaba.app)
// n'est pas une vraie mailbox réceptrice → bascule sur l'email réel de l'admin.
//
// Différence avec seed-admin.js : seed-admin INSERT OR UPDATE par phone, et le
// phone est dérivé de l'email. Donc seed-admin avec un nouvel email crée un
// DEUXIÈME admin au lieu de renommer l'existant. Ce script identifie l'admin
// existant par currentEmail et met à jour son email (et son fake phone, pour
// rester cohérent avec la convention 'admin-' + slug email).
//
// Sécurité :
// - password_changed_at = NOW() → invalide tous les tokens existants (SEC M9)
// - Politique SEC M2 appliquée au nouveau password (12+ chars, complexité)
// - Le password est en argv, pas en variable d'env → reste local au terminal
//
// Pour reset le compte PROD sans exposer DATABASE_URL en .env local :
//   $env:DATABASE_URL="<render-prod-url>"; node scripts/reset-admin-credentials.js \
//     ancien@email.com nouveau@email.com 'MotDePasseFort!2026'

require('dotenv').config();
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var passwordPolicy = require('../services/passwordPolicy');

var args = process.argv.slice(2);
var currentEmail = (args[0] || '').trim().toLowerCase();
var newEmail = (args[1] || '').trim().toLowerCase();
var newPassword = args[2] || '';

if (!currentEmail || !newEmail || !newPassword) {
  console.error('Usage: node scripts/reset-admin-credentials.js <currentEmail> <newEmail> <newPassword>');
  process.exit(1);
}
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
  console.error('Nouvel email invalide.');
  process.exit(1);
}
// Politique SEC M2 : valide la complexité du password. Passe newEmail en
// contexte pour le check anti-self-leak (password contenant le local-part).
var policyError = passwordPolicy.validate(newPassword, { email: newEmail });
if (policyError) {
  console.error('Password invalide : ' + policyError);
  process.exit(1);
}

// Phone factice mis à jour pour rester cohérent avec la convention seed-admin.
// Format : 'admin-' + slug du nouveau email, slicé à 14 chars (column VARCHAR(20)).
var newFakePhone = 'admin-' + newEmail.replace(/[^a-z0-9]/g, '').slice(0, 14);

console.log('Reset credentials admin : ' + currentEmail + ' → ' + newEmail);

pool.query(
  "SELECT id, email, role, admin_role FROM users WHERE LOWER(email) = $1 AND role = 'admin'",
  [currentEmail]
)
  .then(function(r) {
    if (r.rows.length === 0) {
      console.error('Aucun admin trouvé avec email = ' + currentEmail);
      process.exit(1);
    }
    var adminId = r.rows[0].id;
    var adminRole = r.rows[0].admin_role || '(NULL)';
    console.log('Admin trouvé : id=' + adminId + ', admin_role=' + adminRole);
    return auth.hashPassword(newPassword).then(function(passwordHash) {
      return pool.query(
        'UPDATE users SET email = $1, phone = $2, password_hash = $3, ' +
        'password_changed_at = NOW(), updated_at = NOW() WHERE id = $4 ' +
        'RETURNING id, email, role',
        [newEmail, newFakePhone, passwordHash, adminId]
      );
    });
  })
  .then(function(r) {
    var admin = r.rows[0];
    console.log('Admin mis à jour : id=' + admin.id + ', email=' + admin.email);
    console.log('Tu peux maintenant te connecter avec :');
    console.log('  email    : ' + admin.email);
    console.log('  password : (celui que tu viens de fournir)');
    console.log('NB : les tokens existants sont invalidés (SEC M9). Si tu avais 2FA setup,');
    console.log('     elle reste active (totp_secret préservé).');
    process.exit(0);
  })
  .catch(function(err) {
    if (err.code === '23505') {
      console.error('Conflit unicité : un autre user a déjà cet email ou ce fake phone.');
      console.error('Vérifie qu\'il n\'y a pas de doublon avant de réessayer.');
    } else {
      console.error('Erreur reset-admin-credentials:', err.message);
    }
    process.exit(1);
  });
