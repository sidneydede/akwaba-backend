// scripts/reset-admin-credentials.js — Reset email + password d'un compte admin existant
// Usage:
//   node scripts/reset-admin-credentials.js <currentEmail> <newEmail> [newPassword]
//
// Si <newPassword> est omis, le script en génère un crypto-random garanti sans
// chars ambigus pour PowerShell/bash (que [a-zA-Z0-9] + suffixe "Aa2!").
// L'affichage final montre le password généré 1 fois — copie-le immédiatement.
//
// Après UPDATE en DB, le script appelle le backend live (env AKWABA_BACKEND_URL
// ou default prod) pour vérifier que le login fonctionne end-to-end. Si OK, la
// DB sur laquelle on écrit ET le backend prod tapent bien sur la même base.
// Si FAIL, on a un mismatch (typique : DATABASE_URL local pas alignée avec
// celle utilisée par le service Render).
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
// - Politique SEC M2 appliquée au nouveau password
// - Password généré in-process si non fourni → jamais en argv, jamais clipboard
// - 2FA TOTP préservée (totp_secret non touché)

require('dotenv').config();
var crypto = require('crypto');
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var passwordPolicy = require('../services/passwordPolicy');

var args = process.argv.slice(2);
var currentEmail = (args[0] || '').trim().toLowerCase();
var newEmail = (args[1] || '').trim().toLowerCase();
var newPassword = args[2] || '';
var passwordGenerated = false;

if (!currentEmail || !newEmail) {
  console.error('Usage: node scripts/reset-admin-credentials.js <currentEmail> <newEmail> [newPassword]');
  console.error('Si <newPassword> omis : génère un password crypto-random safe pour shell.');
  process.exit(1);
}
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
  console.error('Nouvel email invalide.');
  process.exit(1);
}

function generateSafePassword() {
  var alnum = crypto.randomBytes(18).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
  return alnum.slice(0, 16) + 'Aa2!';
}

if (!newPassword) {
  newPassword = generateSafePassword();
  passwordGenerated = true;
}

// Politique SEC M2 : valide la complexité (catch d'un password fourni faible).
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
        'RETURNING id, email',
        [newEmail, newFakePhone, passwordHash, adminId]
      );
    });
  })
  .then(function(r) {
    var admin = r.rows[0];
    console.log('Admin mis à jour : id=' + admin.id + ', email=' + admin.email);
    // Auto-verify end-to-end : appelle le backend live pour confirmer que la
    // DB qu'on vient de modifier est bien celle utilisée par le service prod.
    var backendUrl = process.env.AKWABA_BACKEND_URL || 'https://akwaba-backend.onrender.com';
    console.log('Verif live contre ' + backendUrl + ' ...');
    return fetch(backendUrl + '/admin/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: newEmail, password: newPassword })
    })
      .then(function(res) {
        return res.json().then(function(data) { return { status: res.status, data: data }; });
      })
      .then(function(result) {
        console.log('');
        console.log('============================================================');
        if (result.data && result.data.success) {
          console.log('  END-TO-END OK : backend a accepte les nouveaux credentials.');
        } else {
          console.log('  END-TO-END FAIL : DB/backend pointent sur des bases differentes.');
          console.log('  Status=' + result.status + ' Reponse=' + JSON.stringify(result.data));
        }
        console.log('============================================================');
        if (passwordGenerated) {
          console.log('');
          console.log('NOUVEAU PASSWORD : ' + newPassword);
          console.log('(Copie-le maintenant — pas reaffiche. Clear-Host apres usage.)');
        }
        console.log('');
        console.log('Login : ' + backendUrl.replace('akwaba-backend.onrender.com', 'admin.event-next-door.com') + '/login');
        console.log('Email : ' + newEmail);
        console.log('NB : tokens existants invalides (SEC M9). 2FA TOTP preservee.');
        process.exit(0);
      });
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
