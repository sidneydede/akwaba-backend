// scripts/regenerate-admin-password.js — Génère un nouveau password + reset un admin.
// Usage : node scripts/regenerate-admin-password.js <email>
// Pour prod : DATABASE_URL=<render-url> en env avant le run.
//
// Évite tous les pièges de quoting PowerShell : le password n'est jamais en argv,
// il est généré dans le process Node puis appliqué directement. Affichage final
// 1 fois → copie-le et clear ton scrollback après usage (Clear-Host).
//
// Password garanti :
//   - Que des chars [a-zA-Z0-9] + "Aa2!" en suffixe → aucun caractère ambigu
//     pour PowerShell/bash/cmd
//   - 20 chars total, satisfait SEC M2 (12+ chars, maj/min/chiffre/spécial)
//   - Crypto-random (18 bytes d'entropie source)

require('dotenv').config();
var crypto = require('crypto');
var pool = require('../db/pool');
var auth = require('../middleware/auth');

var email = (process.argv[2] || '').trim().toLowerCase();
if (!email) {
  console.error('Usage: node scripts/regenerate-admin-password.js <email>');
  process.exit(1);
}

function generatePassword() {
  var alnum = crypto.randomBytes(18).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
  return alnum.slice(0, 16) + 'Aa2!';
}

var newPassword = generatePassword();

pool.query(
  "SELECT id FROM users WHERE LOWER(email) = $1 AND role = 'admin'",
  [email]
)
  .then(function(r) {
    if (r.rows.length === 0) {
      console.error('Aucun admin trouvé avec email = ' + email);
      process.exit(1);
    }
    var adminId = r.rows[0].id;
    return auth.hashPassword(newPassword)
      .then(function(hash) {
        return pool.query(
          'UPDATE users SET password_hash = $1, password_changed_at = NOW(), ' +
          'updated_at = NOW() WHERE id = $2',
          [hash, adminId]
        );
      })
      .then(function() {
        console.log('Reset OK pour admin id=' + adminId + ', email=' + email);
        // Auto-verify end-to-end : appelle le backend live avec le password
        // qu'on vient d'écrire en DB. Si l'env BACKEND_URL est set, l'utilise,
        // sinon default prod. Élimine tout doute sur DB/backend mismatch ou
        // typing humain (le password ne passe jamais par le clipboard).
        var backendUrl = process.env.AKWABA_BACKEND_URL || 'https://akwaba-backend.onrender.com';
        console.log('Verif live contre ' + backendUrl + ' ...');
        return fetch(backendUrl + '/admin/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email, password: newPassword })
        })
          .then(function(res) {
            return res.json().then(function(data) { return { status: res.status, data: data }; });
          })
          .then(function(result) {
            console.log('');
            console.log('============================================================');
            if (result.data && result.data.success) {
              console.log('  END-TO-END OK : backend a accepte le nouveau password.');
              console.log('  Le portail admin ' + backendUrl + ' verra le meme.');
            } else {
              console.log('  END-TO-END FAIL : backend a refuse le password qu\'on vient');
              console.log('  d\'ecrire en DB. Probablement DB/backend pointent sur des');
              console.log('  bases differentes. Status=' + result.status);
              console.log('  Reponse=' + JSON.stringify(result.data));
            }
            console.log('============================================================');
            console.log('');
            console.log('NOUVEAU PASSWORD : ' + newPassword);
            console.log('');
            console.log('Si END-TO-END OK : login sur https://admin.event-next-door.com/login');
            console.log('avec dedesidney@gmail.com + le password ci-dessus.');
            console.log('Pense ensuite a Clear-Host pour purger ton scrollback.');
            process.exit(0);
          });
      });
  })
  .catch(function(e) {
    console.error('Erreur:', e.message);
    process.exit(1);
  });
