// scripts/list-admins.js — Liste tous les comptes admin (id, email, admin_role, 2FA).
// Usage: node scripts/list-admins.js
// Pour prod : DATABASE_URL=<render-url> en env avant le run.
//
// Utile pour retrouver l'email exact d'un admin avant d'appeler reset-admin-credentials.
// Read-only, ne modifie rien.

require('dotenv').config();
var pool = require('../db/pool');

pool.query(
  "SELECT id, email, nom, prenom, admin_role, " +
  "totp_enabled_at IS NOT NULL AS totp, suspended_at IS NOT NULL AS suspended, " +
  "last_login_at FROM users WHERE role = 'admin' ORDER BY id"
)
  .then(function(r) {
    if (r.rows.length === 0) {
      console.log('Aucun admin en base.');
      process.exit(0);
    }
    console.log(r.rows.length + ' admin(s) :');
    r.rows.forEach(function(u) {
      console.log(
        '  id=' + u.id +
        ' | email=' + u.email +
        ' | ' + (u.prenom || '') + ' ' + (u.nom || '') +
        ' | role=' + (u.admin_role || 'NULL') +
        ' | 2fa=' + (u.totp ? 'yes' : 'no') +
        (u.suspended ? ' | SUSPENDED' : '') +
        (u.last_login_at ? ' | last_login=' + u.last_login_at.toISOString().slice(0, 16) : ' | never_logged_in')
      );
    });
    process.exit(0);
  })
  .catch(function(err) {
    console.error('Erreur list-admins:', err.message);
    process.exit(1);
  });
