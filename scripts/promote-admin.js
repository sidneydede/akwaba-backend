// scripts/promote-admin.js — UPSERT d'un compte admin avec un vrai numéro de téléphone.
// Usage : node scripts/promote-admin.js <phone> <email> <password> [nom] [prenom]
// Si le user existe déjà (par phone) → UPDATE (role=admin + email + password).
// Sinon → INSERT.

require('dotenv').config();
var pool = require('../db/pool');
var auth = require('../middleware/auth');

var args = process.argv.slice(2);
var phone = (args[0] || '').trim();
var email = (args[1] || '').trim().toLowerCase();
var password = args[2] || '';
var nom = args[3] || 'Admin';
var prenom = args[4] || 'Akwaba';

if (!phone || !email || !password) {
  console.error('Usage : node scripts/promote-admin.js <phone> <email> <password> [nom] [prenom]');
  process.exit(1);
}

if (password.length < 8) {
  console.error('Le mot de passe doit faire au moins 8 caractères.');
  process.exit(1);
}

console.log('Promotion / création admin pour ' + phone + '...');

auth.hashPassword(password)
  .then(function(hash) {
    return pool.query(
      'INSERT INTO users (nom, prenom, phone, email, role, password_hash) ' +
      "VALUES ($1, $2, $3, $4, 'admin', $5) " +
      'ON CONFLICT (phone) DO UPDATE SET ' +
      "role = 'admin', email = EXCLUDED.email, password_hash = EXCLUDED.password_hash, updated_at = NOW() " +
      'RETURNING id, nom, prenom, email, role',
      [nom, prenom, phone, email, hash]
    );
  })
  .then(function(result) {
    var u = result.rows[0];
    console.log('OK : ' + u.prenom + ' ' + u.nom + ' (id=' + u.id + ') est ' + u.role);
    console.log('Connecte-toi sur /organisateur/admin/login avec :');
    console.log('  email    : ' + u.email);
    console.log('  password : (celui que tu viens de fournir)');
    process.exit(0);
  })
  .catch(function(err) {
    console.error('Erreur :', err.message);
    process.exit(1);
  });
