// scripts/seed-admin.js — Crée ou met à jour un compte admin
// Usage: node scripts/seed-admin.js <email> <password> [nom] [prenom]
// Idempotent : si l'email existe déjà, met à jour password_hash + role='admin'.
// À runner une seule fois en prod via le shell Render après déploiement.

require('dotenv').config();
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var passwordPolicy = require('../services/passwordPolicy');

var args = process.argv.slice(2);
var email = (args[0] || '').trim().toLowerCase();
var password = args[1] || '';
var nom = args[2] || 'Admin';
var prenom = args[3] || 'Akwaba';

if (!email || !password) {
  console.error('Usage: node scripts/seed-admin.js <email> <password> [nom] [prenom]');
  process.exit(1);
}

// SEC M2 : password complexity (12+ chars, maj/min/chiffre/spécial, pas commun).
var policyError = passwordPolicy.validate(password, { email: email, nom: nom });
if (policyError) {
  console.error('Password invalide : ' + policyError);
  process.exit(1);
}

// Téléphone factice : la colonne est UNIQUE NOT NULL côté users mais
// inutile pour les admins (qui se loguent par email + password).
// Format : 'admin-' + slug de l'email pour rester unique sans collisionner les vrais numéros.
var fakePhone = 'admin-' + email.replace(/[^a-z0-9]/g, '').slice(0, 14);

console.log('Création/mise à jour admin pour ' + email + '...');

auth.hashPassword(password)
  .then(function(passwordHash) {
    // SEC M9 : password_changed_at = NOW() pour invalider les anciens tokens
    // de cet admin (s'il en avait des actifs avant le reset).
    return pool.query(
      'INSERT INTO users (nom, prenom, phone, email, role, password_hash, password_changed_at) ' +
      'VALUES ($1, $2, $3, $4, $5, $6, NOW()) ' +
      'ON CONFLICT (phone) DO UPDATE SET ' +
      'email = EXCLUDED.email, role = EXCLUDED.role, password_hash = EXCLUDED.password_hash, ' +
      'password_changed_at = NOW(), ' +
      'nom = EXCLUDED.nom, prenom = EXCLUDED.prenom, updated_at = NOW() ' +
      'RETURNING id, email, role',
      [nom, prenom, fakePhone, email, 'admin', passwordHash]
    );
  })
  .then(function(result) {
    var admin = result.rows[0];
    console.log('Admin OK : id=' + admin.id + ', email=' + admin.email + ', role=' + admin.role);
    console.log('Tu peux maintenant te connecter sur le dashboard avec :');
    console.log('  email    : ' + email);
    console.log('  password : (celui que tu viens de fournir)');
    process.exit(0);
  })
  .catch(function(err) {
    console.error('Erreur seed-admin:', err.message);
    process.exit(1);
  });
