// pool.js — Connexion PostgreSQL via pg Pool
// Utilise DATABASE_URL fourni par Render ou .env local

var pg = require('pg');
var Pool = pg.Pool;

// SSL activé pour les DB cloud (Render, Neon, Supabase...). On détecte par
// la présence de sslmode=require dans l'URL ou par le hostname connu.
var dbUrl = process.env.DATABASE_URL || '';
var needsSsl = dbUrl.includes('sslmode=require') ||
  dbUrl.includes('render.com') ||
  dbUrl.includes('neon.tech') ||
  dbUrl.includes('supabase.co');

var pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: needsSsl ? { rejectUnauthorized: false } : false
});

// Test de connexion au démarrage
pool.query('SELECT NOW()')
  .then(function(result) {
    console.log('PostgreSQL connecté:', result.rows[0].now);
  })
  .catch(function(err) {
    console.error('Erreur connexion PostgreSQL:', err.message);
  });

module.exports = pool;
