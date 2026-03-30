// pool.js — Connexion PostgreSQL via pg Pool
// Utilise DATABASE_URL fourni par Render ou .env local

var pg = require('pg');
var Pool = pg.Pool;

var pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
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
