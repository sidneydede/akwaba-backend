// migrate.js — Crée les tables PostgreSQL pour Akwaba
// Usage: node db/migrate.js

require('dotenv').config();
var pool = require('./pool');

var CREATE_TABLES = "\n\
-- Table des utilisateurs\n\
CREATE TABLE IF NOT EXISTS users (\n\
  id SERIAL PRIMARY KEY,\n\
  nom VARCHAR(100) NOT NULL,\n\
  prenom VARCHAR(100) NOT NULL,\n\
  phone VARCHAR(20) UNIQUE NOT NULL,\n\
  role VARCHAR(20) DEFAULT 'participant',\n\
  otp_code VARCHAR(6),\n\
  otp_expires_at TIMESTAMP,\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  updated_at TIMESTAMP DEFAULT NOW()\n\
);\n\
\n\
-- Table des événements\n\
CREATE TABLE IF NOT EXISTS events (\n\
  id SERIAL PRIMARY KEY,\n\
  title VARCHAR(200) NOT NULL,\n\
  description TEXT,\n\
  category VARCHAR(50) NOT NULL,\n\
  date VARCHAR(100) NOT NULL,\n\
  lieu VARCHAR(200) NOT NULL,\n\
  prix INTEGER NOT NULL DEFAULT 0,\n\
  prix_display VARCHAR(50) NOT NULL,\n\
  emoji VARCHAR(10) DEFAULT '🎵',\n\
  color VARCHAR(10) DEFAULT '#E67E22',\n\
  chaud BOOLEAN DEFAULT false,\n\
  image_url TEXT,\n\
  places_total INTEGER DEFAULT 500,\n\
  places_restantes INTEGER DEFAULT 500,\n\
  organizer_id INTEGER REFERENCES users(id),\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  updated_at TIMESTAMP DEFAULT NOW()\n\
);\n\
\n\
-- Table des réservations (billets)\n\
CREATE TABLE IF NOT EXISTS bookings (\n\
  id SERIAL PRIMARY KEY,\n\
  user_id INTEGER NOT NULL REFERENCES users(id),\n\
  event_id INTEGER NOT NULL REFERENCES events(id),\n\
  ref VARCHAR(20) UNIQUE NOT NULL,\n\
  quantity INTEGER DEFAULT 1,\n\
  total_amount INTEGER NOT NULL,\n\
  paiement_method VARCHAR(50),\n\
  statut VARCHAR(20) DEFAULT 'en_attente',\n\
  transaction_id VARCHAR(100),\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  updated_at TIMESTAMP DEFAULT NOW()\n\
);\n\
\n\
-- Table des paiements (historique CinetPay)\n\
CREATE TABLE IF NOT EXISTS payments (\n\
  id SERIAL PRIMARY KEY,\n\
  booking_id INTEGER REFERENCES bookings(id),\n\
  transaction_id VARCHAR(100) UNIQUE NOT NULL,\n\
  amount INTEGER NOT NULL,\n\
  currency VARCHAR(10) DEFAULT 'XOF',\n\
  method VARCHAR(50),\n\
  status VARCHAR(20) DEFAULT 'PENDING',\n\
  cinetpay_data JSONB,\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  updated_at TIMESTAMP DEFAULT NOW()\n\
);\n\
\n\
-- Table des tokens push (un user peut avoir plusieurs devices)\n\
CREATE TABLE IF NOT EXISTS device_tokens (\n\
  id SERIAL PRIMARY KEY,\n\
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n\
  token TEXT NOT NULL,\n\
  platform VARCHAR(20),\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  last_seen_at TIMESTAMP DEFAULT NOW(),\n\
  UNIQUE (user_id, token)\n\
);\n\
\n\
-- Index pour les requêtes fréquentes\n\
CREATE INDEX IF NOT EXISTS idx_bookings_user ON bookings(user_id);\n\
CREATE INDEX IF NOT EXISTS idx_bookings_event ON bookings(event_id);\n\
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);\n\
CREATE INDEX IF NOT EXISTS idx_payments_transaction ON payments(transaction_id);\n\
CREATE INDEX IF NOT EXISTS idx_device_tokens_user ON device_tokens(user_id);\n\
\n\
-- Géolocalisation : coordonnées d'un événement (idempotent sur redeploy)\n\
ALTER TABLE events ADD COLUMN IF NOT EXISTS latitude DECIMAL(9,6);\n\
ALTER TABLE events ADD COLUMN IF NOT EXISTS longitude DECIMAL(9,6);\n\
\n\
-- Admin / modération (idempotent sur redeploy)\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMP;\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_reason TEXT;\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(200);\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;\n\
\n\
ALTER TABLE events ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'pending';\n\
ALTER TABLE events ADD COLUMN IF NOT EXISTS moderated_by INTEGER REFERENCES users(id);\n\
ALTER TABLE events ADD COLUMN IF NOT EXISTS moderated_at TIMESTAMP;\n\
ALTER TABLE events ADD COLUMN IF NOT EXISTS rejection_reason TEXT;\n\
\n\
-- Backfill : tous les events pré-existants passent à 'approved' pour ne pas\n\
-- disparaître de l'app. Les nouveaux events partent à 'pending' (DEFAULT).\n\
UPDATE events SET status = 'approved' WHERE status IS NULL;\n\
\n\
-- Audit log : trace toutes les actions admin (qui, quoi, quand, sur quelle cible)\n\
CREATE TABLE IF NOT EXISTS admin_audit_log (\n\
  id SERIAL PRIMARY KEY,\n\
  admin_id INTEGER REFERENCES users(id),\n\
  action VARCHAR(50) NOT NULL,\n\
  target_type VARCHAR(20),\n\
  target_id VARCHAR(50),\n\
  metadata JSONB,\n\
  created_at TIMESTAMP DEFAULT NOW()\n\
);\n\
\n\
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);\n\
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);\n\
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);\n\
CREATE INDEX IF NOT EXISTS idx_admin_audit_admin ON admin_audit_log(admin_id, created_at DESC);\n\
";

console.log('Migration en cours...');

pool.query(CREATE_TABLES)
  .then(function() {
    console.log('Tables créées avec succès !');
    console.log('  - users');
    console.log('  - events');
    console.log('  - bookings');
    console.log('  - payments');
    console.log('  - device_tokens');
    console.log('  - admin_audit_log');
    process.exit(0);
  })
  .catch(function(err) {
    console.error('Erreur migration:', err.message);
    process.exit(1);
  });
