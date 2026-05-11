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
-- Check-in : trace du scan QR à l'entrée par l'organisateur\n\
ALTER TABLE bookings ADD COLUMN IF NOT EXISTS utilise_at TIMESTAMP;\n\
ALTER TABLE bookings ADD COLUMN IF NOT EXISTS checkin_by INTEGER REFERENCES users(id);\n\
\n\
-- AUTH-05 : protection brute-force OTP (attempt limit + lockout temporaire)\n\
-- Plus strict pour les organisateurs car compromission = accès aux fonds.\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_attempts INT DEFAULT 0;\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_locked_until TIMESTAMP;\n\
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
\n\
-- ============================================================\n\
-- ADM-05 : Reversements organisateurs (escrow J+2)\n\
-- ============================================================\n\
\n\
-- Date/heure de début parsable (TIMESTAMP). La colonne `date` reste pour rétrocompat\n\
-- d'affichage (texte 'Sam 14 Juin · 20h00'). start_at est ce sur quoi on calcule\n\
-- l'éligibilité au reversement (event_end + 48h).\n\
ALTER TABLE events ADD COLUMN IF NOT EXISTS start_at TIMESTAMP;\n\
ALTER TABLE events ADD COLUMN IF NOT EXISTS end_at TIMESTAMP;\n\
\n\
-- Compte de reversement de l'organisateur (mobile money ou bancaire).\n\
-- Format JSONB : { provider: 'orange_money' | 'mtn_momo' | 'wave' | 'bank',\n\
--                  number: '+225...', name: 'John Doe',\n\
--                  bank_name?: 'NSIA', iban?: 'CI...' }\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS payout_account JSONB;\n\
\n\
-- Table des reversements. Un reversement = un montant net à verser à un organisateur,\n\
-- agrégé sur une période (typiquement les bookings d'un événement, ou multi-events\n\
-- en mode 'period'). On garde event_id NULL pour les payouts manuels multi-events.\n\
CREATE TABLE IF NOT EXISTS payouts (\n\
  id SERIAL PRIMARY KEY,\n\
  organizer_id INTEGER NOT NULL REFERENCES users(id),\n\
  event_id INTEGER REFERENCES events(id),\n\
  period_start TIMESTAMP,\n\
  period_end TIMESTAMP,\n\
  bookings_count INTEGER NOT NULL DEFAULT 0,\n\
  gross_amount BIGINT NOT NULL DEFAULT 0,\n\
  commission_amount BIGINT NOT NULL DEFAULT 0,\n\
  cinetpay_fees BIGINT NOT NULL DEFAULT 0,\n\
  net_amount BIGINT NOT NULL DEFAULT 0,\n\
  status VARCHAR(20) NOT NULL DEFAULT 'scheduled',\n\
  scheduled_at TIMESTAMP,\n\
  released_at TIMESTAMP,\n\
  released_by INTEGER REFERENCES users(id),\n\
  block_reason TEXT,\n\
  account_info JSONB,\n\
  notes TEXT,\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  updated_at TIMESTAMP DEFAULT NOW()\n\
);\n\
\n\
CREATE INDEX IF NOT EXISTS idx_payouts_organizer ON payouts(organizer_id, status);\n\
CREATE INDEX IF NOT EXISTS idx_payouts_status_scheduled ON payouts(status, scheduled_at);\n\
CREATE INDEX IF NOT EXISTS idx_payouts_event ON payouts(event_id);\n\
\n\
-- v2-B : flag d'auto-release calculé par le CRON (refund ratio < seuil ET amount < threshold).\n\
-- Permet à l'admin de voir d'un coup d'œil les payouts \"safe\" à releaser en bulk.\n\
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS auto_release_eligible BOOLEAN DEFAULT false;\n\
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS transfer_reference VARCHAR(100);\n\
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS transfer_status VARCHAR(20);\n\
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS transfer_data JSONB;\n\
\n\
-- v2-C : préférences utilisateur (catégories favorites pour broadcast et reco).\n\
-- Format JSONB : { categories: [\"Festival\", \"Sport\", ...], lang?: \"fr\" }\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS preferences JSONB DEFAULT '{}';\n\
\n\
-- BK-04 : annulation billet par l'utilisateur avec calcul refund selon délai.\n\
ALTER TABLE bookings ADD COLUMN IF NOT EXISTS cancelled_at TIMESTAMP;\n\
ALTER TABLE bookings ADD COLUMN IF NOT EXISTS refund_amount BIGINT;\n\
ALTER TABLE bookings ADD COLUMN IF NOT EXISTS refund_ratio DECIMAL(4,3);\n\
ALTER TABLE bookings ADD COLUMN IF NOT EXISTS cancellation_reason TEXT;\n\
\n\
-- NOTIF-01 : flags de rappels push pour éviter les doublons de notifications.\n\
ALTER TABLE bookings ADD COLUMN IF NOT EXISTS reminder_sent_d1 BOOLEAN DEFAULT false;\n\
ALTER TABLE bookings ADD COLUMN IF NOT EXISTS reminder_sent_h2 BOOLEAN DEFAULT false;\n\
\n\
-- ============================================================\n\
-- ADM-06 : Marketing (banners + featured + broadcasts)\n\
-- ============================================================\n\
\n\
-- Mise en avant payante d'un event (badge À la une + position prioritaire).\n\
ALTER TABLE events ADD COLUMN IF NOT EXISTS is_featured BOOLEAN DEFAULT false;\n\
ALTER TABLE events ADD COLUMN IF NOT EXISTS featured_until TIMESTAMP;\n\
\n\
-- Bannières home (carousel À la une côté mobile).\n\
CREATE TABLE IF NOT EXISTS banners (\n\
  id SERIAL PRIMARY KEY,\n\
  title VARCHAR(120) NOT NULL,\n\
  subtitle VARCHAR(200),\n\
  image_url TEXT NOT NULL,\n\
  link_type VARCHAR(20) NOT NULL DEFAULT 'event',\n\
  link_target VARCHAR(200),\n\
  position INTEGER DEFAULT 0,\n\
  active_from TIMESTAMP,\n\
  active_until TIMESTAMP,\n\
  created_by INTEGER REFERENCES users(id),\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  updated_at TIMESTAMP DEFAULT NOW()\n\
);\n\
CREATE INDEX IF NOT EXISTS idx_banners_active ON banners(active_from, active_until, position);\n\
\n\
-- Historique des broadcasts push (modération + audit + ne pas spammer).\n\
CREATE TABLE IF NOT EXISTS broadcasts (\n\
  id SERIAL PRIMARY KEY,\n\
  title VARCHAR(120) NOT NULL,\n\
  body VARCHAR(500) NOT NULL,\n\
  segment VARCHAR(40) NOT NULL DEFAULT 'all',\n\
  segment_value VARCHAR(100),\n\
  recipients_count INTEGER DEFAULT 0,\n\
  sent_count INTEGER DEFAULT 0,\n\
  failed_count INTEGER DEFAULT 0,\n\
  data JSONB,\n\
  sent_by INTEGER REFERENCES users(id),\n\
  sent_at TIMESTAMP DEFAULT NOW()\n\
);\n\
CREATE INDEX IF NOT EXISTS idx_broadcasts_sent ON broadcasts(sent_at DESC);\n\
\n\
-- ============================================================\n\
-- ADM-07 : Paramètres plateforme (clé/valeur typée)\n\
-- ============================================================\n\
-- Stockés en table KV pour pouvoir être édités sans deploy.\n\
-- Valeurs JSON pour supporter int, decimal, string, bool, json.\n\
CREATE TABLE IF NOT EXISTS app_settings (\n\
  key VARCHAR(60) PRIMARY KEY,\n\
  value JSONB NOT NULL,\n\
  description TEXT,\n\
  updated_by INTEGER REFERENCES users(id),\n\
  updated_at TIMESTAMP DEFAULT NOW()\n\
);\n\
\n\
-- Seed des paramètres par défaut (idempotent : ON CONFLICT DO NOTHING).\n\
INSERT INTO app_settings (key, value, description) VALUES\n\
  ('commission_rate', '0.06', 'Taux de commission Akwaba sur les billets vendus (0.06 = 6%)'),\n\
  ('cinetpay_fee_rate', '0.015', 'Frais CinetPay estimés (~1.5%)'),\n\
  ('escrow_hours', '48', 'Délai en heures avant qu''un payout devienne éligible (J+2 = 48h)'),\n\
  ('refund_policy_default', '{\"more_than_48h\":1.0,\"between_24_and_48h\":0.7,\"less_than_24h\":0.0}', 'Politique de remboursement par défaut (proportion remboursée selon le délai avant événement)'),\n\
  ('tva_rate', '0.18', 'TVA Côte d''Ivoire (18%, incluse dans le prix affiché)'),\n\
  ('payout_review_threshold_amount', '500000', 'Montant FCFA au-dessus duquel un payout exige revue manuelle'),\n\
  ('payout_review_refund_ratio', '0.10', 'Ratio de remboursements au-dessus duquel un payout est bloqué pour revue (0.10 = 10%)')\n\
ON CONFLICT (key) DO NOTHING;\n\
\n\
-- ============================================================\n\
-- FAV-01 : Favoris utilisateur\n\
-- ============================================================\n\
-- Un user peut mettre 0..N events en favori. Couple unique pour empêcher\n\
-- les doublons. ON DELETE CASCADE pour garbage collect quand un user ou un\n\
-- event est supprimé.\n\
CREATE TABLE IF NOT EXISTS favorites (\n\
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n\
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  PRIMARY KEY (user_id, event_id)\n\
);\n\
\n\
CREATE INDEX IF NOT EXISTS idx_favorites_user ON favorites(user_id, created_at DESC);\n\
CREATE INDEX IF NOT EXISTS idx_favorites_event ON favorites(event_id);\n\
\n\
-- ============================================================\n\
-- PROFILE-01 : Champs profil étendus (ville, date naissance, photo)\n\
-- ============================================================\n\
-- Saisis lors de l'étape ProfilSetup (onboarding 03/03) côté front.\n\
-- Tous optionnels (l'user peut skip).\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS ville VARCHAR(120);\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS date_naissance DATE;\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS photo_url TEXT;\n\
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
    console.log('  - payouts (ADM-05)');
    console.log('  - banners (ADM-06)');
    console.log('  - broadcasts (ADM-06)');
    console.log('  - app_settings (ADM-07)');
    console.log('  - favorites (FAV-01)');
    process.exit(0);
  })
  .catch(function(err) {
    console.error('Erreur migration:', err.message);
    process.exit(1);
  });
