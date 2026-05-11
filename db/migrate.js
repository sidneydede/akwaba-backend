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
\n\
-- ============================================================\n\
-- FEEDBACK-01 : NPS post-event (signal qualité interne)\n\
-- ============================================================\n\
-- Différent des reviews publics : feedback = interne (ratings + commentaires\n\
-- privés pour l'équipe Akwaba), reviews = social proof public sur la fiche event.\n\
-- 1 feedback max par user par booking (UNIQUE).\n\
CREATE TABLE IF NOT EXISTS feedback (\n\
  id SERIAL PRIMARY KEY,\n\
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n\
  booking_id INTEGER NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,\n\
  event_id INTEGER REFERENCES events(id) ON DELETE SET NULL,\n\
  rating SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),\n\
  comment TEXT,\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  UNIQUE (user_id, booking_id)\n\
);\n\
CREATE INDEX IF NOT EXISTS idx_feedback_event ON feedback(event_id);\n\
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at DESC);\n\
\n\
-- ============================================================\n\
-- REF-01 : Programme de parrainage\n\
-- ============================================================\n\
-- Chaque user a un referral_code unique (genere a register, backfill pour existants).\n\
-- Quand un filleul redeem un code, on cree un referral pending. Quand le filleul\n\
-- fait sa 1ere reservation confirmee (hook webhook /payments/notify), on award\n\
-- 200 pts au parrain + push notif. Le filleul a deja recu 500 pts au redeem.\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(12) UNIQUE;\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS points INTEGER DEFAULT 0;\n\
\n\
-- Backfill : tous les users existants recoivent un code AKW-XXXX deterministe\n\
-- (hash de id+created_at en base36, premiers 4 chars uppercase).\n\
UPDATE users SET referral_code = 'AKW-' || UPPER(SUBSTRING(MD5(id::text || COALESCE(created_at::text, NOW()::text)) FROM 1 FOR 4))\n\
WHERE referral_code IS NULL;\n\
\n\
CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);\n\
\n\
CREATE TABLE IF NOT EXISTS referrals (\n\
  id SERIAL PRIMARY KEY,\n\
  parrain_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n\
  filleul_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n\
  status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed')),\n\
  points_filleul INTEGER NOT NULL DEFAULT 500,\n\
  points_parrain INTEGER NOT NULL DEFAULT 200,\n\
  parrain_points_awarded BOOLEAN NOT NULL DEFAULT false,\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  confirmed_at TIMESTAMP,\n\
  UNIQUE (filleul_id),\n\
  CHECK (parrain_id != filleul_id)\n\
);\n\
CREATE INDEX IF NOT EXISTS idx_referrals_parrain ON referrals(parrain_id);\n\
\n\
-- ============================================================\n\
-- FOLLOW-01 : Suivre un organisateur + push notif perso\n\
-- ============================================================\n\
-- Push notif au follower quand un event de l'orga suivi devient 'approved'\n\
-- (hook dans PATCH /admin/events/:id/approve, cf. routes/admin.js).\n\
CREATE TABLE IF NOT EXISTS follows (\n\
  id SERIAL PRIMARY KEY,\n\
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n\
  organisateur_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  UNIQUE (user_id, organisateur_id),\n\
  CHECK (user_id != organisateur_id)\n\
);\n\
CREATE INDEX IF NOT EXISTS idx_follows_user ON follows(user_id);\n\
CREATE INDEX IF NOT EXISTS idx_follows_orga ON follows(organisateur_id);\n\
\n\
-- Anti double-push : flag sur events pour ne notifier les followers QU'UNE\n\
-- fois (premier passage status='approved'). Si admin reject puis re-approve,\n\
-- on ne re-notifie pas.\n\
ALTER TABLE events ADD COLUMN IF NOT EXISTS followers_notified_at TIMESTAMP;\n\
\n\
-- ============================================================\n\
-- REVIEW-01 : Avis publics sur events (P3.1)\n\
-- ============================================================\n\
-- Different du feedback (NPS prive). Reviews = note + commentaire publics\n\
-- affiches sur la fiche event (social proof). 1 avis max par user par event.\n\
CREATE TABLE IF NOT EXISTS reviews (\n\
  id SERIAL PRIMARY KEY,\n\
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n\
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,\n\
  rating SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),\n\
  comment TEXT,\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  UNIQUE (user_id, event_id)\n\
);\n\
CREATE INDEX IF NOT EXISTS idx_reviews_event ON reviews(event_id, created_at DESC);\n\
\n\
-- ============================================================\n\
-- WAITLIST-01 : Liste d'attente sur events sold-out\n\
-- ============================================================\n\
-- Quand places_restantes = 0, l'user peut rejoindre la waitlist. Quand un\n\
-- booking est annule (POST /bookings/:id/cancel), un hook notifie le 1er\n\
-- user en waitlist (par joined_at ASC) qu'une place s'est liberee. notified_at\n\
-- est marque pour ne pas re-notifier le meme user. Si l'user rejoint plus\n\
-- tard, il revient en queue avec notified_at = NULL.\n\
CREATE TABLE IF NOT EXISTS waitlists (\n\
  id SERIAL PRIMARY KEY,\n\
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n\
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,\n\
  joined_at TIMESTAMP DEFAULT NOW(),\n\
  notified_at TIMESTAMP,\n\
  UNIQUE (user_id, event_id)\n\
);\n\
CREATE INDEX IF NOT EXISTS idx_waitlists_event_queue ON waitlists(event_id, joined_at ASC);\n\
CREATE INDEX IF NOT EXISTS idx_waitlists_user ON waitlists(user_id);\n\
\n\
-- ============================================================\n\
-- TEAM-01 : Multi-organisateurs (equipe scan only)\n\
-- ============================================================\n\
-- L'orga proprietaire d'un event peut inviter d'autres users a aider au\n\
-- scan le jour J (portiers, assistants). Ces 'staff' n'ont pas acces a\n\
-- l'edition ni aux finances, juste au scanner.\n\
-- Role 'scanner' pour V1. Roles futurs possibles : 'co_orga', 'box_office'.\n\
-- L'invitation se fait par numero de telephone : si l'user existe deja, on\n\
-- ajoute direct ; sinon on creee un user pending qui sera lie au compte si\n\
-- la personne s'inscrit avec ce phone.\n\
CREATE TABLE IF NOT EXISTS event_staff (\n\
  id SERIAL PRIMARY KEY,\n\
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,\n\
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n\
  role VARCHAR(20) NOT NULL DEFAULT 'scanner',\n\
  invited_by INTEGER REFERENCES users(id),\n\
  created_at TIMESTAMP DEFAULT NOW(),\n\
  UNIQUE (event_id, user_id)\n\
);\n\
CREATE INDEX IF NOT EXISTS idx_event_staff_user ON event_staff(user_id);\n\
CREATE INDEX IF NOT EXISTS idx_event_staff_event ON event_staff(event_id);\n\
\n\
-- ============================================================\n\
-- ADM-2FA : TOTP obligatoire pour les comptes admin\n\
-- ============================================================\n\
-- totp_secret = secret confirme et actif (utilise au login)\n\
-- totp_pending_secret = secret en cours de setup (avant la 1ere validation par code)\n\
-- totp_enabled_at = date d'activation (NULL = pas encore active)\n\
-- Les admins existants devront passer par /admin/2fa/setup au prochain login\n\
-- (must_setup_2fa = true tant que totp_enabled_at IS NULL).\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(64);\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending_secret VARCHAR(64);\n\
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled_at TIMESTAMP;\n\
\n\
-- ============================================================\n\
-- ADM-DIGEST : Digest quotidien automatique envoyé aux admins\n\
-- ============================================================\n\
-- Un digest = un instantané des metrics J-1 + flags d'anomalies, généré par\n\
-- le cron jobs/admin-digest.js chaque jour à 8h UTC. Stocké en DB + envoyé\n\
-- par email (si RESEND_API_KEY configuré). UNIQUE sur digest_date pour éviter\n\
-- les doublons si le cron tick plusieurs fois dans la journée.\n\
CREATE TABLE IF NOT EXISTS admin_digests (\n\
  id SERIAL PRIMARY KEY,\n\
  digest_date DATE UNIQUE NOT NULL,\n\
  data JSONB NOT NULL,\n\
  html TEXT NOT NULL,\n\
  email_sent_at TIMESTAMP,\n\
  email_recipients TEXT[],\n\
  email_error TEXT,\n\
  created_at TIMESTAMP DEFAULT NOW()\n\
);\n\
CREATE INDEX IF NOT EXISTS idx_admin_digests_date ON admin_digests(digest_date DESC);\n\
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
