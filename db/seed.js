// seed.js — Insère les données de test dans la base Akwaba
// Usage: node db/seed.js

require('dotenv').config();
var pool = require('./pool');

// Utilisateur de test
var INSERT_USER = "\
INSERT INTO users (nom, prenom, phone, role) VALUES \
('Dadié', 'Ammou', '0700000000', 'participant'), \
('Konaté', 'Ibrahim', '0500000000', 'organisateur'), \
('Touré', 'Awa', '0100000000', 'organisateur') \
ON CONFLICT (phone) DO NOTHING;\
";

// Événements de test (mêmes que l'API actuelle + nouveaux)
// Coordonnées Abidjan/Bouaké pour tester la géolocalisation.
var INSERT_EVENTS = "\
INSERT INTO events (title, description, category, date, lieu, prix, prix_display, emoji, color, chaud, places_total, places_restantes, latitude, longitude) VALUES \
(\
  'FEMUA 2025', \
  'Le Festival des Musiques Urbaines d''Anoumabo, l''un des plus grands festivals de musique en Afrique de l''Ouest. Artistes internationaux, ambiance électrique et culture ivoirienne à son meilleur.', \
  'Festival', \
  'Sam 5 Avr · 20h00', \
  'Stade Felix Houphouet, Abidjan', \
  5000, \
  '5 000 FCFA', \
  '🎵', \
  '#E67E22', \
  true, \
  5000, \
  4753, \
  5.281, \
  -3.987 \
), \
(\
  'Match ASEC vs Africa', \
  'Le classico ivoirien ! ASEC Mimosas contre Africa Sports dans un match au sommet de la Ligue 1. Ambiance garantie dans le stade.', \
  'Football', \
  'Dim 6 Avr · 16h00', \
  'Stade de la Paix, Bouaké', \
  2000, \
  '2 000 FCFA', \
  '⚽', \
  '#C0392B', \
  false, \
  20000, \
  18500, \
  7.690, \
  -5.030 \
), \
(\
  'Nuit du Coupé-Décalé', \
  'La plus grande soirée coupé-décalé d''Abidjan ! DJ Mix, artistes live et ambiance folle jusqu''au bout de la nuit. Dress code : classe et tendance.', \
  'Soirée', \
  'Ven 4 Avr · 22h00', \
  'Black & White Club, Cocody', \
  3000, \
  '3 000 FCFA', \
  '🎉', \
  '#B8860B', \
  true, \
  800, \
  752, \
  5.358, \
  -3.985 \
), \
(\
  'Stand-up Abidjan Comedy', \
  'Les meilleurs humoristes de Côte d''Ivoire réunis pour une soirée de rire et de bonne humeur. Sketches, impro et surprise au programme.', \
  'Culture', \
  'Sam 5 Avr · 19h00', \
  'Palais de la Culture, Plateau', \
  4000, \
  '4 000 FCFA', \
  '🎭', \
  '#922B21', \
  false, \
  1200, \
  1150, \
  5.317, \
  -4.013 \
), \
(\
  'Africa Digital Summit', \
  'Conférence tech annuelle réunissant entrepreneurs, développeurs et investisseurs de toute l''Afrique. Networking, pitchs et ateliers pratiques.', \
  'Conférences', \
  'Lun 7 Avr · 09h00', \
  'Sofitel Hôtel Ivoire, Cocody', \
  15000, \
  '15 000 FCFA', \
  '🎓', \
  '#2980B9', \
  true, \
  500, \
  420, \
  5.330, \
  -3.999 \
), \
(\
  'Veillée de Prière - Cathédrale', \
  'Grande veillée de prière et louange à la Cathédrale Saint-Paul du Plateau. Entrée libre, venez nombreux.', \
  'Religion', \
  'Ven 4 Avr · 20h00', \
  'Cathédrale Saint-Paul, Plateau', \
  0, \
  'Gratuit', \
  '🙏', \
  '#27AE60', \
  false, \
  2000, \
  1800, \
  5.330, \
  -4.018 \
) \
ON CONFLICT DO NOTHING;\
";

// Nettoie les doublons d'events seedés accumulés par les redeploys passés
// (le seed était rerun à chaque cold start sans UNIQUE constraint efficace).
// Garde le plus petit id par titre, sauf si un id plus grand a des bookings
// (auquel cas on le garde aussi pour ne pas casser la contrainte FK).
// Idempotent : ne fait rien si pas de doublons.
var CLEANUP_DUPLICATES = "\
DELETE FROM events \
WHERE id NOT IN (SELECT MIN(id) FROM events GROUP BY title) \
  AND id NOT IN (SELECT DISTINCT event_id FROM bookings WHERE event_id IS NOT NULL);\
";

// Backfill des coordonnées pour les events seedés sur une DB pré-existante
// (ne fait rien si la colonne latitude est déjà renseignée). Idempotent.
var BACKFILL_COORDS = "\
UPDATE events SET latitude = 5.281, longitude = -3.987 WHERE title = 'FEMUA 2025' AND latitude IS NULL;\
UPDATE events SET latitude = 7.690, longitude = -5.030 WHERE title = 'Match ASEC vs Africa' AND latitude IS NULL;\
UPDATE events SET latitude = 5.358, longitude = -3.985 WHERE title = 'Nuit du Coupé-Décalé' AND latitude IS NULL;\
UPDATE events SET latitude = 5.317, longitude = -4.013 WHERE title = 'Stand-up Abidjan Comedy' AND latitude IS NULL;\
UPDATE events SET latitude = 5.330, longitude = -3.999 WHERE title = 'Africa Digital Summit' AND latitude IS NULL;\
UPDATE events SET latitude = 5.330, longitude = -4.018 WHERE title = 'Veillée de Prière - Cathédrale' AND latitude IS NULL;\
";

console.log('Seed en cours...');

pool.query(INSERT_USER)
  .then(function() {
    console.log('Utilisateurs de test créés');
    // Nettoyage des doublons accumulés par les redeploys passés.
    return pool.query(CLEANUP_DUPLICATES);
  })
  .then(function(cleanupResult) {
    if (cleanupResult.rowCount > 0) {
      console.log('Doublons d\'events nettoyés : ' + cleanupResult.rowCount + ' row(s)');
    }
    // Skip INSERT_EVENTS si la table contient déjà des events (évite la
    // recréation à chaque cold start). Le seed n'insère qu'une fois sur DB vide.
    return pool.query('SELECT COUNT(*)::int AS n FROM events');
  })
  .then(function(countResult) {
    var n = countResult.rows[0].n;
    if (n > 0) {
      console.log('Events déjà présents (' + n + '), skip INSERT seed');
      return null;
    }
    console.log('Table events vide, insertion des events seed');
    return pool.query(INSERT_EVENTS);
  })
  .then(function() {
    return pool.query(BACKFILL_COORDS);
  })
  .then(function() {
    console.log('Coordonnées géo backfillées (events sans lat/lng)');
    console.log('Seed terminé avec succès !');
    process.exit(0);
  })
  .catch(function(err) {
    console.error('Erreur seed:', err.message);
    process.exit(1);
  });
