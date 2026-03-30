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
var INSERT_EVENTS = "\
INSERT INTO events (title, description, category, date, lieu, prix, prix_display, emoji, color, chaud, places_total, places_restantes) VALUES \
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
  4753 \
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
  18500 \
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
  752 \
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
  1150 \
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
  420 \
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
  1800 \
) \
ON CONFLICT DO NOTHING;\
";

console.log('Seed en cours...');

pool.query(INSERT_USER)
  .then(function() {
    console.log('Utilisateurs de test créés');
    return pool.query(INSERT_EVENTS);
  })
  .then(function() {
    console.log('Événements de test créés');
    console.log('Seed terminé avec succès !');
    process.exit(0);
  })
  .catch(function(err) {
    console.error('Erreur seed:', err.message);
    process.exit(1);
  });
