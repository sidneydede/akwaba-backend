const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Route de test
app.get('/', function(req, res) {
  res.json({ message: 'Akwaba API fonctionne !', version: '1.0.0' });
});

// Routes événements
app.get('/events', function(req, res) {
  res.json({
    success: true,
    events: [
      {
        id: '1',
        title: 'FEMUA 2025',
        category: 'Festival',
        date: 'Sam 5 Avr · 20h00',
        lieu: 'Stade Felix Houphouet, Abidjan',
        prix: '5 000 FCFA',
        emoji: '🎵',
        color: '#E67E22',
        chaud: true,
      },
      {
        id: '2',
        title: 'Match ASEC vs Africa',
        category: 'Football',
        date: 'Dim 6 Avr · 16h00',
        lieu: 'Stade de la Paix, Bouaké',
        prix: '2 000 FCFA',
        emoji: '⚽',
        color: '#C0392B',
        chaud: false,
      },
      {
        id: '3',
        title: 'Nuit du Coupé-Décalé',
        category: 'Soirée',
        date: 'Ven 4 Avr · 22h00',
        lieu: 'Black & White Club, Cocody',
        prix: '3 000 FCFA',
        emoji: '🎉',
        color: '#B8860B',
        chaud: true,
      },
      {
        id: '4',
        title: 'Stand-up Abidjan Comedy',
        category: 'Culture',
        date: 'Sam 5 Avr · 19h00',
        lieu: 'Palais de la Culture, Plateau',
        prix: '4 000 FCFA',
        emoji: '🎭',
        color: '#922B21',
        chaud: false,
      },
    ]
  });
});

// Route inscription
app.post('/auth/register', function(req, res) {
  const { nom, prenom, phone, role } = req.body;
  if (!nom || !prenom || !phone) {
    return res.status(400).json({ success: false, message: 'Champs manquants' });
  }
  res.json({
    success: true,
    message: 'Compte créé avec succès',
    user: { id: '1', nom, prenom, phone, role: role || 'participant' },
    token: 'akwaba-token-' + Date.now(),
  });
});

// Route connexion
app.post('/auth/login', function(req, res) {
  const { phone } = req.body;
  if (!phone) {
    return res.status(400).json({ success: false, message: 'Numéro requis' });
  }
  res.json({
    success: true,
    message: 'Connexion réussie',
    user: { id: '1', nom: 'Dadié', prenom: 'Ammou', phone },
    token: 'akwaba-token-' + Date.now(),
  });
});

// Route réservation
app.post('/bookings', function(req, res) {
  const { eventId, paiement } = req.body;
  if (!eventId || !paiement) {
    return res.status(400).json({ success: false, message: 'Données manquantes' });
  }
  var ref = 'AKW-' + Math.random().toString(36).substr(2, 8).toUpperCase();
  res.json({
    success: true,
    message: 'Réservation confirmée',
    booking: {
      id: Date.now().toString(),
      eventId,
      paiement,
      ref,
      statut: 'confirmé',
      createdAt: new Date().toISOString(),
    }
  });
});

app.listen(PORT, function() {
  console.log('Akwaba API démarrée sur le port ' + PORT);
});