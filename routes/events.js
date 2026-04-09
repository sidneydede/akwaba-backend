// routes/events.js — CRUD des événements
// GET /events : liste publique, POST /events : création (organisateurs)

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');

// GET /events — Liste tous les événements
// @query {string} category - Filtrer par catégorie (optionnel)
// @query {string} search - Recherche texte (optionnel)
router.get('/', function(req, res) {
  var category = req.query.category;
  var search = req.query.search;

  var query = 'SELECT id, title, description, category, date, lieu, prix, prix_display, emoji, color, chaud, image_url, places_total, places_restantes FROM events ORDER BY chaud DESC, created_at DESC';
  var params = [];

  if (category) {
    query = 'SELECT id, title, description, category, date, lieu, prix, prix_display, emoji, color, chaud, image_url, places_total, places_restantes FROM events WHERE LOWER(category) = LOWER($1) ORDER BY chaud DESC, created_at DESC';
    params = [category];
  }

  if (search) {
    query = 'SELECT id, title, description, category, date, lieu, prix, prix_display, emoji, color, chaud, image_url, places_total, places_restantes FROM events WHERE LOWER(title) LIKE LOWER($1) OR LOWER(lieu) LIKE LOWER($1) ORDER BY chaud DESC, created_at DESC';
    params = ['%' + search + '%'];
  }

  pool.query(query, params)
    .then(function(result) {
      // Format compatible avec le frontend existant
      var events = result.rows.map(function(row) {
        return {
          id: row.id.toString(),
          title: row.title,
          description: row.description,
          category: row.category,
          date: row.date,
          lieu: row.lieu,
          prix: row.prix_display,
          prix_num: row.prix,
          emoji: row.emoji,
          color: row.color,
          chaud: row.chaud,
          image_url: row.image_url,
          places_total: row.places_total,
          places_restantes: row.places_restantes
        };
      });

      res.json({ success: true, events: events });
    })
    .catch(function(err) {
      console.error('Erreur GET /events:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /events/mine — Liste les événements créés par l'organisateur connecté
router.get('/mine', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT id, title, description, category, date, lieu, prix, prix_display, emoji, color, chaud, image_url, places_total, places_restantes, created_at FROM events WHERE organizer_id = $1 ORDER BY created_at DESC',
    [req.userId]
  )
    .then(function(result) {
      var events = result.rows.map(function(row) {
        return {
          id: row.id.toString(),
          title: row.title,
          description: row.description,
          category: row.category,
          date: row.date,
          lieu: row.lieu,
          prix: row.prix_display,
          prix_num: row.prix,
          emoji: row.emoji,
          color: row.color,
          chaud: row.chaud,
          image_url: row.image_url,
          places_total: row.places_total,
          places_restantes: row.places_restantes,
          created_at: row.created_at
        };
      });
      res.json({ success: true, events: events });
    })
    .catch(function(err) {
      console.error('Erreur GET /events/mine:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /events/:id — Détail d'un événement
router.get('/:id', function(req, res) {
  pool.query('SELECT * FROM events WHERE id = $1', [req.params.id])
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Événement non trouvé' });
      }

      var row = result.rows[0];
      res.json({
        success: true,
        event: {
          id: row.id.toString(),
          title: row.title,
          description: row.description,
          category: row.category,
          date: row.date,
          lieu: row.lieu,
          prix: row.prix_display,
          prix_num: row.prix,
          emoji: row.emoji,
          color: row.color,
          chaud: row.chaud,
          image_url: row.image_url,
          places_total: row.places_total,
          places_restantes: row.places_restantes
        }
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /events/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /events — Créer un événement (organisateurs uniquement)
// @body {string} title, description, category, date, lieu, prix, emoji, color
router.post('/', auth.authMiddleware, function(req, res) {
  var body = req.body;

  if (!body.title || !body.category || !body.date || !body.lieu) {
    return res.status(400).json({
      success: false,
      message: 'Titre, catégorie, date et lieu sont obligatoires'
    });
  }

  var prix = parseInt(body.prix) || 0;
  var prixDisplay = prix > 0 ? prix.toLocaleString('fr-FR') + ' FCFA' : 'Gratuit';
  var placesTotal = parseInt(body.places_total) || 500;

  pool.query(
    'INSERT INTO events (title, description, category, date, lieu, prix, prix_display, emoji, color, chaud, image_url, places_total, places_restantes, organizer_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, $13) RETURNING *',
    [
      body.title,
      body.description || '',
      body.category,
      body.date,
      body.lieu,
      prix,
      prixDisplay,
      body.emoji || '🎵',
      body.color || '#E67E22',
      body.chaud || false,
      body.image_url || null,
      placesTotal,
      req.userId
    ]
  )
    .then(function(result) {
      var row = result.rows[0];
      res.status(201).json({
        success: true,
        message: 'Événement créé',
        event: {
          id: row.id.toString(),
          title: row.title,
          category: row.category,
          date: row.date,
          lieu: row.lieu,
          prix: row.prix_display
        }
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /events:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
