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
// Inclut places_vendues (places_total - places_restantes) et revenue (somme des bookings 'confirme').
router.get('/mine', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
  pool.query(
    'SELECT e.id, e.title, e.description, e.category, e.date, e.lieu, e.prix, e.prix_display, ' +
    'e.emoji, e.color, e.chaud, e.image_url, e.places_total, e.places_restantes, e.created_at, ' +
    '(e.places_total - e.places_restantes) AS places_vendues, ' +
    "COALESCE((SELECT SUM(total_amount) FROM bookings WHERE event_id = e.id AND statut = 'confirme'), 0) AS revenue " +
    'FROM events e WHERE e.organizer_id = $1 ORDER BY e.created_at DESC',
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
          places_vendues: row.places_vendues,
          revenue: parseInt(row.revenue) || 0,
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
          places_restantes: row.places_restantes,
          organizer_id: row.organizer_id
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
router.post('/', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
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

// PUT /events/:id — Modifier un événement (organisateur propriétaire uniquement)
// PATCH partiel : seuls les champs fournis sont mis à jour (via COALESCE).
router.put('/:id', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
  var eventId = req.params.id;
  var body = req.body;

  pool.query('SELECT organizer_id, places_total, places_restantes FROM events WHERE id = $1', [eventId])
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Événement non trouvé' });
      }
      var current = result.rows[0];
      if (current.organizer_id !== req.userId) {
        return res.status(403).json({ success: false, message: 'Cet événement ne vous appartient pas' });
      }

      // Recalcule prix_display si prix change
      var prix = body.prix !== undefined ? parseInt(body.prix) || 0 : null;
      var prixDisplay = prix !== null
        ? (prix > 0 ? prix.toLocaleString('fr-FR') + ' FCFA' : 'Gratuit')
        : null;

      // Ajustement de capacité : si places_total change, places_restantes suit le même delta.
      // places_vendues = places_total - places_restantes doit rester >= 0.
      var newPlacesTotal = body.places_total !== undefined ? parseInt(body.places_total) || current.places_total : null;
      var placesVendues = current.places_total - current.places_restantes;
      var newPlacesRestantes = null;
      if (newPlacesTotal !== null) {
        if (newPlacesTotal < placesVendues) {
          return res.status(400).json({
            success: false,
            message: 'Capacité inférieure aux billets déjà vendus (' + placesVendues + ')'
          });
        }
        newPlacesRestantes = newPlacesTotal - placesVendues;
      }

      return pool.query(
        'UPDATE events SET ' +
        'title = COALESCE($1, title), ' +
        'description = COALESCE($2, description), ' +
        'category = COALESCE($3, category), ' +
        'date = COALESCE($4, date), ' +
        'lieu = COALESCE($5, lieu), ' +
        'prix = COALESCE($6, prix), ' +
        'prix_display = COALESCE($7, prix_display), ' +
        'emoji = COALESCE($8, emoji), ' +
        'color = COALESCE($9, color), ' +
        'chaud = COALESCE($10, chaud), ' +
        'image_url = COALESCE($11, image_url), ' +
        'places_total = COALESCE($12, places_total), ' +
        'places_restantes = COALESCE($13, places_restantes), ' +
        'updated_at = NOW() ' +
        'WHERE id = $14 RETURNING *',
        [
          body.title || null,
          body.description !== undefined ? body.description : null,
          body.category || null,
          body.date || null,
          body.lieu || null,
          prix,
          prixDisplay,
          body.emoji || null,
          body.color || null,
          body.chaud !== undefined ? body.chaud : null,
          body.image_url !== undefined ? body.image_url : null,
          newPlacesTotal,
          newPlacesRestantes,
          eventId
        ]
      )
        .then(function(updateResult) {
          var row = updateResult.rows[0];
          res.json({
            success: true,
            message: 'Événement modifié',
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
        });
    })
    .catch(function(err) {
      console.error('Erreur PUT /events/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// DELETE /events/:id — Supprimer un événement (organisateur propriétaire uniquement)
// Refuse (409) si l'event a au moins une réservation.
router.delete('/:id', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
  var eventId = req.params.id;

  pool.query('SELECT organizer_id FROM events WHERE id = $1', [eventId])
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Événement non trouvé' });
      }
      if (result.rows[0].organizer_id !== req.userId) {
        return res.status(403).json({ success: false, message: 'Cet événement ne vous appartient pas' });
      }

      return pool.query('SELECT COUNT(*) AS n FROM bookings WHERE event_id = $1', [eventId])
        .then(function(countResult) {
          var n = parseInt(countResult.rows[0].n) || 0;
          if (n > 0) {
            return res.status(409).json({
              success: false,
              message: 'Impossible de supprimer : ' + n + ' réservation(s) existante(s)'
            });
          }
          return pool.query('DELETE FROM events WHERE id = $1', [eventId])
            .then(function() {
              res.json({ success: true, message: 'Événement supprimé' });
            });
        });
    })
    .catch(function(err) {
      console.error('Erreur DELETE /events/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
