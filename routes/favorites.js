// routes/favorites.js — Favoris utilisateur (FAV-01)
//
// Un user peut bookmarker des events pour les retrouver dans l'onglet "Favoris"
// de l'app mobile. Pas de visibilité publique : seuls les events favoris du user
// connecté sont retournés.

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');

// GET /favorites — Liste des events favoris du user connecté.
// Renvoie les events complets (mêmes colonnes que GET /events) pour que le front
// puisse rendre les EventCard sans appel additionnel. Triés du plus récent ajouté
// au plus ancien.
router.get('/', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT e.id, e.title, e.description, e.category, e.date, e.lieu, ' +
    'e.prix, e.prix_display, e.emoji, e.color, e.chaud, e.image_url, ' +
    'e.places_total, e.places_restantes, e.latitude AS lat, e.longitude AS lng, ' +
    'f.created_at AS favorited_at ' +
    'FROM favorites f ' +
    'JOIN events e ON e.id = f.event_id ' +
    'WHERE f.user_id = $1 AND e.status != \'rejected\' ' +
    'ORDER BY f.created_at DESC',
    [req.userId]
  )
    .then(function(result) {
      // Format `prix` aligné avec GET /events : le front attend la chaîne formatée
      // (event.prix), pas le nombre brut. On utilise prix_display si présent.
      var events = result.rows.map(function(e) {
        return {
          id: e.id.toString(),
          title: e.title,
          description: e.description,
          category: e.category,
          date: e.date,
          lieu: e.lieu,
          prix: e.prix_display || (e.prix === 0 ? 'Gratuit' : e.prix + ' F'),
          emoji: e.emoji,
          color: e.color,
          chaud: e.chaud,
          image_url: e.image_url,
          places_total: e.places_total,
          places_restantes: e.places_restantes,
          lat: e.lat != null ? Number(e.lat) : null,
          lng: e.lng != null ? Number(e.lng) : null,
          favorited_at: e.favorited_at,
        };
      });
      res.json({ success: true, events: events });
    })
    .catch(function(err) {
      console.error('Erreur GET /favorites:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /favorites/ids — Juste les IDs favoris du user connecté.
// Utile pour annoter rapidement EventCard sur la home sans charger les events
// complets (le front a déjà la liste via GET /events).
router.get('/ids', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT event_id FROM favorites WHERE user_id = $1',
    [req.userId]
  )
    .then(function(result) {
      var ids = result.rows.map(function(r) { return r.event_id.toString(); });
      res.json({ success: true, ids: ids });
    })
    .catch(function(err) {
      console.error('Erreur GET /favorites/ids:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /favorites/:eventId — Ajoute un favori. Idempotent (ON CONFLICT DO NOTHING).
// Renvoie 200 même si déjà en favori.
router.post('/:eventId', auth.authMiddleware, function(req, res) {
  var eventId = parseInt(req.params.eventId, 10);
  if (isNaN(eventId)) {
    return res.status(400).json({ success: false, message: 'eventId invalide' });
  }
  // Vérifie que l'event existe avant d'insérer (évite un FK error qui retourne 500).
  pool.query('SELECT id FROM events WHERE id = $1', [eventId])
    .then(function(eventCheck) {
      if (eventCheck.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Événement introuvable' });
      }
      return pool.query(
        'INSERT INTO favorites (user_id, event_id) VALUES ($1, $2) ' +
        'ON CONFLICT (user_id, event_id) DO NOTHING ' +
        'RETURNING created_at',
        [req.userId, eventId]
      ).then(function(insertResult) {
        var alreadyExisted = insertResult.rows.length === 0;
        res.json({
          success: true,
          favorite: {
            event_id: eventId.toString(),
            already_existed: alreadyExisted,
          },
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /favorites/:eventId:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// DELETE /favorites/:eventId — Retire un favori. Idempotent (200 même si pas en favori).
router.delete('/:eventId', auth.authMiddleware, function(req, res) {
  var eventId = parseInt(req.params.eventId, 10);
  if (isNaN(eventId)) {
    return res.status(400).json({ success: false, message: 'eventId invalide' });
  }
  pool.query(
    'DELETE FROM favorites WHERE user_id = $1 AND event_id = $2',
    [req.userId, eventId]
  )
    .then(function(result) {
      res.json({ success: true, removed: result.rowCount > 0 });
    })
    .catch(function(err) {
      console.error('Erreur DELETE /favorites/:eventId:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
