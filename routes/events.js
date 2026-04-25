// routes/events.js — CRUD des événements
// GET /events : liste publique, POST /events : création (organisateurs)

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');

// GET /events — Liste tous les événements
// @query {string} category - Filtrer par catégorie (optionnel)
// @query {string} search - Recherche texte (optionnel)
// @query {number} lat - Latitude utilisateur pour calcul de distance (optionnel)
// @query {number} lng - Longitude utilisateur (requis si lat fourni)
// @query {number} distance_km - Filtre par rayon en km (requiert lat+lng)
//
// Calcul de distance : formule de Haversine en SQL pur (rayon Terre 6371 km).
// Pas d'index spatial nécessaire (~50-200 events, full scan négligeable).
// Si distance_km fourni : exclut les events sans coords (latitude IS NULL),
// trie par distance ASC. Sinon : tri par défaut (chaud DESC, created_at DESC).
router.get('/', function(req, res) {
  var category = req.query.category;
  var search = req.query.search;
  var lat = req.query.lat !== undefined ? parseFloat(req.query.lat) : null;
  var lng = req.query.lng !== undefined ? parseFloat(req.query.lng) : null;
  var distanceKm = req.query.distance_km !== undefined ? parseFloat(req.query.distance_km) : null;

  var hasGeo = lat !== null && !isNaN(lat) && lng !== null && !isNaN(lng);
  var hasDistanceFilter = hasGeo && distanceKm !== null && !isNaN(distanceKm);

  var params = [];
  var distanceExpr = '';
  if (hasGeo) {
    params.push(lat); // $1
    params.push(lng); // $2
    // LEAST(1, GREATEST(-1, ...)) clampe pour éviter ACOS de valeurs hors [-1,1]
    // dues aux erreurs flottantes (ex: même point → cos*cos+sin*sin légèrement > 1)
    distanceExpr = '(6371 * acos(LEAST(1, GREATEST(-1, ' +
      'cos(radians($1)) * cos(radians(latitude)) * cos(radians(longitude) - radians($2)) + ' +
      'sin(radians($1)) * sin(radians(latitude))' +
      '))))';
  }

  var selectCols = 'id, title, description, category, date, lieu, prix, prix_display, ' +
    'emoji, color, chaud, image_url, places_total, places_restantes, latitude, longitude';
  if (hasGeo) selectCols += ', ' + distanceExpr + ' AS distance_km';

  var clauses = [];
  if (hasDistanceFilter) clauses.push('latitude IS NOT NULL AND longitude IS NOT NULL');
  if (category) {
    params.push(category);
    clauses.push('LOWER(category) = LOWER($' + params.length + ')');
  }
  if (search) {
    params.push('%' + search + '%');
    clauses.push('(LOWER(title) LIKE LOWER($' + params.length + ') OR LOWER(lieu) LIKE LOWER($' + params.length + '))');
  }

  var sql = 'SELECT ' + selectCols + ' FROM events';
  if (clauses.length > 0) sql += ' WHERE ' + clauses.join(' AND ');

  if (hasDistanceFilter) {
    // Sous-requête : Postgres n'autorise pas l'alias distance_km dans WHERE/ORDER BY direct
    params.push(distanceKm);
    sql = 'SELECT * FROM (' + sql + ') sub WHERE distance_km <= $' + params.length + ' ORDER BY distance_km ASC';
  } else {
    sql += ' ORDER BY chaud DESC, created_at DESC';
  }

  pool.query(sql, params)
    .then(function(result) {
      var events = result.rows.map(function(row) {
        var ev = {
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
          latitude: row.latitude !== null ? parseFloat(row.latitude) : null,
          longitude: row.longitude !== null ? parseFloat(row.longitude) : null
        };
        if (row.distance_km !== undefined && row.distance_km !== null) {
          ev.distance_km = parseFloat(row.distance_km);
        }
        return ev;
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
    'e.emoji, e.color, e.chaud, e.image_url, e.places_total, e.places_restantes, ' +
    'e.latitude, e.longitude, e.created_at, ' +
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
          latitude: row.latitude !== null ? parseFloat(row.latitude) : null,
          longitude: row.longitude !== null ? parseFloat(row.longitude) : null,
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
          latitude: row.latitude !== null ? parseFloat(row.latitude) : null,
          longitude: row.longitude !== null ? parseFloat(row.longitude) : null,
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
  var latitude = body.latitude !== undefined && body.latitude !== null && body.latitude !== ''
    ? parseFloat(body.latitude) : null;
  var longitude = body.longitude !== undefined && body.longitude !== null && body.longitude !== ''
    ? parseFloat(body.longitude) : null;
  if (latitude !== null && isNaN(latitude)) latitude = null;
  if (longitude !== null && isNaN(longitude)) longitude = null;

  pool.query(
    'INSERT INTO events (title, description, category, date, lieu, prix, prix_display, emoji, color, chaud, image_url, places_total, places_restantes, organizer_id, latitude, longitude) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, $13, $14, $15) RETURNING *',
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
      req.userId,
      latitude,
      longitude
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
          prix: row.prix_display,
          latitude: row.latitude !== null ? parseFloat(row.latitude) : null,
          longitude: row.longitude !== null ? parseFloat(row.longitude) : null
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

      // Coords optionnelles. Pour effacer une coord, le client doit envoyer null
      // explicitement (COALESCE garde l'ancienne si undefined → null côté JS).
      var latitude = null;
      if (body.latitude !== undefined && body.latitude !== null && body.latitude !== '') {
        var parsedLat = parseFloat(body.latitude);
        if (!isNaN(parsedLat)) latitude = parsedLat;
      }
      var longitude = null;
      if (body.longitude !== undefined && body.longitude !== null && body.longitude !== '') {
        var parsedLng = parseFloat(body.longitude);
        if (!isNaN(parsedLng)) longitude = parsedLng;
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
        'latitude = COALESCE($14, latitude), ' +
        'longitude = COALESCE($15, longitude), ' +
        'updated_at = NOW() ' +
        'WHERE id = $16 RETURNING *',
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
          latitude,
          longitude,
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
              places_restantes: row.places_restantes,
              latitude: row.latitude !== null ? parseFloat(row.latitude) : null,
              longitude: row.longitude !== null ? parseFloat(row.longitude) : null
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
