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
  // Catalogue public : ne montre que les events validés par modération admin.
  clauses.push("status = 'approved'");
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

// GET /events/recommended — Liste personnalisée "Pour toi" (REC-01 v1 stub).
//
// V1 stub : pas de vraie ML, juste un mix popularité (nb de bookings confirmés)
// + signal "chaud" (mis à la main par les orgas) + filtre par catégories
// préférées si le user en a définies dans /auth/me/preferences.
//
// Auth optionnelle : si token présent on lit les préférences pour personnaliser,
// sinon on retourne le top global. Pas d'erreur 401 pour un anonyme.
//
// V2 (besoin de volume) : score basé sur les events vus, billets achetés,
// événements similaires aux favoris, etc.
router.get('/recommended', function(req, res) {
  // Auth optionnelle : lecture du token si présent, mais on accepte les anonymes.
  var userId = null;
  var authHeader = req.headers.authorization;
  if (authHeader && authHeader.indexOf('Bearer ') === 0) {
    userId = auth.decodeToken(authHeader.replace('Bearer ', ''));
  }

  var prefCategories = []; // partagé via closure entre les deux .then

  var prefPromise = userId
    ? pool.query('SELECT preferences FROM users WHERE id = $1', [userId])
    : Promise.resolve({ rows: [] });

  prefPromise
    .then(function(userResult) {
      if (userResult.rows.length > 0) {
        var prefs = userResult.rows[0].preferences || {};
        if (Array.isArray(prefs.categories)) {
          prefCategories = prefs.categories.filter(function(c) {
            return typeof c === 'string' && c.length > 0;
          });
        }
      }

      // Popularity = nb de bookings actifs (confirmés ou déjà utilisés).
      // Sous-requête plutôt que JOIN/GROUP BY pour éviter les bookings sans event.
      var selectCols = 'e.id, e.title, e.description, e.category, e.date, e.lieu, ' +
        'e.prix, e.prix_display, e.emoji, e.color, e.chaud, e.image_url, ' +
        'e.places_total, e.places_restantes, e.latitude, e.longitude, ' +
        "(SELECT COUNT(*)::int FROM bookings b WHERE b.event_id = e.id " +
        "AND b.statut IN ('confirme', 'utilise')) AS popularity";

      var sql, params;
      if (prefCategories.length > 0) {
        // Personnalisé : on filtre par les catégories préférées.
        sql = 'SELECT ' + selectCols + ' FROM events e ' +
          "WHERE e.status = 'approved' AND LOWER(e.category) = ANY($1::text[]) " +
          'ORDER BY e.chaud DESC, popularity DESC, e.created_at DESC LIMIT 20';
        params = [prefCategories.map(function(c) { return c.toLowerCase(); })];
      } else {
        // Anonyme ou sans préférences : top global.
        sql = 'SELECT ' + selectCols + ' FROM events e ' +
          "WHERE e.status = 'approved' " +
          'ORDER BY e.chaud DESC, popularity DESC, e.created_at DESC LIMIT 20';
        params = [];
      }

      return pool.query(sql, params);
    })
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
          popularity: row.popularity || 0,
        };
      });
      res.json({
        success: true,
        events: events,
        personalized: prefCategories.length > 0,
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /events/recommended:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /events/mine — Liste les événements créés par l'organisateur connecté
// Inclut places_vendues (places_total - places_restantes) et revenue (somme des bookings 'confirme').
router.get('/mine', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
  pool.query(
    'SELECT e.id, e.title, e.description, e.category, e.date, e.lieu, e.prix, e.prix_display, ' +
    'e.emoji, e.color, e.chaud, e.image_url, e.places_total, e.places_restantes, ' +
    'e.latitude, e.longitude, e.created_at, e.status, e.rejection_reason, ' +
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
          status: row.status,
          rejection_reason: row.rejection_reason,
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

// GET /events/:id/dashboard — Tableau de bord d'un événement pour son orga.
// Retourne : event + stats + liste détaillée des bookings (user, statut, scan).
// Permission : orga propriétaire uniquement.
router.get('/:id/dashboard', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
  var eventId = req.params.id;

  Promise.all([
    pool.query(
      'SELECT id, organizer_id, title, description, category, date, start_at, end_at, ' +
      'lieu, prix, prix_display, emoji, color, chaud, image_url, ' +
      'places_total, places_restantes, status, rejection_reason, created_at ' +
      'FROM events WHERE id = $1',
      [eventId]
    ),
    pool.query(
      'SELECT b.id, b.ref, b.quantity, b.total_amount, b.statut, b.created_at, ' +
      'b.utilise_at, b.cancelled_at, b.refund_amount, ' +
      'u.id AS user_id, u.nom, u.prenom, u.phone ' +
      'FROM bookings b LEFT JOIN users u ON u.id = b.user_id ' +
      'WHERE b.event_id = $1 ORDER BY b.created_at DESC',
      [eventId]
    ),
  ])
    .then(function(results) {
      if (results[0].rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Événement non trouvé' });
      }
      var ev = results[0].rows[0];
      if (ev.organizer_id !== req.userId) {
        return res.status(403).json({
          success: false,
          message: 'Cet événement ne vous appartient pas',
        });
      }

      var bookings = results[1].rows;
      var stats = {
        bookings_total: bookings.length,
        bookings_confirme: 0,
        bookings_attente: 0,
        bookings_annule: 0,
        bookings_utilise: 0,
        billets_vendus: 0,        // sum quantity confirmed (=places vendues)
        revenue_brut: 0,          // sum total_amount confirmed
        billets_scannes: 0,       // sum quantity used
        refund_total: 0,          // sum refund_amount on cancelled
      };
      bookings.forEach(function(b) {
        if (b.statut === 'confirme') {
          stats.bookings_confirme++;
          stats.billets_vendus += b.quantity;
          stats.revenue_brut += parseInt(b.total_amount) || 0;
        } else if (b.statut === 'en_attente') {
          stats.bookings_attente++;
        } else if (b.statut === 'utilise') {
          stats.bookings_utilise++;
          stats.billets_scannes += b.quantity;
          stats.billets_vendus += b.quantity;          // utilise inclut "vendu et scanné"
          stats.revenue_brut += parseInt(b.total_amount) || 0;
        } else if (b.statut === 'annule') {
          stats.bookings_annule++;
          stats.refund_total += parseInt(b.refund_amount) || 0;
        }
      });

      res.json({
        success: true,
        event: {
          id: ev.id.toString(),
          title: ev.title,
          description: ev.description,
          category: ev.category,
          date: ev.date,
          start_at: ev.start_at,
          end_at: ev.end_at,
          lieu: ev.lieu,
          prix: ev.prix_display,
          prix_num: ev.prix,
          emoji: ev.emoji,
          color: ev.color,
          chaud: ev.chaud,
          image_url: ev.image_url,
          places_total: ev.places_total,
          places_restantes: ev.places_restantes,
          status: ev.status,
          rejection_reason: ev.rejection_reason,
          created_at: ev.created_at,
        },
        stats: stats,
        bookings: bookings.map(function(b) {
          return {
            id: b.id.toString(),
            ref: b.ref,
            quantity: b.quantity,
            total_amount: parseInt(b.total_amount) || 0,
            statut: b.statut,
            created_at: b.created_at,
            utilise_at: b.utilise_at,
            cancelled_at: b.cancelled_at,
            refund_amount: b.refund_amount != null ? parseInt(b.refund_amount) : null,
            user: b.user_id ? {
              id: b.user_id.toString(),
              nom: b.nom,
              prenom: b.prenom,
              phone: b.phone,
            } : null,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /events/:id/dashboard:', err.message);
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

// POST /events/upload-signature — Génère une signature Cloudinary pour upload direct
// par un organisateur depuis l'app mobile. Le fichier va direct chez Cloudinary,
// pas par notre backend (économise bandwidth Render). Auth orga obligatoire.
router.post('/upload-signature', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
  var crypto = require('crypto');
  var apiKey = process.env.CLOUDINARY_API_KEY;
  var apiSecret = process.env.CLOUDINARY_API_SECRET;
  var cloudName = process.env.CLOUDINARY_CLOUD_NAME;

  if (!apiKey || !apiSecret || !cloudName) {
    return res.status(503).json({
      success: false,
      message: 'Cloudinary non configuré côté serveur',
    });
  }

  // Folder organisé par orga pour faciliter les permissions/cleanup futurs.
  var folder = 'akwaba/events/' + req.userId;
  var timestamp = Math.floor(Date.now() / 1000);
  var paramsToSign = 'folder=' + folder + '&timestamp=' + timestamp;
  var signature = crypto.createHash('sha1').update(paramsToSign + apiSecret).digest('hex');

  res.json({
    success: true,
    signature: signature,
    timestamp: timestamp,
    api_key: apiKey,
    cloud_name: cloudName,
    folder: folder,
    upload_url: 'https://api.cloudinary.com/v1_1/' + cloudName + '/image/upload',
  });
});

// POST /events — Créer un événement (organisateurs uniquement)
// @body {string} title, description, category, date, lieu, prix, emoji, color, image_url
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

  // start_at / end_at (TIMESTAMP) : nécessaires pour les calculs J+2 escrow,
  // refund 48h/24h, et rappels push. Optionnels — la string `date` reste affichée.
  var startAt = null;
  if (body.start_at) {
    var d = new Date(body.start_at);
    if (!isNaN(d.getTime())) startAt = d;
  }
  var endAt = null;
  if (body.end_at) {
    var de = new Date(body.end_at);
    if (!isNaN(de.getTime())) endAt = de;
  }

  pool.query(
    'INSERT INTO events (title, description, category, date, lieu, prix, prix_display, emoji, color, chaud, image_url, places_total, places_restantes, organizer_id, latitude, longitude, start_at, end_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, $13, $14, $15, $16, $17) RETURNING *',
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
      longitude,
      startAt,
      endAt
    ]
  )
    .then(function(result) {
      var row = result.rows[0];
      res.status(201).json({
        success: true,
        message: 'Événement créé. En attente de validation par notre équipe.',
        event: {
          id: row.id.toString(),
          title: row.title,
          category: row.category,
          date: row.date,
          lieu: row.lieu,
          prix: row.prix_display,
          latitude: row.latitude !== null ? parseFloat(row.latitude) : null,
          longitude: row.longitude !== null ? parseFloat(row.longitude) : null,
          status: row.status
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

      // Parse start_at / end_at si fournis (sinon COALESCE garde l'ancienne valeur).
      var newStartAt = null;
      if (body.start_at) {
        var ds = new Date(body.start_at);
        if (!isNaN(ds.getTime())) newStartAt = ds;
      }
      var newEndAt = null;
      if (body.end_at) {
        var dee = new Date(body.end_at);
        if (!isNaN(dee.getTime())) newEndAt = dee;
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
        'start_at = COALESCE($16, start_at), ' +
        'end_at = COALESCE($17, end_at), ' +
        'updated_at = NOW() ' +
        'WHERE id = $18 RETURNING *',
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
          newStartAt,
          newEndAt,
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
