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

  // FOLLOW-01 : LEFT JOIN sur users pour exposer organisateur_id/prenom/nom au front
  // (utilisé par la card "Organisé par X" + bouton Suivre dans EventScreen).
  // LEFT JOIN car certains events legacy peuvent avoir organizer_id NULL.
  var selectCols = 'e.id, e.title, e.description, e.category, e.date, e.lieu, ' +
    'e.prix, e.prix_display, e.emoji, e.color, e.chaud, e.image_url, ' +
    'e.places_total, e.places_restantes, e.latitude, e.longitude, ' +
    'u.id AS organisateur_id, u.prenom AS organisateur_prenom, u.nom AS organisateur_nom';
  if (hasGeo) selectCols += ', ' + distanceExpr + ' AS distance_km';

  var clauses = [];
  // Catalogue public : ne montre que les events validés par modération admin.
  clauses.push("e.status = 'approved'");
  if (hasDistanceFilter) clauses.push('e.latitude IS NOT NULL AND e.longitude IS NOT NULL');
  if (category) {
    params.push(category);
    clauses.push('LOWER(e.category) = LOWER($' + params.length + ')');
  }
  if (search) {
    params.push('%' + search + '%');
    clauses.push('(LOWER(e.title) LIKE LOWER($' + params.length + ') OR LOWER(e.lieu) LIKE LOWER($' + params.length + '))');
  }

  var sql = 'SELECT ' + selectCols + ' FROM events e LEFT JOIN users u ON u.id = e.organizer_id';
  if (clauses.length > 0) sql += ' WHERE ' + clauses.join(' AND ');

  if (hasDistanceFilter) {
    // Sous-requête : Postgres n'autorise pas l'alias distance_km dans WHERE/ORDER BY direct
    params.push(distanceKm);
    sql = 'SELECT * FROM (' + sql + ') sub WHERE distance_km <= $' + params.length + ' ORDER BY distance_km ASC';
  } else {
    sql += ' ORDER BY e.chaud DESC, e.created_at DESC';
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
          longitude: row.longitude !== null ? parseFloat(row.longitude) : null,
          // Alias lat/lng pour cohérence avec /favorites et le client mobile
          // (MapScreen / EventMiniMap lisent event.lat / event.lng).
          lat: row.latitude !== null ? parseFloat(row.latitude) : null,
          lng: row.longitude !== null ? parseFloat(row.longitude) : null,
          organisateur_id: row.organisateur_id ? row.organisateur_id.toString() : null,
          organisateur_prenom: row.organisateur_prenom || null,
          organisateur_nom: row.organisateur_nom || null,
        };
        if (row.distance_km !== undefined && row.distance_km !== null) {
          ev.distance_km = parseFloat(row.distance_km);
        }
        return ev;
      });

      res.json({ success: true, events: events });
    })
    .catch(function(err) {
      console.error('Erreur GET /events:', err.message, '\n  code:', err && err.code);
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
  // decodeToken retourne null si invalide (pas d'exception), donc safe.
  // Wrapper try/catch supplémentaire au cas où une regression amenerait un throw.
  var userId = null;
  try {
    var authHeader = req.headers.authorization;
    if (authHeader && authHeader.indexOf('Bearer ') === 0) {
      userId = auth.decodeToken(authHeader.replace('Bearer ', ''));
    }
  } catch (decodeErr) {
    console.warn('GET /events/recommended : decodeToken throw (continuing as anonymous)', decodeErr.message);
    userId = null;
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
      // FOLLOW-01 : ajout JOIN users pour exposer organisateur_id/prenom/nom au front.
      var selectCols = 'e.id, e.title, e.description, e.category, e.date, e.lieu, ' +
        'e.prix, e.prix_display, e.emoji, e.color, e.chaud, e.image_url, ' +
        'e.places_total, e.places_restantes, e.latitude, e.longitude, ' +
        'u.id AS organisateur_id, u.prenom AS organisateur_prenom, u.nom AS organisateur_nom, ' +
        "(SELECT COUNT(*)::int FROM bookings b WHERE b.event_id = e.id " +
        "AND b.statut IN ('confirme', 'utilise')) AS popularity";

      var sql, params;
      if (prefCategories.length > 0) {
        // Personnalisé : on filtre par les catégories préférées.
        sql = 'SELECT ' + selectCols + ' FROM events e ' +
          'LEFT JOIN users u ON u.id = e.organizer_id ' +
          "WHERE e.status = 'approved' AND LOWER(e.category) = ANY($1::text[]) " +
          'ORDER BY e.chaud DESC, popularity DESC, e.created_at DESC LIMIT 20';
        params = [prefCategories.map(function(c) { return c.toLowerCase(); })];
      } else {
        // Anonyme ou sans préférences : top global.
        sql = 'SELECT ' + selectCols + ' FROM events e ' +
          'LEFT JOIN users u ON u.id = e.organizer_id ' +
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
          // Alias lat/lng pour cohérence avec /favorites et le client mobile
          // (MapScreen / EventMiniMap lisent event.lat / event.lng).
          lat: row.latitude !== null ? parseFloat(row.latitude) : null,
          lng: row.longitude !== null ? parseFloat(row.longitude) : null,
          organisateur_id: row.organisateur_id ? row.organisateur_id.toString() : null,
          organisateur_prenom: row.organisateur_prenom || null,
          organisateur_nom: row.organisateur_nom || null,
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
      // Log verbose (message + stack + SQL state si Postgres) pour pouvoir diagnostiquer
      // depuis les logs Render. Sentry capture aussi via setupExpressErrorHandler.
      console.error(
        'Erreur GET /events/recommended:',
        err && err.message,
        '\n  code:', err && err.code,
        '\n  stack:', err && err.stack
      );
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /events/mine — Liste les événements de l'organisateur connecté.
// Inclut aussi les events ou je suis dans event_staff (TEAM-01) avec un
// flag my_role ('owner' | 'scanner') pour que le front puisse adapter l'UI
// (cacher edit/finances pour scanner only).
//
// Permission : tout user authentifie (le scope est filtre par WHERE).
// On ne requiert plus role=organisateur global car les staff peuvent etre
// de simples participants.
router.get('/mine', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT e.id, e.title, e.description, e.category, e.date, e.lieu, e.prix, e.prix_display, ' +
    'e.emoji, e.color, e.chaud, e.image_url, e.places_total, e.places_restantes, ' +
    'e.latitude, e.longitude, e.created_at, e.status, e.rejection_reason, ' +
    '(e.places_total - e.places_restantes) AS places_vendues, ' +
    "COALESCE((SELECT SUM(total_amount) FROM bookings WHERE event_id = e.id AND statut = 'confirme'), 0) AS revenue, " +
    "CASE WHEN e.organizer_id = $1 THEN 'owner' ELSE 'scanner' END AS my_role " +
    'FROM events e WHERE e.organizer_id = $1 ' +
    'OR EXISTS (SELECT 1 FROM event_staff s WHERE s.event_id = e.id AND s.user_id = $1) ' +
    'ORDER BY e.created_at DESC',
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
          // Alias lat/lng pour cohérence avec /favorites et le client mobile
          // (MapScreen / EventMiniMap lisent event.lat / event.lng).
          lat: row.latitude !== null ? parseFloat(row.latitude) : null,
          lng: row.longitude !== null ? parseFloat(row.longitude) : null,
          places_vendues: row.places_vendues,
          revenue: parseInt(row.revenue) || 0,
          status: row.status,
          rejection_reason: row.rejection_reason,
          created_at: row.created_at,
          my_role: row.my_role,
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
      'sales_close_at, lieu, prix, prix_display, emoji, color, chaud, image_url, ' +
      'commission_rate, places_total, places_restantes, status, rejection_reason, created_at ' +
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
    // UX audit P0#6 : recupere les taux de commission et frais CinetPay pour
    // calculer le revenu net reel cote backend (la verite). Per-event override
    // sur events.commission_rate prevaut sur le defaut global.
    pool.query("SELECT key, value FROM app_settings WHERE key IN ('commission_rate', 'cinetpay_fee_rate')"),
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
      // P0#6 : taux effectifs. Per-event override sur ev.commission_rate prend
      // precedence sur la valeur globale d'app_settings.
      var settingsMap = {};
      results[2].rows.forEach(function(r) { settingsMap[r.key] = parseFloat(r.value); });
      var globalCommissionRate = isNaN(settingsMap.commission_rate) ? 0.06 : settingsMap.commission_rate;
      var cinetpayFeeRate = isNaN(settingsMap.cinetpay_fee_rate) ? 0.015 : settingsMap.cinetpay_fee_rate;
      var effectiveCommissionRate = (ev.commission_rate !== null && ev.commission_rate !== undefined)
        ? parseFloat(ev.commission_rate)
        : globalCommissionRate;

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
        // P0#6 : deductions explicites pour transparence B2B
        commission_rate: effectiveCommissionRate,
        cinetpay_fee_rate: cinetpayFeeRate,
        commission_total: 0,      // commission Akwaba sur revenue_brut
        cinetpay_fees_total: 0,   // frais CinetPay sur revenue_brut
        revenue_net: 0,           // revenue_brut - commission - cinetpay - refunds
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
      // Calculs deductions arrondis a l'entier (FCFA n'a pas de centimes)
      stats.commission_total = Math.round(stats.revenue_brut * effectiveCommissionRate);
      stats.cinetpay_fees_total = Math.round(stats.revenue_brut * cinetpayFeeRate);
      stats.revenue_net = stats.revenue_brut - stats.commission_total - stats.cinetpay_fees_total - stats.refund_total;

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
          sales_close_at: ev.sales_close_at,
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

// GET /events/:id — Détail d'un événement (avec orga via LEFT JOIN, FOLLOW-01)
router.get('/:id', function(req, res) {
  pool.query(
    'SELECT e.*, u.id AS organisateur_id, u.prenom AS organisateur_prenom, u.nom AS organisateur_nom ' +
    'FROM events e LEFT JOIN users u ON u.id = e.organizer_id WHERE e.id = $1',
    [req.params.id]
  )
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
          // Alias lat/lng pour cohérence avec /favorites et le client mobile
          // (MapScreen / EventMiniMap lisent event.lat / event.lng).
          lat: row.latitude !== null ? parseFloat(row.latitude) : null,
          lng: row.longitude !== null ? parseFloat(row.longitude) : null,
          organizer_id: row.organizer_id,
          organisateur_id: row.organisateur_id ? row.organisateur_id.toString() : null,
          organisateur_prenom: row.organisateur_prenom || null,
          organisateur_nom: row.organisateur_nom || null,
        }
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /events/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /events/upload-signature — Signature Cloudinary pour upload direct
// d'IMAGE ou VIDÉO par un organisateur. Le fichier va direct chez Cloudinary
// (économise bandwidth Render). Auth orga obligatoire.
// @body {string} type - 'image' (défaut) ou 'video'
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

  // type=video → resource_type=video chez Cloudinary, sinon image (défaut).
  var isVideo = req.body.type === 'video';
  var resourceType = isVideo ? 'video' : 'image';
  // Folder organisé par orga + type pour cleanup futur facile.
  var folder = 'akwaba/events/' + req.userId + (isVideo ? '/videos' : '');
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
    resource_type: resourceType,
    upload_url: 'https://api.cloudinary.com/v1_1/' + cloudName + '/' + resourceType + '/upload',
  });
});

// POST /events — Créer un événement (organisateurs uniquement)
// @body {string} title, description, category, date, lieu, prix, emoji, color, image_url
router.post('/', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
  var body = req.body;

  // ADM-KYC : bloque la création si l'orga n'a pas son KYC validé. Les orgas
  // grandfathered (existants avant la migration) sont déjà 'approved'.
  // Les nouveaux organisateurs partent de 'none' et doivent soumettre.
  if (req.user.kyc_status && req.user.kyc_status !== 'approved') {
    return res.status(403).json({
      success: false,
      code: 'kyc_required',
      kyc_status: req.user.kyc_status,
      message: req.user.kyc_status === 'pending'
        ? 'Vérification KYC en cours de review. Création d\'event bloquée le temps de la validation.'
        : req.user.kyc_status === 'rejected'
          ? 'Vérification KYC rejetée. Re-soumets tes documents.'
          : 'Vérification KYC requise avant de créer un event. Contacte le support.',
    });
  }

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
  // UX audit orga P0#5 : refuser une date dans le passé (form + sécurité backend).
  // Tolérance 5 min pour absorber le délai entre saisie et POST (horloges, latence).
  var startAt = null;
  if (body.start_at) {
    var d = new Date(body.start_at);
    if (!isNaN(d.getTime())) {
      if (d.getTime() < Date.now() - 5 * 60 * 1000) {
        return res.status(400).json({
          success: false,
          code: 'start_at_in_past',
          message: 'La date de l\'événement doit être dans le futur.',
        });
      }
      startAt = d;
    }
  }
  var endAt = null;
  if (body.end_at) {
    var de = new Date(body.end_at);
    if (!isNaN(de.getTime())) {
      if (startAt && de.getTime() <= startAt.getTime()) {
        return res.status(400).json({
          success: false,
          code: 'end_at_before_start',
          message: 'La date de fin doit être après la date de début.',
        });
      }
      endAt = de;
    }
  }
  // P1#10 audit orga : sales_close_at. Doit etre > now() et < start_at (sinon
  // pas de sens : on ne ferme pas la billetterie apres la fin de l'event ni
  // avant maintenant). Tolerance 5 min.
  var salesCloseAt = null;
  if (body.sales_close_at) {
    var dsc = new Date(body.sales_close_at);
    if (!isNaN(dsc.getTime())) {
      if (dsc.getTime() < Date.now() - 5 * 60 * 1000) {
        return res.status(400).json({
          success: false,
          code: 'sales_close_in_past',
          message: 'La date de fermeture des ventes doit être dans le futur.',
        });
      }
      if (startAt && dsc.getTime() > startAt.getTime() + 5 * 60 * 1000) {
        return res.status(400).json({
          success: false,
          code: 'sales_close_after_start',
          message: 'La fermeture des ventes doit être avant le début de l\'événement.',
        });
      }
      salesCloseAt = dsc;
    }
  }

  // EVENT-VIDEO : whitelist Cloudinary tenant pour video_url (anti XSS).
  var videoUrl = null;
  if (body.video_url) {
    var rawUrl = String(body.video_url).trim();
    var cloud = process.env.CLOUDINARY_CLOUD_NAME || '';
    var allowedPrefix = cloud ? 'https://res.cloudinary.com/' + cloud + '/' : null;
    if (allowedPrefix && rawUrl.indexOf(allowedPrefix) === 0 && rawUrl.length <= 500) {
      videoUrl = rawUrl;
    } else {
      return res.status(400).json({
        success: false,
        message: 'video_url doit être une URL Cloudinary du tenant Akwaba.',
      });
    }
  }

  pool.query(
    'INSERT INTO events (title, description, category, date, lieu, prix, prix_display, emoji, color, chaud, image_url, video_url, places_total, places_restantes, organizer_id, latitude, longitude, start_at, end_at, sales_close_at) ' +
    'VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13, $14, $15, $16, $17, $18, $19) RETURNING *',
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
      videoUrl,
      placesTotal,
      req.userId,
      latitude,
      longitude,
      startAt,
      endAt,
      salesCloseAt
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
          // Alias lat/lng pour cohérence avec /favorites et le client mobile
          // (MapScreen / EventMiniMap lisent event.lat / event.lng).
          lat: row.latitude !== null ? parseFloat(row.latitude) : null,
          lng: row.longitude !== null ? parseFloat(row.longitude) : null,
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
      // UX audit orga P0#5 : meme validation que POST — refuser date passee.
      // Tolerance speciale en edit : si l'event a deja eu lieu, on ne re-bloque pas
      // (l'orga peut vouloir corriger un titre/description sur un event passe).
      // On bloque uniquement quand l'orga essaie de DEPLACER vers le passe.
      var newStartAt = null;
      if (body.start_at) {
        var ds = new Date(body.start_at);
        if (!isNaN(ds.getTime())) {
          if (ds.getTime() < Date.now() - 5 * 60 * 1000) {
            return res.status(400).json({
              success: false,
              code: 'start_at_in_past',
              message: 'La date de l\'événement doit être dans le futur.',
            });
          }
          newStartAt = ds;
        }
      }
      var newEndAt = null;
      if (body.end_at) {
        var dee = new Date(body.end_at);
        if (!isNaN(dee.getTime())) {
          if (newStartAt && dee.getTime() <= newStartAt.getTime()) {
            return res.status(400).json({
              success: false,
              code: 'end_at_before_start',
              message: 'La date de fin doit être après la date de début.',
            });
          }
          newEndAt = dee;
        }
      }
      // P1#10 audit orga : sales_close_at edit. Meme validation que POST.
      // null explicite = clear, undefined = no change (COALESCE).
      var newSalesCloseAt = undefined;
      if (body.sales_close_at === null || body.sales_close_at === '') {
        newSalesCloseAt = null; // clear
      } else if (body.sales_close_at !== undefined) {
        var dscu = new Date(body.sales_close_at);
        if (!isNaN(dscu.getTime())) {
          if (dscu.getTime() < Date.now() - 5 * 60 * 1000) {
            return res.status(400).json({
              success: false,
              code: 'sales_close_in_past',
              message: 'La date de fermeture des ventes doit être dans le futur.',
            });
          }
          if (newStartAt && dscu.getTime() > newStartAt.getTime() + 5 * 60 * 1000) {
            return res.status(400).json({
              success: false,
              code: 'sales_close_after_start',
              message: 'La fermeture des ventes doit être avant le début de l\'événement.',
            });
          }
          newSalesCloseAt = dscu;
        }
      }

      // EVENT-VIDEO : valide video_url contre tenant Cloudinary.
      // undefined → COALESCE garde l'ancienne valeur.
      // null explicite → vide la vidéo.
      // string → doit être Cloudinary du tenant.
      var newVideoUrl = undefined;
      if (body.video_url === null || body.video_url === '') {
        newVideoUrl = null; // clear
      } else if (body.video_url !== undefined) {
        var rawV = String(body.video_url).trim();
        var cloudV = process.env.CLOUDINARY_CLOUD_NAME || '';
        var allowedV = cloudV ? 'https://res.cloudinary.com/' + cloudV + '/' : null;
        if (allowedV && rawV.indexOf(allowedV) === 0 && rawV.length <= 500) {
          newVideoUrl = rawV;
        } else {
          return res.status(400).json({
            success: false,
            message: 'video_url doit être une URL Cloudinary du tenant Akwaba.',
          });
        }
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
        'video_url = CASE WHEN $18::boolean THEN $19 ELSE video_url END, ' +
        'places_total = COALESCE($12, places_total), ' +
        'places_restantes = COALESCE($13, places_restantes), ' +
        'latitude = COALESCE($14, latitude), ' +
        'longitude = COALESCE($15, longitude), ' +
        'start_at = COALESCE($16, start_at), ' +
        'end_at = COALESCE($17, end_at), ' +
        'sales_close_at = CASE WHEN $21::boolean THEN $22 ELSE sales_close_at END, ' +
        'updated_at = NOW() ' +
        'WHERE id = $20 RETURNING *',
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
          newVideoUrl !== undefined,  // $18 — flag : faut-il toucher video_url ?
          newVideoUrl,                // $19 — la nouvelle valeur (null ou string)
          eventId,
          newSalesCloseAt !== undefined,  // $21 — flag : faut-il toucher sales_close_at ?
          newSalesCloseAt                  // $22 — la nouvelle valeur (null ou Date)
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
              longitude: row.longitude !== null ? parseFloat(row.longitude) : null,
              // Alias lat/lng pour cohérence avec /favorites + client mobile.
              lat: row.latitude !== null ? parseFloat(row.latitude) : null,
              lng: row.longitude !== null ? parseFloat(row.longitude) : null
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

// ============================================================
// ADM-SEARCH-LOG : Log des recherches users (signal acquisition)
// ============================================================
// POST /events/search-log — Le mobile log chaque search (typiquement quand
// result_count est connu après l'appel /events?search=). On garde tout, le
// front filtrera par result_count=0 côté admin pour identifier les requêtes
// non satisfaites.
// @body {string} query, {number} result_count
router.post('/search-log', function(req, res) {
  var query = (req.body.query || '').trim();
  var resultCount = parseInt(req.body.result_count);
  if (!query || query.length > 200 || isNaN(resultCount)) {
    return res.status(400).json({ success: false, message: 'query + result_count requis' });
  }

  // user_id optionnel — si Authorization header présent, on attache l'user.
  // Sinon log anonyme (user_id NULL).
  var userId = null;
  var authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    var auth = require('../middleware/auth');
    userId = auth.decodeToken(authHeader.replace('Bearer ', ''));
  }

  pool.query(
    'INSERT INTO search_queries (query, user_id, result_count) VALUES ($1, $2, $3)',
    [query.slice(0, 200), userId, resultCount]
  )
    .then(function() {
      res.json({ success: true });
    })
    .catch(function(err) {
      console.error('Erreur POST /events/search-log:', err.message);
      // Silent fail — un log raté ne doit pas casser le front.
      res.json({ success: false });
    });
});

module.exports = router;
