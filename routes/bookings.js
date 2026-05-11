// routes/bookings.js — Gestion des réservations / billets
// POST /bookings : créer une réservation, GET /bookings : mes billets

var express = require('express');
var router = express.Router();
var crypto = require('crypto');
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var push = require('../services/push');
var qr = require('../services/qr');
var cinetpay = require('../services/cinetpay');
var waitlistRouter = require('./waitlist');

// Envoie les notifications "billet confirmé" au participant et à l'organisateur.
// Appelé après qu'un booking passe en statut 'confirme'. N'attend pas le résultat
// (fire-and-forget) pour ne pas ralentir la réponse HTTP.
// @param {number|string} bookingId
function notifyBookingConfirmed(bookingId) {
  pool.query(
    'SELECT b.id, b.ref, b.quantity, b.total_amount, b.user_id, ' +
    'e.id AS event_id, e.title, e.organizer_id ' +
    'FROM bookings b JOIN events e ON b.event_id = e.id WHERE b.id = $1',
    [bookingId]
  )
    .then(function(result) {
      if (result.rows.length === 0) return;
      var b = result.rows[0];

      // Notif au participant
      push.notifyUser(b.user_id, {
        title: 'Billet confirmé 🎟️',
        body: '« ' + b.title + ' » — réf ' + b.ref + (b.quantity > 1 ? ' (' + b.quantity + ' places)' : ''),
        data: { type: 'booking_confirmed', bookingId: b.id.toString(), eventId: b.event_id.toString() }
      });

      // Notif à l'organisateur (si différent du participant)
      if (b.organizer_id && b.organizer_id !== b.user_id) {
        push.notifyUser(b.organizer_id, {
          title: 'Nouvelle vente 💰',
          body: b.quantity + ' billet' + (b.quantity > 1 ? 's' : '') + ' vendu' + (b.quantity > 1 ? 's' : '') + ' sur « ' + b.title + ' »',
          data: { type: 'sale', bookingId: b.id.toString(), eventId: b.event_id.toString() }
        });
      }
    })
    .catch(function(err) {
      console.error('Erreur notifyBookingConfirmed:', err.message);
    });
}

// Génère une référence unique pour le billet
// @returns {string} Référence au format AKW-XXXXXXXX
function generateRef() {
  return 'AKW-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

// POST /bookings — Créer une réservation
// @body {number} eventId, {string} paiement, {number} quantity
router.post('/', auth.authMiddleware, function(req, res) {
  var eventId = req.body.eventId;
  var paiement = req.body.paiement;
  var quantity = parseInt(req.body.quantity) || 1;

  if (!eventId) {
    return res.status(400).json({
      success: false,
      message: 'eventId est obligatoire'
    });
  }

  // Récupère l'événement pour vérifier les places et le prix
  pool.query('SELECT id, title, prix, prix_display, places_restantes FROM events WHERE id = $1', [eventId])
    .then(function(eventResult) {
      if (eventResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Événement non trouvé'
        });
      }

      var event = eventResult.rows[0];

      if (event.places_restantes < quantity) {
        return res.status(400).json({
          success: false,
          message: 'Plus assez de places disponibles'
        });
      }

      var ref = generateRef();
      var totalAmount = event.prix * quantity;

      // Crée la réservation en 'en_attente' (transaction_id = ref pour le tracking CinetPay)
      return pool.query(
        "INSERT INTO bookings (user_id, event_id, ref, quantity, total_amount, paiement_method, statut, transaction_id) " +
        "VALUES ($1, $2, $3, $4, $5, $6, 'en_attente', $3) RETURNING *",
        [req.userId, eventId, ref, quantity, totalAmount, paiement]
      )
        .then(function(bookingResult) {
          var booking = bookingResult.rows[0];

          // Décrémente les places restantes (soft-lock — sera relâché si paiement échoue
          // via le job de réconciliation cinetpay)
          return pool.query(
            'UPDATE events SET places_restantes = places_restantes - $1 WHERE id = $2',
            [quantity, eventId]
          )
            .then(function() {
              // Récupère les infos user pour CinetPay
              return pool.query('SELECT id, nom, prenom, phone FROM users WHERE id = $1', [req.userId]);
            })
            .then(function(userResult) {
              var user = userResult.rows[0] || {};

              // Mode MOCK_PAYMENTS=true : on bypass CinetPay et on confirme direct.
              // Utile en phase test avant que les credentials CinetPay merchant soient
              // disponibles. À DÉSACTIVER en prod (sinon les billets sont confirmés
              // sans débit réel).
              var isMockMode = process.env.MOCK_PAYMENTS === 'true';

              // Si l'event est gratuit (prix = 0) OU si on est en mock mode, confirme
              // directement sans appeler CinetPay.
              if (totalAmount === 0 || isMockMode) {
                return pool.query(
                  "UPDATE bookings SET statut = 'confirme', updated_at = NOW() WHERE id = $1 RETURNING id",
                  [booking.id]
                ).then(function() {
                  notifyBookingConfirmed(booking.id);
                  return res.status(201).json({
                    success: true,
                    message: isMockMode
                      ? 'Réservation confirmée (MODE MOCK — aucun paiement réel)'
                      : 'Réservation gratuite confirmée',
                    booking: {
                      id: booking.id.toString(),
                      eventId: booking.event_id.toString(),
                      ref: booking.ref,
                      qr_payload: qr.signRef(booking.ref),
                      quantity: booking.quantity,
                      total_amount: totalAmount,
                      paiement: isMockMode ? 'mock' : 'gratuit',
                      statut: 'confirme',
                      payment_url: null,
                      mock: isMockMode || undefined,
                      createdAt: booking.created_at
                    }
                  });
                });
              }

              // Initie le paiement CinetPay et récupère l'URL à ouvrir côté mobile.
              return cinetpay.initPayment({
                ref: ref,
                amount: totalAmount,
                description: '« ' + event.title + ' » · ' + quantity + ' billet' + (quantity > 1 ? 's' : ''),
                customer: {
                  id: user.id,
                  name: user.nom,
                  surname: user.prenom,
                  phone: user.phone,
                },
                channels: paiement === 'card' ? 'CREDIT_CARD' : 'ALL',
              })
                .then(function(initResult) {
                  if (!initResult.ok) {
                    // Init CinetPay a échoué : on annule le booking et on relâche les places.
                    console.error('CinetPay init échoué pour', ref, ':', initResult.raw);
                    return pool.query(
                      "UPDATE bookings SET statut = 'annule', updated_at = NOW() WHERE id = $1",
                      [booking.id]
                    )
                      .then(function() {
                        return pool.query(
                          'UPDATE events SET places_restantes = places_restantes + $1 WHERE id = $2',
                          [quantity, eventId]
                        );
                      })
                      .then(function() {
                        res.status(502).json({
                          success: false,
                          message: 'Initialisation du paiement impossible. Réessayez plus tard.',
                        });
                      });
                  }

                  res.status(201).json({
                    success: true,
                    message: 'Réservation créée, redirection vers le paiement',
                    booking: {
                      id: booking.id.toString(),
                      eventId: booking.event_id.toString(),
                      ref: booking.ref,
                      qr_payload: qr.signRef(booking.ref),
                      quantity: booking.quantity,
                      total_amount: totalAmount,
                      paiement: booking.paiement_method,
                      statut: booking.statut,
                      payment_url: initResult.payment_url,
                      payment_token: initResult.payment_token,
                      createdAt: booking.created_at
                    }
                  });
                });
            });
        });
    })
    .catch(function(err) {
      console.error('Erreur POST /bookings:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /bookings — Liste les billets de l'utilisateur connecté
router.get('/', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT b.id, b.ref, b.quantity, b.total_amount, b.paiement_method, b.statut, b.created_at, ' +
    'b.cancelled_at, b.refund_amount, b.refund_ratio, b.cancellation_reason, ' +
    'e.title, e.date, e.lieu, e.prix_display, e.emoji, e.color, e.category, e.start_at, e.image_url ' +
    'FROM bookings b JOIN events e ON b.event_id = e.id ' +
    'WHERE b.user_id = $1 ORDER BY b.created_at DESC',
    [req.userId]
  )
    .then(function(result) {
      var billets = result.rows.map(function(row) {
        return {
          id: row.id.toString(),
          ref: row.ref,
          // qr_payload : ce que doit afficher le QR code (ref + signature HMAC).
          // Calculé à la volée — HMAC déterministe, pas de stockage en base nécessaire.
          qr_payload: qr.signRef(row.ref),
          quantity: row.quantity,
          total_amount: row.total_amount,
          paiement: row.paiement_method,
          statut: row.statut,
          created_at: row.created_at,
          cancelled_at: row.cancelled_at,
          refund_amount: row.refund_amount != null ? parseInt(row.refund_amount) : null,
          refund_ratio: row.refund_ratio != null ? parseFloat(row.refund_ratio) : null,
          cancellation_reason: row.cancellation_reason,
          event: {
            title: row.title,
            date: row.date,
            start_at: row.start_at,
            lieu: row.lieu,
            prix: row.prix_display,
            emoji: row.emoji,
            color: row.color,
            category: row.category,
            image_url: row.image_url
          }
        };
      });

      res.json({ success: true, billets: billets });
    })
    .catch(function(err) {
      console.error('Erreur GET /bookings:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /bookings/check-in — Scan QR à l'entrée par l'organisateur
// Webapp orga décode le QR (AKWABA-BILLET:AKW-XXXXXXXX.HHHHHHHHHHHHHHHH) et envoie
// le payload ici. Le serveur vérifie la signature HMAC, l'ownership orga, le statut,
// puis marque le billet 'utilise'.
// @body {string} payload - Contenu QR signé: 'AKW-XXXXXXXX.HHHHHHHHHHHHHHHH'
//   (compat ancien format : accepte aussi {ref} pour les billets pré-signature ; bientôt obsolète)
router.post('/check-in', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
  var ref;

  // Nouveau format signé (obligatoire à terme).
  if (req.body.payload) {
    var verified = qr.parseAndVerify(req.body.payload);
    if (!verified.ok) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_SIGNATURE',
        message: 'Signature du billet invalide. Le QR a été falsifié ou est corrompu.'
      });
    }
    ref = verified.ref;
  } else if (req.body.ref) {
    // Compat temporaire pour billets pré-signature (à retirer après 30j de prod).
    ref = req.body.ref;
    if (typeof ref !== 'string' || !/^AKW-[A-F0-9]{8}$/.test(ref)) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_REF',
        message: 'Référence de billet invalide. Format attendu : AKW-XXXXXXXX.'
      });
    }
  } else {
    return res.status(400).json({
      success: false,
      code: 'MISSING_PAYLOAD',
      message: 'Champ payload (QR signé) requis.'
    });
  }

  // 1) Lookup billet + event + participant en une seule requête
  pool.query(
    'SELECT b.id, b.statut, b.quantity, b.utilise_at, ' +
    'e.id AS event_id, e.organizer_id, e.title AS event_title, ' +
    'u.nom, u.prenom ' +
    'FROM bookings b ' +
    'JOIN events e ON b.event_id = e.id ' +
    'JOIN users u ON b.user_id = u.id ' +
    'WHERE b.ref = $1',
    [ref]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          code: 'NOT_FOUND',
          message: 'Aucun billet ne correspond à cette référence.'
        });
      }

      var b = result.rows[0];

      // 2) Ownership : seul l'orga propriétaire de l'event peut check-in
      if (b.organizer_id !== req.user.id) {
        return res.status(403).json({
          success: false,
          code: 'NOT_YOUR_EVENT',
          message: 'Ce billet appartient à un événement d\'un autre organisateur.'
        });
      }

      // 3) Statuts non-checkin-able
      if (b.statut === 'utilise') {
        return res.status(409).json({
          success: false,
          code: 'ALREADY_USED',
          message: 'Billet déjà scanné.',
          utilise_at: b.utilise_at,
          participant: { nom: b.nom, prenom: b.prenom }
        });
      }
      if (b.statut === 'annule') {
        return res.status(410).json({
          success: false,
          code: 'CANCELLED',
          message: 'Billet annulé.'
        });
      }
      if (b.statut === 'en_attente') {
        return res.status(402).json({
          success: false,
          code: 'PAYMENT_PENDING',
          message: 'Paiement non confirmé pour ce billet.'
        });
      }
      if (b.statut !== 'confirme') {
        return res.status(409).json({
          success: false,
          code: 'INVALID_STATUS',
          message: 'Statut billet inattendu : ' + b.statut
        });
      }

      // 4) UPDATE conditionnel : protège contre la race condition double-scan.
      //    Si un autre scan passe entre le SELECT et l'UPDATE, rowCount=0 → on renvoie 409.
      return pool.query(
        "UPDATE bookings SET statut = 'utilise', utilise_at = NOW(), checkin_by = $2 " +
        "WHERE id = $1 AND statut = 'confirme' RETURNING utilise_at",
        [b.id, req.user.id]
      )
        .then(function(updResult) {
          if (updResult.rowCount === 0) {
            return res.status(409).json({
              success: false,
              code: 'ALREADY_USED',
              message: 'Billet scanné juste à l\'instant par un autre scan.'
            });
          }
          res.json({
            success: true,
            checkin: {
              ref: ref,
              participant: { nom: b.nom, prenom: b.prenom },
              places: b.quantity,
              event_title: b.event_title,
              utilise_at: updResult.rows[0].utilise_at
            }
          });
        });
    })
    .catch(function(err) {
      console.error('Erreur POST /bookings/check-in:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /bookings/check-in-batch — Sync de scans offline (SCAN-OFFLINE-01).
// Le scanner mobile peut accumuler des scans en local quand le reseau est
// down (typique en salle des fetes CI). Cet endpoint ingere le batch et
// retourne un statut par item pour que le client puisse purger sa queue.
//
// Pour chaque item, applique la meme logique que /check-in (ownership +
// statut + UPDATE conditionnel). Idempotent : un ref deja 'utilise' par
// le meme orga renvoie ok=true (deja gere) plutot qu'erreur.
//
// @body {Array} items - [{ payload?, ref?, scanned_at? }]
// @returns {Array} results - [{ ref, ok, code?, message? }]
router.post('/check-in-batch', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
  var items = Array.isArray(req.body.items) ? req.body.items : [];
  if (items.length === 0) {
    return res.status(400).json({ success: false, message: 'items vide' });
  }
  if (items.length > 200) {
    return res.status(400).json({ success: false, message: 'batch limite a 200 items' });
  }

  // Helper : traite un seul item, retourne une promesse resolue avec
  // { ref, ok, code, message }. Pas de reject (les erreurs sont des items).
  function processOne(item) {
    var ref;
    if (item.payload) {
      var verified = qr.parseAndVerify(item.payload);
      if (!verified.ok) {
        return Promise.resolve({ ref: null, ok: false, code: 'INVALID_SIGNATURE', message: 'QR falsifie' });
      }
      ref = verified.ref;
    } else if (item.ref && /^AKW-[A-F0-9]{8}$/.test(item.ref)) {
      ref = item.ref;
    } else {
      return Promise.resolve({ ref: item.ref || null, ok: false, code: 'INVALID_REF', message: 'Ref invalide' });
    }

    return pool.query(
      'SELECT b.id, b.statut, b.utilise_at, e.organizer_id ' +
      'FROM bookings b JOIN events e ON b.event_id = e.id WHERE b.ref = $1',
      [ref]
    ).then(function(result) {
      if (result.rows.length === 0) {
        return { ref: ref, ok: false, code: 'NOT_FOUND', message: 'Billet introuvable' };
      }
      var b = result.rows[0];
      if (b.organizer_id !== req.user.id) {
        return { ref: ref, ok: false, code: 'NOT_YOUR_EVENT', message: 'Pas ton evenement' };
      }
      if (b.statut === 'utilise') {
        // Idempotent : deja scanne, pas une erreur dans le contexte batch.
        return { ref: ref, ok: true, code: 'ALREADY_USED', utilise_at: b.utilise_at };
      }
      if (b.statut === 'annule') {
        return { ref: ref, ok: false, code: 'CANCELLED', message: 'Billet annule' };
      }
      if (b.statut !== 'confirme') {
        return { ref: ref, ok: false, code: 'INVALID_STATUS', message: 'Statut: ' + b.statut };
      }
      var scannedAt = item.scanned_at && !isNaN(new Date(item.scanned_at).getTime())
        ? new Date(item.scanned_at)
        : new Date();
      return pool.query(
        "UPDATE bookings SET statut = 'utilise', utilise_at = $2, checkin_by = $3 " +
        "WHERE id = $1 AND statut = 'confirme' RETURNING utilise_at",
        [b.id, scannedAt, req.user.id]
      ).then(function(upd) {
        if (upd.rowCount === 0) {
          return { ref: ref, ok: true, code: 'ALREADY_USED' };
        }
        return { ref: ref, ok: true, utilise_at: upd.rows[0].utilise_at };
      });
    }).catch(function(err) {
      console.error('Erreur batch item', ref, err.message);
      return { ref: ref, ok: false, code: 'SERVER_ERROR', message: 'Erreur serveur' };
    });
  }

  Promise.all(items.map(processOne))
    .then(function(results) {
      res.json({ success: true, results: results });
    })
    .catch(function(err) {
      console.error('Erreur POST /bookings/check-in-batch:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /bookings/lookup — Recherche manuelle d'un billet par telephone
// (SCAN-LOOKUP-01). Cas d'usage : QR illisible, telephone du participant
// casse, billet papier degrade. L'orga tape le numero, on retourne les
// billets correspondants pour ses events. Utile quand le scan visuel echoue.
//
// @body {number|string} event_id (optionnel — si absent, cherche dans tous
//   les events de l'orga)
// @body {string} phone (peut etre partiel : "0707..." matchera "+2250707...")
// @returns {Array} bookings - matchings avec statut + participant
router.post('/lookup', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
  var phone = (req.body.phone || '').trim();
  var eventId = req.body.event_id;
  if (phone.length < 4) {
    return res.status(400).json({ success: false, message: 'Telephone trop court (min 4 chiffres)' });
  }
  // Normalise pour matching ILIKE : supprime espaces et caracteres non-numeriques
  // sauf le +. Permet de matcher "07 07..." vs "+2250707...".
  var normalized = phone.replace(/[^0-9+]/g, '');
  // On utilise un suffix matching : les phones backend sont stockes avec +225
  // prefix typiquement. L'orga peut taper juste les 8-10 derniers digits.
  var suffix = normalized.replace(/^\+?225/, '').slice(-10);
  if (suffix.length < 4) {
    return res.status(400).json({ success: false, message: 'Telephone invalide' });
  }

  var sql = 'SELECT b.id, b.ref, b.quantity, b.statut, b.utilise_at, b.created_at, ' +
    'b.event_id, e.title AS event_title, ' +
    'u.nom, u.prenom, u.phone ' +
    'FROM bookings b ' +
    'JOIN events e ON b.event_id = e.id ' +
    'JOIN users u ON b.user_id = u.id ' +
    'WHERE e.organizer_id = $1 AND u.phone LIKE $2';
  var params = [req.user.id, '%' + suffix];
  if (eventId) {
    sql += ' AND b.event_id = $3';
    params.push(eventId);
  }
  sql += ' ORDER BY b.created_at DESC LIMIT 20';

  pool.query(sql, params)
    .then(function(result) {
      var bookings = result.rows.map(function(r) {
        return {
          id: r.id,
          ref: r.ref,
          quantity: r.quantity,
          statut: r.statut,
          utilise_at: r.utilise_at,
          created_at: r.created_at,
          event_id: r.event_id.toString(),
          event_title: r.event_title,
          participant: { nom: r.nom, prenom: r.prenom, phone: r.phone },
        };
      });
      res.json({ success: true, bookings: bookings });
    })
    .catch(function(err) {
      console.error('Erreur POST /bookings/lookup:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /bookings/:id/cancel — Annulation par l'utilisateur (BK-04).
// Politique de remboursement (lue depuis app_settings.refund_policy_default) :
//   - >48h avant l'événement → 100%
//   - 24-48h               → 70%
//   - <24h ou passé        → 0%
// Si event.start_at est NULL (legacy event sans timestamp parsable), on applique
// la politique la plus généreuse (100%) — vaut mieux trop rembourser que créer
// un litige sur la première annulation.
//
// Le remboursement réel CinetPay est fait manuellement via le back-office par
// l'admin pour MVP (audit-log only). Une intégration CinetPay refund pourra
// être branchée ici plus tard.
router.post('/:id/cancel', auth.authMiddleware, function(req, res) {
  var bookingId = req.params.id;
  var reason = (req.body.reason || '').trim();

  pool.query(
    'SELECT b.id, b.user_id, b.event_id, b.quantity, b.total_amount, b.statut, ' +
    'e.title, e.start_at, e.organizer_id ' +
    'FROM bookings b JOIN events e ON e.id = b.event_id ' +
    'WHERE b.id = $1',
    [bookingId]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Réservation non trouvée' });
      }
      var b = result.rows[0];
      if (b.user_id !== req.userId) {
        return res.status(403).json({ success: false, message: 'Cette réservation ne vous appartient pas' });
      }
      if (b.statut !== 'confirme' && b.statut !== 'en_attente') {
        return res.status(409).json({
          success: false,
          message: 'Réservation déjà annulée, utilisée ou remboursée',
        });
      }

      // Récupère la politique de remboursement (JSONB de la table app_settings).
      return pool.query(
        "SELECT value FROM app_settings WHERE key = 'refund_policy_default'"
      ).then(function(polRes) {
        var policy = polRes.rows.length > 0
          ? polRes.rows[0].value
          : { more_than_48h: 1.0, between_24_and_48h: 0.7, less_than_24h: 0.0 };

        // Calcul du ratio selon le délai avant l'événement.
        var ratio;
        if (!b.start_at) {
          // Pas de date parsable : on est généreux (100%).
          ratio = 1.0;
        } else {
          var hoursUntil = (new Date(b.start_at).getTime() - Date.now()) / 3600000;
          if (hoursUntil > 48) ratio = parseFloat(policy.more_than_48h);
          else if (hoursUntil > 24) ratio = parseFloat(policy.between_24_and_48h);
          else ratio = parseFloat(policy.less_than_24h);
        }

        var refundAmount = Math.floor(b.total_amount * ratio);

        // Transaction : update booking + relâche les places.
        return pool.query(
          "UPDATE bookings SET statut = 'annule', cancelled_at = NOW(), " +
          'refund_amount = $1, refund_ratio = $2, cancellation_reason = $3, ' +
          'updated_at = NOW() WHERE id = $4 RETURNING id',
          [refundAmount, ratio, reason || null, bookingId]
        )
          .then(function() {
            return pool.query(
              'UPDATE events SET places_restantes = places_restantes + $1 WHERE id = $2',
              [b.quantity, b.event_id]
            );
          })
          .then(function() {
            // WAITLIST-01 : une place s'est liberee, notifier le prochain user en
            // queue (joined_at ASC, notified_at NULL). Best effort, ne bloque pas.
            // Si l'event etait sold-out et a maintenant 1+ places restantes,
            // ce hook fait gagner 30-50% des places annulees re-vendues.
            //
            // Note : on call notifyNextOnWaitlist pour CHAQUE place liberee
            // (b.quantity fois) si quantity > 1 — comme ca on notifie q users.
            for (var qi = 0; qi < b.quantity; qi++) {
              waitlistRouter.notifyNextOnWaitlist(b.event_id);
            }
          })
          .then(function() {
            // Notif user (toujours) + orga si refund > 0 (impact sur ses revenus).
            push.notifyUser(b.user_id, {
              title: 'Annulation enregistrée',
              body: refundAmount > 0
                ? '« ' + b.title + ' » — remboursement de ' + refundAmount.toLocaleString('fr-FR') + ' FCFA en cours'
                : '« ' + b.title + ' » — annulation sans remboursement (délai dépassé)',
              data: { type: 'booking_cancelled', bookingId: b.id.toString() },
            });
            if (b.organizer_id && b.organizer_id !== b.user_id && refundAmount > 0) {
              push.notifyUser(b.organizer_id, {
                title: 'Annulation client',
                body: b.quantity + ' billet' + (b.quantity > 1 ? 's' : '') + ' annulé' +
                  (b.quantity > 1 ? 's' : '') + ' sur « ' + b.title + ' »',
                data: { type: 'booking_cancelled_for_orga', bookingId: b.id.toString() },
              });
            }

            res.json({
              success: true,
              cancellation: {
                booking_id: bookingId,
                refund_amount: refundAmount,
                refund_ratio: ratio,
                refund_status: refundAmount > 0 ? 'pending_manual' : 'no_refund',
                message: refundAmount > 0
                  ? 'Annulation enregistrée. Remboursement de ' + refundAmount.toLocaleString('fr-FR') + ' FCFA traité sous 5 jours ouvrés.'
                  : 'Annulation enregistrée. Aucun remboursement applicable selon la politique (moins de 24h avant l\'événement).',
              },
            });
          });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /bookings/:id/cancel:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /bookings/:id/confirm — Confirme une réservation (après paiement)
router.patch('/:id/confirm', function(req, res) {
  var bookingId = req.params.id;
  var transactionId = req.body.transaction_id;

  pool.query(
    "UPDATE bookings SET statut = 'confirme', transaction_id = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    [transactionId, bookingId]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Réservation non trouvée' });
      }

      notifyBookingConfirmed(result.rows[0].id);

      res.json({
        success: true,
        message: 'Réservation confirmée',
        booking: result.rows[0]
      });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /bookings/:id/confirm:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
