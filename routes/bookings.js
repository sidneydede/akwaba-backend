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
var paystack = require('../services/paystack');
var userAudit = require('../services/userAudit');
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

  // SEC H8 : bornes quantity [1, 10]. parseInt(-5) === -5 → total_amount
  // négatif → refund frauduleux possible si cancel auto. parseInt(1000) =
  // achat massif suspect (anti-bot, anti-scalper).
  if (quantity < 1 || quantity > 10) {
    return res.status(400).json({
      success: false,
      message: 'quantity doit être entre 1 et 10 places.',
    });
  }

  // P0#4 audit : ticket_id explicite (multi-tickets). Si absent, fallback au
  // 1er ticket non-archive du event (sort_order ASC) — preserve la rétrocompat
  // pour les clients legacy (ancien mobile) qui ne envoient que eventId.
  var explicitTicketId = req.body.ticket_id ? parseInt(req.body.ticket_id, 10) : null;

  // DUPLICATE-01 : si l'user a deja un billet (confirme ou en_attente) pour
  // cet event, on renvoie 409 avec code='duplicate_booking' + details. Le
  // mobile montre un pop-up "tu as deja un billet, continuer ?" et re-poste
  // avec confirm_duplicate=true pour bypasser (cas legitime : achat pour un ami).
  var skipDupCheck = req.body.confirm_duplicate === true;

  Promise.all([
    pool.query(
      'SELECT id, title, prix, prix_display, places_restantes, start_at, sales_close_at ' +
      'FROM events WHERE id = $1',
      [eventId]
    ),
    pool.query(
      'SELECT id, name, price, places_total, places_restantes ' +
      'FROM event_tickets WHERE event_id = $1 AND archived_at IS NULL ' +
      'ORDER BY sort_order ASC, id ASC',
      [eventId]
    ),
    skipDupCheck
      ? Promise.resolve({ rows: [] })
      : pool.query(
          'SELECT id, ref, quantity, statut, created_at FROM bookings ' +
          "WHERE user_id = $1 AND event_id = $2 AND statut IN ('confirme', 'en_attente') " +
          'ORDER BY created_at DESC LIMIT 5',
          [req.userId, eventId]
        ),
  ])
    .then(function(results) {
      var eventResult = results[0];
      var ticketsResult = results[1];
      var dupResult = results[2];
      if (eventResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Événement non trouvé'
        });
      }

      // DUPLICATE-01 (suite) : si doublon trouve, on stoppe ici avec un 409
      // structure pour le mobile. On NE PAS continuer le flow (pas de place
      // decrement, pas d'INSERT booking).
      if (dupResult.rows.length > 0) {
        var totalExistingQty = dupResult.rows.reduce(function(s, r) { return s + (r.quantity || 1); }, 0);
        return res.status(409).json({
          success: false,
          code: 'duplicate_booking',
          message: 'Tu as déjà ' + (dupResult.rows.length > 1 ? dupResult.rows.length + ' billets' : 'un billet') +
            ' pour cet événement (' + totalExistingQty + ' place' + (totalExistingQty > 1 ? 's' : '') + ').',
          existing_bookings: dupResult.rows.map(function(r) {
            return {
              id: r.id.toString(),
              ref: r.ref,
              quantity: r.quantity,
              statut: r.statut,
              created_at: r.created_at,
            };
          }),
        });
      }

      var event = eventResult.rows[0];

      // P1#10 : ferme les ventes selon sales_close_at (ou start_at fallback).
      // On accorde 1 min de tolerance pour absorber le delai entre check et insert.
      var now = Date.now();
      var closeAt = null;
      if (event.sales_close_at) closeAt = new Date(event.sales_close_at).getTime();
      else if (event.start_at) closeAt = new Date(event.start_at).getTime();
      if (closeAt && now > closeAt + 60 * 1000) {
        return res.status(400).json({
          success: false,
          code: 'sales_closed',
          message: event.sales_close_at
            ? 'Les ventes pour cet événement sont fermées.'
            : 'L\'événement a déjà commencé.',
        });
      }

      // P0#4 : selectionne le ticket cible.
      var availableTickets = ticketsResult.rows;
      if (availableTickets.length === 0) {
        // Tres anciens events pre-migration (improbable apres backfill). Refuse.
        return res.status(400).json({
          success: false,
          message: 'Cet événement n\'a pas de catégorie de places configurée.',
        });
      }
      var ticket;
      if (explicitTicketId) {
        ticket = availableTickets.filter(function(t) { return t.id === explicitTicketId; })[0];
        if (!ticket) {
          return res.status(400).json({
            success: false,
            code: 'ticket_not_found',
            message: 'Cette catégorie de place n\'existe plus pour cet événement.',
          });
        }
      } else {
        ticket = availableTickets[0]; // fallback : 1er ticket (sort_order ASC).
      }

      if (ticket.places_restantes < quantity) {
        return res.status(400).json({
          success: false,
          code: 'sold_out',
          message: 'Plus assez de places dans la catégorie « ' + ticket.name + ' ».',
        });
      }

      var ref = generateRef();
      var totalAmount = ticket.price * quantity;

      // Crée la réservation en 'en_attente' (transaction_id = ref pour le tracking CinetPay)
      return pool.query(
        "INSERT INTO bookings (user_id, event_id, ticket_id, ref, quantity, total_amount, paiement_method, statut, transaction_id) " +
        "VALUES ($1, $2, $3, $4, $5, $6, $7, 'en_attente', $4) RETURNING *",
        [req.userId, eventId, ticket.id, ref, quantity, totalAmount, paiement]
      )
        .then(function(bookingResult) {
          var booking = bookingResult.rows[0];

          // P0#4 : decremente places sur LE TICKET specifique + sur events
          // (le total events.places_restantes reste coherent pour les queries legacy).
          return pool.query(
            'UPDATE event_tickets SET places_restantes = places_restantes - $1, updated_at = NOW() ' +
            'WHERE id = $2',
            [quantity, ticket.id]
          )
            .then(function() {
              return pool.query(
                'UPDATE events SET places_restantes = places_restantes - $1 WHERE id = $2',
                [quantity, eventId]
              );
            })
            .then(function() {
              // Récupère les infos user pour le checkout Paystack (email
              // obligatoire côté Paystack, fallback placeholder si absent).
              return pool.query('SELECT id, nom, prenom, phone, email FROM users WHERE id = $1', [req.userId]);
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

              // Initie le paiement Paystack (hosted checkout) et récupère
              // l'URL à ouvrir côté mobile. payment_url = authorization_url
              // Paystack — le frontend EventScreen consomme cette clé.
              return paystack.initPayment({
                reference: ref,
                amount: totalAmount,
                description: '« ' + event.title + ' » · ' + quantity + ' billet' + (quantity > 1 ? 's' : ''),
                customer: {
                  id: user.id,
                  name: ((user.prenom || '') + ' ' + (user.nom || '')).trim() || 'Client',
                  phone: user.phone,
                  email: user.email,
                },
                // Le picker côté frontend (Orange/MTN/Wave/Djamo) reste pour
                // UX mais sa valeur n'oriente le routage que si l'user a
                // choisi carte bancaire. Sinon Paystack affiche tous les
                // canaux et l'user re-picke sur la page hosted.
                channels: paiement === 'carte_bancaire' || paiement === 'card'
                  ? ['card']
                  : ['mobile_money', 'card'],
              })
                .then(function(initResult) {
                  if (!initResult.ok) {
                    // Init Paystack a échoué : on annule le booking et on relâche les places.
                    console.error('Paystack init échoué pour', ref, ':', initResult.raw);
                    return pool.query(
                      "UPDATE bookings SET statut = 'annule', updated_at = NOW() WHERE id = $1",
                      [booking.id]
                    )
                      .then(function() {
                        // P0#4 : libere places sur ticket ET events.
                        return pool.query(
                          'UPDATE event_tickets SET places_restantes = places_restantes + $1, updated_at = NOW() ' +
                          'WHERE id = $2',
                          [quantity, ticket.id]
                        );
                      })
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

// Helper : verifie que req.userId est autorise a scanner les billets de
// l'event (organizer_id OU event_staff entry). Retourne une promesse qui
// resolve true/false. Utilise par /check-in et /check-in-batch pour
// supporter les "scanner only" assistants (TEAM-01).
function userCanScanEvent(userId, eventId) {
  return pool.query(
    'SELECT 1 FROM events WHERE id = $1 AND organizer_id = $2 ' +
    'UNION SELECT 1 FROM event_staff WHERE event_id = $1 AND user_id = $2 ' +
    'LIMIT 1',
    [eventId, userId]
  ).then(function(result) { return result.rows.length > 0; });
}

// POST /bookings/check-in — Scan QR à l'entrée par l'organisateur
// Webapp orga décode le QR (AKWABA-BILLET:AKW-XXXXXXXX.HHHHHHHHHHHHHHHH) et envoie
// le payload ici. Le serveur vérifie la signature HMAC, l'ownership orga
// OU staff entry (TEAM-01), le statut, puis marque le billet 'utilise'.
// @body {string} payload - Contenu QR signé: 'AKW-XXXXXXXX.HHHHHHHHHHHHHHHH'
//   (compat ancien format : accepte aussi {ref} pour les billets pré-signature ; bientôt obsolète)
router.post('/check-in', auth.authMiddleware, function(req, res) {
  // req.user n'est pas pose ici (on a remplace requireOrganizer par
  // authMiddleware seul pour permettre aux staff de scanner). On construit
  // un user simple a partir de req.userId pour les usages downstream.
  req.user = { id: req.userId };
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
  var b;
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
        res.status(404).json({
          success: false,
          code: 'NOT_FOUND',
          message: 'Aucun billet ne correspond à cette référence.'
        });
        return null;
      }
      b = result.rows[0];
      // 2) Authorization : owner OR staff (TEAM-01).
      return userCanScanEvent(req.user.id, b.event_id);
    })
    .then(function(allowed) {
      if (allowed === null) return null;  // already responded with 404
      if (!allowed) {
        res.status(403).json({
          success: false,
          code: 'NOT_YOUR_EVENT',
          message: 'Ce billet appartient à un événement sur lequel tu n\'es pas autorisé à scanner.'
        });
        return null;
      }
      // 3) Statuts non-checkin-able
      if (b.statut === 'utilise') {
        res.status(409).json({
          success: false,
          code: 'ALREADY_USED',
          message: 'Billet déjà scanné.',
          utilise_at: b.utilise_at,
          participant: { nom: b.nom, prenom: b.prenom }
        });
        return null;
      }
      if (b.statut === 'annule') {
        res.status(410).json({ success: false, code: 'CANCELLED', message: 'Billet annulé.' });
        return null;
      }
      if (b.statut === 'en_attente') {
        res.status(402).json({ success: false, code: 'PAYMENT_PENDING', message: 'Paiement non confirmé pour ce billet.' });
        return null;
      }
      if (b.statut !== 'confirme') {
        res.status(409).json({ success: false, code: 'INVALID_STATUS', message: 'Statut billet inattendu : ' + b.statut });
        return null;
      }
      // 4) UPDATE conditionnel : protège contre la race condition double-scan.
      return pool.query(
        "UPDATE bookings SET statut = 'utilise', utilise_at = NOW(), checkin_by = $2 " +
        "WHERE id = $1 AND statut = 'confirme' RETURNING utilise_at",
        [b.id, req.user.id]
      );
    })
    .then(function(updResult) {
      if (updResult === null || !updResult) return;
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
    })
    .catch(function(err) {
      console.error('Erreur POST /bookings/check-in:', err.message);
      if (!res.headersSent) {
        res.status(500).json({ success: false, message: 'Erreur serveur' });
      }
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
router.post('/check-in-batch', auth.authMiddleware, function(req, res) {
  // TEAM-01 : on autorise scanner-only assistants en plus des owners.
  // L'authorization par event est verifiee inline via userCanScanEvent
  // dans processOne (pas besoin de role=organisateur global).
  req.user = { id: req.userId };
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

    function processStatus(b) {
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
    }

    return pool.query(
      'SELECT b.id, b.statut, b.utilise_at, b.event_id, e.organizer_id ' +
      'FROM bookings b JOIN events e ON b.event_id = e.id WHERE b.ref = $1',
      [ref]
    ).then(function(result) {
      if (result.rows.length === 0) {
        return { ref: ref, ok: false, code: 'NOT_FOUND', message: 'Billet introuvable' };
      }
      var b = result.rows[0];
      // TEAM-01 : owner OR staff
      return userCanScanEvent(req.user.id, b.event_id).then(function(allowed) {
        if (!allowed) {
          return { ref: ref, ok: false, code: 'NOT_YOUR_EVENT', message: 'Pas autorise a scanner cet event' };
        }
        return processStatus(b);
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
router.post('/lookup', auth.authMiddleware, function(req, res) {
  // TEAM-01 : autorise owner OU staff. Le filtre SQL ci-dessous limite au
  // scope (events.organizer_id = me OR I'm in event_staff for that event).
  req.user = { id: req.userId };
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

  // Scope = events ou je suis owner OU staff. INNER JOIN sur la sous-requete
  // permet ce filtre en un seul passage.
  var sql = 'SELECT b.id, b.ref, b.quantity, b.statut, b.utilise_at, b.created_at, ' +
    'b.event_id, e.title AS event_title, ' +
    'u.nom, u.prenom, u.phone ' +
    'FROM bookings b ' +
    'JOIN events e ON b.event_id = e.id ' +
    'JOIN users u ON b.user_id = u.id ' +
    'WHERE u.phone LIKE $2 AND ' +
    '(e.organizer_id = $1 OR EXISTS (SELECT 1 FROM event_staff s WHERE s.event_id = e.id AND s.user_id = $1))';
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
    'SELECT b.id, b.user_id, b.event_id, b.ticket_id, b.quantity, b.total_amount, b.statut, ' +
    'b.transaction_id, ' +
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
        // refund_status passe en 'pending' si remboursement dû, 'skip' sinon.
        // L'admin verra le booking dans /refunds queue et marquera 'paid'
        // après virement manuel CinetPay.
        var initialRefundStatus = refundAmount > 0 ? 'pending' : 'skip';
        // SEC H4 : trace l'annulation pour le user (transparence + incident response)
        userAudit.log(req.userId, userAudit.ACTIONS.BOOKING_CANCEL, req, {
          booking_id: bookingId,
          event_title: b.title,
          refund_amount: refundAmount,
          refund_ratio: ratio,
        });
        return pool.query(
          "UPDATE bookings SET statut = 'annule', cancelled_at = NOW(), " +
          'refund_amount = $1, refund_ratio = $2, cancellation_reason = $3, ' +
          'refund_status = $5, updated_at = NOW() WHERE id = $4 RETURNING id',
          [refundAmount, ratio, reason || null, bookingId, initialRefundStatus]
        )
          .then(function() {
            // Refund Paystack (fire-and-forget). Skip si le booking était en
            // 'en_attente' — aucun paiement réel n'a transité chez Paystack
            // donc rien à rembourser (Paystack répondrait "transaction_not_found").
            // Si l'API call fail, on garde refund_status='pending' et l'admin
            // pourra retrigger manuellement. Le webhook refund.processed/failed
            // bumpera ensuite vers 'paid'/'failed'.
            if (initialRefundStatus === 'pending' && b.transaction_id && b.statut === 'confirme') {
              paystack.initiateRefund({
                transaction: b.transaction_id,
                amount: refundAmount,
                reason: 'Annulation user' + (reason ? ' : ' + reason : ''),
              })
                .then(function(rf) {
                  if (rf.ok) {
                    console.log('Refund Paystack initié:', b.transaction_id, 'status:', rf.status);
                  } else {
                    console.error('Refund Paystack échoué:', b.transaction_id, rf.raw);
                  }
                })
                .catch(function(e) { console.error('Refund Paystack exception:', e.message); });
            }
          })
          .then(function() {
            // P0#4 : libere la place sur LE TICKET specifique (si ticket_id present)
            if (b.ticket_id) {
              return pool.query(
                'UPDATE event_tickets SET places_restantes = places_restantes + $1, updated_at = NOW() ' +
                'WHERE id = $2',
                [b.quantity, b.ticket_id]
              );
            }
          })
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

// La confirmation d'une réservation (statut → 'confirme') se fait UNIQUEMENT
// côté serveur dans le webhook CinetPay (/payments/notify), après vérification
// HMAC + double-check de l'API CinetPay. Aucun endpoint client de confirmation
// n'est exposé : un tel endpoint laisserait un utilisateur marquer sa propre
// réservation comme payée sans encaissement réel.

// POST /bookings/:id/refund-orga — Refund partiel/total declenche par l'orga.
// UX audit orga P1#12 : avant cet endpoint, seul l'admin pouvait initier un
// refund hors politique. Maintenant l'orga peut rembourser depuis son
// dashboard event (cas usage : reclamation client, geste commercial,
// double booking, etc.).
//
// @body {number} amount   — montant du refund en FCFA (0 < amount <= total_amount)
// @body {string} reason   — justification (10 chars min, requise pour audit)
//
// Securite : verifie que l'event du booking appartient bien a l'orga connecte.
// Bookings deja annules sont refuses (idempotence). refund_status = 'pending',
// l'admin traite le transfert CinetPay via la queue refund existante.
router.post('/:id/refund-orga', auth.authMiddleware, auth.requireOrganizer, function(req, res) {
  var bookingId = req.params.id;
  var body = req.body || {};
  var amount = parseInt(body.amount, 10);
  var reason = String(body.reason || '').trim();

  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ success: false, message: 'Montant invalide.' });
  }
  if (!reason || reason.length < 10) {
    return res.status(400).json({
      success: false,
      message: 'Raison requise (10 caractères min) pour l\'audit.',
    });
  }

  // Fetch booking + event (avec organizer_id pour verif ownership).
  pool.query(
    'SELECT b.id, b.user_id, b.event_id, b.ticket_id, b.quantity, b.total_amount, b.statut, ' +
    'b.refund_status, b.ref, b.transaction_id, e.title, e.organizer_id ' +
    'FROM bookings b JOIN events e ON e.id = b.event_id ' +
    'WHERE b.id = $1',
    [bookingId]
  )
    .then(function(r) {
      if (r.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Réservation introuvable.' });
      }
      var b = r.rows[0];
      if (b.organizer_id !== req.userId) {
        return res.status(403).json({
          success: false,
          message: 'Cette réservation n\'appartient pas à un de tes events.',
        });
      }
      if (b.statut === 'annule') {
        return res.status(409).json({
          success: false,
          message: 'Cette réservation est déjà annulée.',
        });
      }
      if (amount > b.total_amount) {
        return res.status(400).json({
          success: false,
          message: 'Le montant excède le total payé (' + b.total_amount + ' FCFA).',
        });
      }

      var ratio = b.total_amount > 0 ? amount / b.total_amount : 0;

      return pool.query(
        "UPDATE bookings SET statut = 'annule', cancelled_at = NOW(), " +
        'refund_amount = $1, refund_ratio = $2, cancellation_reason = $3, ' +
        "refund_status = 'pending', updated_at = NOW() WHERE id = $4 RETURNING id",
        [amount, ratio, 'Refund orga : ' + reason, bookingId]
      )
        .then(function() {
          // Refund Paystack (fire-and-forget). Skip si le booking n'a jamais
          // été payé (statut='en_attente') — Paystack répondrait
          // "transaction_not_found" puisqu'aucune charge réelle n'existe.
          // Si KO, refund_status reste 'pending' et l'admin retrigger manuellement.
          // Le webhook refund.processed bumpera vers 'paid' quand Paystack confirme.
          if (b.transaction_id && b.statut === 'confirme') {
            paystack.initiateRefund({
              transaction: b.transaction_id,
              amount: amount,
              reason: 'Refund orga : ' + reason,
            })
              .then(function(rf) {
                if (rf.ok) {
                  console.log('Refund Paystack initié (orga):', b.transaction_id, 'status:', rf.status);
                } else {
                  console.error('Refund Paystack échoué (orga):', b.transaction_id, rf.raw);
                }
              })
              .catch(function(e) { console.error('Refund Paystack exception (orga):', e.message); });
          }
        })
        .then(function() {
          // P0#4 : libere la place sur le ticket specifique en + de events.
          if (b.ticket_id) {
            return pool.query(
              'UPDATE event_tickets SET places_restantes = places_restantes + $1, updated_at = NOW() ' +
              'WHERE id = $2',
              [b.quantity, b.ticket_id]
            );
          }
        })
        .then(function() {
          return pool.query(
            'UPDATE events SET places_restantes = places_restantes + $1 WHERE id = $2',
            [b.quantity, b.event_id]
          );
        })
        .then(function() {
          // Notif user
          push.notifyUser(b.user_id, {
            title: 'Remboursement initié',
            body: '« ' + b.title + ' » — ' + amount.toLocaleString('fr-FR') + ' FCFA en cours',
            data: { type: 'refund_orga_initiated', bookingId: b.id.toString() },
          });
        })
        .then(function() {
          res.json({
            success: true,
            booking_id: b.id.toString(),
            refund_amount: amount,
            message: 'Refund de ' + amount.toLocaleString('fr-FR') + ' FCFA enregistré. Traitement CinetPay sous 48h.',
          });
        });
    })
    .catch(function(err) {
      console.error('Erreur POST /bookings/:id/refund-orga:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
