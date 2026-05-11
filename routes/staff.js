// routes/staff.js — Equipe d'assistants pour scan QR (TEAM-01).
//
// Endpoints :
//   POST   /events/:eventId/staff/invite  — invite un user par phone
//   DELETE /events/:eventId/staff/:userId — retire un membre
//   GET    /events/:eventId/staff         — liste des members
//
// Permissions : seul l'orga proprietaire de l'event peut gerer son staff.
// Les members ont role='scanner' pour V1 (pourra etre etendu : co_orga,
// box_office, etc.). Les permissions de scan sont verifiees inline dans
// /bookings/check-in (ownership OR staff entry).
//
// L'invitation se fait par phone : si l'user existe deja (compte cree ou
// participant), on l'ajoute direct ; sinon on cree un user pending.

var express = require('express');
var router = express.Router({ mergeParams: true });
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var push = require('../services/push');

// Middleware : verifie que l'auth user est bien proprietaire de l'event
// passe en :eventId. Pose req.event si OK. Reuse pour les 3 handlers.
function requireEventOwner(req, res, next) {
  var eventId = parseInt(req.params.eventId, 10);
  if (isNaN(eventId)) {
    return res.status(400).json({ success: false, message: 'eventId invalide' });
  }
  pool.query('SELECT id, organizer_id, title FROM events WHERE id = $1', [eventId])
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Evenement introuvable' });
      }
      if (result.rows[0].organizer_id !== req.userId) {
        return res.status(403).json({ success: false, message: 'Tu n\'es pas proprietaire de cet evenement' });
      }
      req.event = result.rows[0];
      next();
    })
    .catch(function(err) {
      console.error('Erreur requireEventOwner:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
}

// Normalise un phone : retire espaces + tout sauf chiffres et +.
// Si pas de prefix, ajoute +225 (Cote d'Ivoire). Sert au lookup users.
function normalizePhone(raw) {
  if (!raw) return '';
  var s = String(raw).replace(/[^0-9+]/g, '');
  if (s && s[0] !== '+') s = '+225' + s.replace(/^225/, '');
  return s;
}

// POST /events/:eventId/staff/invite
// Body : { phone: '0707...', role?: 'scanner' }
// Cree ou retrouve l'user par phone, l'ajoute comme staff. Si l'user a un
// expo_push_token, on lui push une notif. Idempotent (ON CONFLICT).
router.post('/invite', auth.authMiddleware, requireEventOwner, function(req, res) {
  var phone = normalizePhone(req.body.phone);
  if (phone.length < 8) {
    return res.status(400).json({ success: false, message: 'Telephone invalide' });
  }
  var role = req.body.role || 'scanner';
  if (['scanner'].indexOf(role) === -1) {
    return res.status(400).json({ success: false, message: 'Role invalide (scanner uniquement V1)' });
  }

  // Lookup ou creation de l'user
  pool.query('SELECT id, prenom, nom, phone FROM users WHERE phone = $1', [phone])
    .then(function(userResult) {
      if (userResult.rows.length > 0) {
        return userResult.rows[0];
      }
      // User n'existe pas : creation pending. prenom/nom par defaut, role
      // 'participant'. Quand la personne s'inscrira via OTP avec ce phone,
      // l'INSERT echouera (UNIQUE phone) et le code register doit se rabattre
      // sur l'user existant (deja gere via UPDATE).
      return pool.query(
        'INSERT INTO users (nom, prenom, phone, role) VALUES ($1, $2, $3, $4) RETURNING id, prenom, nom, phone',
        ['(en attente)', 'Invité', phone, 'participant']
      ).then(function(insertResult) { return insertResult.rows[0]; });
    })
    .then(function(user) {
      if (user.id === req.userId) {
        return res.status(400).json({ success: false, message: 'Tu ne peux pas t\'inviter toi-meme' });
      }
      return pool.query(
        'INSERT INTO event_staff (event_id, user_id, role, invited_by) ' +
        'VALUES ($1, $2, $3, $4) ON CONFLICT (event_id, user_id) DO UPDATE SET role = EXCLUDED.role ' +
        'RETURNING id, role',
        [req.event.id, user.id, role, req.userId]
      ).then(function(staffResult) {
        // Best-effort push : notifie l'invite qu'il a un nouveau role
        push.notifyUser(user.id, {
          title: 'Tu as ete ajoute comme scanner',
          body: '« ' + req.event.title + ' » — tu pourras scanner les billets le jour J',
          data: { type: 'staff_invited', event_id: req.event.id.toString() },
        });
        res.json({
          success: true,
          staff: {
            id: staffResult.rows[0].id,
            role: staffResult.rows[0].role,
            user: { id: user.id, prenom: user.prenom, nom: user.nom, phone: user.phone },
          },
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /events/:eventId/staff/invite:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// DELETE /events/:eventId/staff/:userId — Retire un member.
router.delete('/:userId', auth.authMiddleware, requireEventOwner, function(req, res) {
  var userId = parseInt(req.params.userId, 10);
  if (isNaN(userId)) {
    return res.status(400).json({ success: false, message: 'userId invalide' });
  }
  pool.query(
    'DELETE FROM event_staff WHERE event_id = $1 AND user_id = $2',
    [req.event.id, userId]
  )
    .then(function(result) {
      res.json({ success: true, removed: result.rowCount > 0 });
    })
    .catch(function(err) {
      console.error('Erreur DELETE /events/:eventId/staff/:userId:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /events/:eventId/staff — Liste les members de l'equipe.
router.get('/', auth.authMiddleware, requireEventOwner, function(req, res) {
  pool.query(
    'SELECT s.id, s.role, s.created_at, u.id AS user_id, u.prenom, u.nom, u.phone ' +
    'FROM event_staff s JOIN users u ON u.id = s.user_id ' +
    'WHERE s.event_id = $1 ORDER BY s.created_at DESC',
    [req.event.id]
  )
    .then(function(result) {
      var staff = result.rows.map(function(r) {
        return {
          id: r.id,
          role: r.role,
          created_at: r.created_at,
          user: { id: r.user_id, prenom: r.prenom, nom: r.nom, phone: r.phone },
        };
      });
      res.json({ success: true, staff: staff });
    })
    .catch(function(err) {
      console.error('Erreur GET /events/:eventId/staff:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
