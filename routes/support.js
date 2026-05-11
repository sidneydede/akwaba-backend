// routes/support.js — Tickets support côté participant.
// Le participant peut créer un ticket, lire ses tickets, ajouter des messages.
// L'admin gère via /admin/support/* (cf. routes/admin.js).

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var push = require('../services/push');

// Toutes les routes participant exigent un user connecté.
router.use(auth.authMiddleware);

// POST /support/tickets — Créer un nouveau ticket avec son 1er message.
// @body {string} subject, body
router.post('/tickets', function(req, res) {
  var subject = (req.body.subject || '').trim();
  var body = (req.body.body || '').trim();
  if (!subject || !body) {
    return res.status(400).json({ success: false, message: 'subject et body requis' });
  }
  if (subject.length > 200) {
    return res.status(400).json({ success: false, message: 'subject trop long (200 chars max)' });
  }
  if (body.length > 5000) {
    return res.status(400).json({ success: false, message: 'message trop long (5000 chars max)' });
  }

  pool.query(
    "INSERT INTO support_tickets (user_id, subject, status, last_message_at) " +
    "VALUES ($1, $2, 'open', NOW()) RETURNING id, created_at",
    [req.userId, subject]
  )
    .then(function(t) {
      var ticketId = t.rows[0].id;
      return pool.query(
        "INSERT INTO support_messages (ticket_id, author_id, author_role, body) " +
        "VALUES ($1, $2, 'user', $3) RETURNING id",
        [ticketId, req.userId, body]
      ).then(function() {
        // Notif push à tous les admins actifs (ils verront le badge sur /support).
        // Fire-and-forget pour ne pas bloquer la réponse user.
        pool.query("SELECT id FROM users WHERE role = 'admin' AND suspended_at IS NULL")
          .then(function(admins) {
            admins.rows.forEach(function(a) {
              push.notifyUser(a.id, {
                title: 'Nouveau ticket support 📩',
                body: subject.length > 60 ? subject.slice(0, 60) + '…' : subject,
                data: { type: 'support_new_ticket', ticketId: ticketId.toString() },
              });
            });
          })
          .catch(function(err) { console.error('Erreur notif admins support:', err.message); });

        res.status(201).json({
          success: true,
          ticket: { id: ticketId.toString(), created_at: t.rows[0].created_at },
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /support/tickets:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /support/tickets/mine — Liste mes tickets, plus récents en haut.
router.get('/tickets/mine', function(req, res) {
  pool.query(
    'SELECT t.id, t.subject, t.status, t.last_message_at, t.created_at, ' +
    'COALESCE((SELECT COUNT(*)::int FROM support_messages WHERE ticket_id = t.id), 0) AS messages_count ' +
    'FROM support_tickets t WHERE t.user_id = $1 ORDER BY t.last_message_at DESC LIMIT 50',
    [req.userId]
  )
    .then(function(r) {
      res.json({
        success: true,
        tickets: r.rows.map(function(t) {
          return {
            id: t.id.toString(),
            subject: t.subject,
            status: t.status,
            messages_count: t.messages_count,
            last_message_at: t.last_message_at,
            created_at: t.created_at,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /support/tickets/mine:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /support/tickets/:id — Thread complet d'un de mes tickets.
router.get('/tickets/:id', function(req, res) {
  Promise.all([
    pool.query(
      'SELECT id, subject, status, last_message_at, created_at FROM support_tickets ' +
      'WHERE id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    ),
    pool.query(
      'SELECT m.id, m.author_role, m.body, m.created_at, ' +
      "u.prenom || ' ' || u.nom AS author_name " +
      'FROM support_messages m LEFT JOIN users u ON u.id = m.author_id ' +
      'WHERE m.ticket_id = $1 ORDER BY m.created_at ASC',
      [req.params.id]
    ),
  ])
    .then(function(r) {
      if (r[0].rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Ticket non trouvé' });
      }
      var t = r[0].rows[0];
      res.json({
        success: true,
        ticket: {
          id: t.id.toString(),
          subject: t.subject,
          status: t.status,
          last_message_at: t.last_message_at,
          created_at: t.created_at,
        },
        messages: r[1].rows.map(function(m) {
          return {
            id: m.id.toString(),
            author_role: m.author_role,
            author_name: m.author_name,
            body: m.body,
            created_at: m.created_at,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /support/tickets/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /support/tickets/:id/messages — Ajoute un message sur mon ticket.
// Re-bascule le ticket en 'open' si l'admin l'avait passé en 'waiting'.
// @body {string} body
router.post('/tickets/:id/messages', function(req, res) {
  var body = (req.body.body || '').trim();
  if (!body) {
    return res.status(400).json({ success: false, message: 'body requis' });
  }
  if (body.length > 5000) {
    return res.status(400).json({ success: false, message: 'body trop long (5000 chars max)' });
  }

  // Vérifie ownership + ticket non closed.
  pool.query(
    "SELECT id, status, assigned_admin_id FROM support_tickets WHERE id = $1 AND user_id = $2",
    [req.params.id, req.userId]
  )
    .then(function(r) {
      if (r.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Ticket non trouvé' });
      }
      var t = r.rows[0];
      if (t.status === 'closed') {
        return res.status(400).json({ success: false, message: 'Ticket fermé, impossible de répondre' });
      }

      return Promise.all([
        pool.query(
          "INSERT INTO support_messages (ticket_id, author_id, author_role, body) " +
          "VALUES ($1, $2, 'user', $3) RETURNING id, created_at",
          [req.params.id, req.userId, body]
        ),
        pool.query(
          "UPDATE support_tickets SET status = CASE WHEN status = 'resolved' THEN 'resolved' " +
          "ELSE 'open' END, last_message_at = NOW(), updated_at = NOW() WHERE id = $1",
          [req.params.id]
        ),
      ]).then(function(results) {
        // Push à l'admin assigné (si assigné), sinon tous les admins
        var notifTarget;
        if (t.assigned_admin_id) {
          notifTarget = Promise.resolve({ rows: [{ id: t.assigned_admin_id }] });
        } else {
          notifTarget = pool.query("SELECT id FROM users WHERE role = 'admin' AND suspended_at IS NULL");
        }
        notifTarget.then(function(admins) {
          admins.rows.forEach(function(a) {
            push.notifyUser(a.id, {
              title: 'Nouvelle réponse support 💬',
              body: body.length > 80 ? body.slice(0, 80) + '…' : body,
              data: {
                type: 'support_user_reply',
                ticketId: req.params.id,
              },
            });
          });
        }).catch(function() {});

        res.status(201).json({
          success: true,
          message: {
            id: results[0].rows[0].id.toString(),
            created_at: results[0].rows[0].created_at,
          },
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /support/tickets/:id/messages:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
