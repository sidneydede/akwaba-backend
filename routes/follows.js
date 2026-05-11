// routes/follows.js — Suivre un organisateur (FOLLOW-01)
//
// Mecanique :
//   - User follow un orga depuis EventScreen (card "Organise par X")
//   - Quand l'orga publie un event qui passe a 'approved' (hook admin.js),
//     tous ses followers recoivent une push notif "📢 Nouveau de X"
//   - Anti double-push via flag events.followers_notified_at (cf. migration)

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var push = require('../services/push');

// POST /follows/:organisateurId — Suit un orga. Idempotent (ON CONFLICT DO NOTHING).
router.post('/:organisateurId', auth.authMiddleware, function(req, res) {
  var orgaId = parseInt(req.params.organisateurId, 10);
  if (isNaN(orgaId)) {
    return res.status(400).json({ success: false, message: 'organisateurId invalide' });
  }
  if (orgaId === req.userId) {
    return res.status(400).json({ success: false, message: 'Tu ne peux pas te suivre toi-même' });
  }

  // Verifie que l'orga existe ET est bien role='organisateur' (sinon on suit du vide)
  pool.query('SELECT id, role FROM users WHERE id = $1', [orgaId])
    .then(function(check) {
      if (check.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Organisateur introuvable' });
      }
      if (check.rows[0].role !== 'organisateur') {
        return res.status(400).json({ success: false, message: 'Cet utilisateur n\'est pas un organisateur' });
      }
      return pool.query(
        'INSERT INTO follows (user_id, organisateur_id) VALUES ($1, $2) ' +
        'ON CONFLICT (user_id, organisateur_id) DO NOTHING ' +
        'RETURNING created_at',
        [req.userId, orgaId]
      ).then(function(insertResult) {
        var alreadyExisted = insertResult.rows.length === 0;
        res.json({
          success: true,
          follow: {
            organisateur_id: orgaId.toString(),
            already_existed: alreadyExisted,
          },
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /follows/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// DELETE /follows/:organisateurId — Unfollow. Idempotent (200 meme si pas suivi).
router.delete('/:organisateurId', auth.authMiddleware, function(req, res) {
  var orgaId = parseInt(req.params.organisateurId, 10);
  if (isNaN(orgaId)) {
    return res.status(400).json({ success: false, message: 'organisateurId invalide' });
  }
  pool.query(
    'DELETE FROM follows WHERE user_id = $1 AND organisateur_id = $2',
    [req.userId, orgaId]
  )
    .then(function(result) {
      res.json({ success: true, removed: result.rowCount > 0 });
    })
    .catch(function(err) {
      console.error('Erreur DELETE /follows/:id:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /follows/ids — Liste des organisateur_id suivis par l'user connecte.
// Endpoint leger pour annoter EventScreen au mount (savoir si "+ Suivre" ou "✓ Suivi").
router.get('/ids', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT organisateur_id FROM follows WHERE user_id = $1',
    [req.userId]
  )
    .then(function(result) {
      var ids = result.rows.map(function(r) { return r.organisateur_id.toString(); });
      res.json({ success: true, ids: ids });
    })
    .catch(function(err) {
      console.error('Erreur GET /follows/ids:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// Helper : push notif "Nouveau de X" a tous les followers d'un orga quand
// un event devient 'approved'. Appele depuis routes/admin.js dans le handler
// PATCH /admin/events/:id/approve. Idempotent via le flag events.followers_notified_at.
//
// Best effort : log les erreurs mais ne throw jamais (l'approbation reste OK).
//
// @param {number} eventId
function notifyFollowersOfNewEvent(eventId) {
  pool.query(
    'SELECT e.id, e.title, e.date, e.organizer_id, e.followers_notified_at, ' +
    'u.prenom AS orga_prenom ' +
    'FROM events e LEFT JOIN users u ON u.id = e.organizer_id ' +
    'WHERE e.id = $1',
    [eventId]
  )
    .then(function(eventResult) {
      if (eventResult.rows.length === 0) return;
      var ev = eventResult.rows[0];
      // Anti double-push : si deja notifie, skip
      if (ev.followers_notified_at) {
        console.log('FOLLOW-01: event', eventId, 'deja notifie aux followers, skip');
        return;
      }
      if (!ev.organizer_id) return; // event legacy sans orga, skip

      // Marque immediatement le flag pour eviter les notifs concurrentes (ex: admin
      // double-click sur approve → 2 calls). UPDATE atomique : si la row a deja
      // followers_notified_at non NULL entre temps, le check au-dessus rattrapera.
      return pool.query(
        'UPDATE events SET followers_notified_at = NOW() WHERE id = $1 AND followers_notified_at IS NULL RETURNING id',
        [eventId]
      ).then(function(updateResult) {
        if (updateResult.rows.length === 0) {
          // Race condition : un autre call a deja notifie
          console.log('FOLLOW-01: event', eventId, 'race condition, deja notifie');
          return;
        }

        // Recupere les follower IDs
        return pool.query(
          'SELECT user_id FROM follows WHERE organisateur_id = $1',
          [ev.organizer_id]
        ).then(function(followersResult) {
          var followerIds = followersResult.rows.map(function(r) { return r.user_id; });
          if (followerIds.length === 0) {
            console.log('FOLLOW-01: orga', ev.organizer_id, 'a 0 followers, rien a push');
            return;
          }

          var orgaPrenom = ev.orga_prenom || 'Un organisateur';
          var bodyDate = ev.date ? ' · ' + ev.date : '';

          // Push notifs en parallele (push.notifyUser ne throw jamais — best effort).
          // Pas de throttling V1 : si l'orga publie 5 events en 1h, l'user recoit 5 push.
          // V2 : agreger en 1 push si plusieurs events sur la meme periode.
          followerIds.forEach(function(followerId) {
            push.notifyUser(followerId, {
              title: '📢 Nouveau de ' + orgaPrenom,
              body: ev.title + bodyDate,
              data: {
                type: 'new_event_from_followed_orga',
                event_id: ev.id.toString(),
                organisateur_id: ev.organizer_id.toString(),
              },
            });
          });

          console.log('FOLLOW-01: notifie', followerIds.length, 'followers de event', eventId);
        });
      });
    })
    .catch(function(err) {
      console.error('Erreur notifyFollowersOfNewEvent:', err.message);
    });
}

router.notifyFollowersOfNewEvent = notifyFollowersOfNewEvent;
module.exports = router;
