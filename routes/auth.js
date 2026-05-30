// routes/auth.js — Authentification OTP par SMS
// Flow : register/login → OTP envoyé par SMS → verify-otp → token

var express = require('express');
var router = express.Router();
var pool = require('../db/pool');
var auth = require('../middleware/auth');
var sms = require('../services/sms');
var email = require('../services/email');
var userAudit = require('../services/userAudit');

// Canaux OTP supportés. Toute valeur hors de cette liste → fallback 'sms'.
var OTP_CHANNELS = ['sms', 'email'];

// Normalise un canal user input vers une valeur connue, ou null si inconnu.
// @param {string} value
// @returns {string|null}
function normalizeChannel(value) {
  if (!value) return null;
  var v = String(value).toLowerCase().trim();
  return OTP_CHANNELS.indexOf(v) !== -1 ? v : null;
}

// Génère un code OTP à 6 chiffres (crypto-random, pas Math.random qui est prédictible).
// @returns {string}
function generateOtp() {
  var crypto = require('crypto');
  var n = crypto.randomInt(100000, 1000000);
  return n.toString();
}

// REF-01 : génère un referral_code unique au format AKW-XXXX (4 chars base36).
// ~1.6M codes possibles, retry si collision UNIQUE (rare). Crypto-random pour
// éviter la prédictibilité (un attaquant pourrait sinon deviner les codes parrain).
// @returns {Promise<string>}
function generateUniqueReferralCode() {
  var crypto = require('crypto');
  function tryOnce(attemptsLeft) {
    if (attemptsLeft <= 0) {
      return Promise.reject(new Error('referral_code generation failed after retries'));
    }
    // 4 chars base36 = 36^4 = 1,679,616 codes. Suffisant pour V1 (~10K users max).
    // Si on grandit, passer à 5 ou 6 chars.
    var bytes = crypto.randomBytes(3);
    var n = (bytes[0] << 16) | (bytes[1] << 8) | bytes[2];
    var suffix = n.toString(36).toUpperCase().padStart(4, '0').slice(-4);
    var code = 'AKW-' + suffix;
    return pool.query('SELECT 1 FROM users WHERE referral_code = $1', [code])
      .then(function(check) {
        if (check.rows.length > 0) {
          return tryOnce(attemptsLeft - 1);
        }
        return code;
      });
  }
  return tryOnce(5);
}

// Calcule la date d'expiration OTP. Plus strict pour orga (compromission = accès aux fonds).
// @param {string} role - 'participant' | 'organisateur' | 'admin'
// @returns {Date}
function otpExpiry(role) {
  var minutes = role === 'organisateur' ? 5 : 10;
  return new Date(Date.now() + minutes * 60 * 1000);
}

// AUTH-05 : limites de tentatives OTP (brute-force protection).
// Orga = 3 tentatives, lockout 30 min. Participant = 5 tentatives, lockout 15 min.
function otpLimits(role) {
  if (role === 'organisateur') return { maxAttempts: 3, lockoutMinutes: 30 };
  return { maxAttempts: 5, lockoutMinutes: 15 };
}

// Helper : envoie un OTP via le canal demandé. Retourne le résultat brut du
// provider ({success, dev?, error?}) ou une erreur synthétique si pré-requis
// non rempli (ex: channel='email' mais pas d'email destinataire).
// @param {string} channel - 'sms' | 'email'
// @param {object} target - { phone?, email? }
// @param {string} code
// @returns {Promise<object>}
function deliverOtp(channel, target, code) {
  if (channel === 'email') {
    if (!target.email) {
      return Promise.resolve({ success: false, error: 'EMAIL_REQUIRED' });
    }
    return email.sendOtp(target.email, code);
  }
  return sms.sendOtp(target.phone, code);
}

// Helper : génère + stocke + envoie un OTP pour une registration EN ATTENTE
// (pas encore promue en users). Le user n'existe pas tant que l'OTP n'est
// pas validé — évite la pollution DB par les inscriptions abandonnées et
// le squatting de numéros.
// @param {object} pending - { phone, nom, prenom, role, email? }
// @param {string} channel - 'sms' | 'email' (défaut 'sms')
// @returns {Promise<object>} { dev_otp?, delivery_error?, channel }
function issuePendingOtp(pending, channel) {
  var ch = normalizeChannel(channel) || 'sms';
  var code = generateOtp();
  var expires = otpExpiry(pending.role || 'participant');
  var pendingEmail = pending.email ? email.normalizeEmail(pending.email) : null;
  return auth.hashPassword(code)
    .then(function(hash) {
      // UPSERT : si le user retape register pour le même phone (modif nom,
      // ou re-essai après abandon), on remplace l'entrée pending sans
      // dupliquer. Compteurs d'attempts réinitialisés. email peut être null.
      return pool.query(
        'INSERT INTO pending_registrations ' +
        '(phone, nom, prenom, role, email, otp_channel, otp_hash, otp_expires_at) ' +
        'VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ' +
        'ON CONFLICT (phone) DO UPDATE SET ' +
        'nom = EXCLUDED.nom, prenom = EXCLUDED.prenom, role = EXCLUDED.role, ' +
        'email = COALESCE(EXCLUDED.email, pending_registrations.email), ' +
        'otp_channel = EXCLUDED.otp_channel, ' +
        'otp_hash = EXCLUDED.otp_hash, otp_expires_at = EXCLUDED.otp_expires_at, ' +
        'otp_attempts = 0, otp_locked_until = NULL, created_at = NOW()',
        [pending.phone, pending.nom, pending.prenom, pending.role || 'participant',
          pendingEmail, ch, hash, expires]
      );
    })
    .then(function() {
      return deliverOtp(ch, { phone: pending.phone, email: pendingEmail }, code);
    })
    .then(function(result) {
      if (result.dev) return { dev_otp: code, channel: ch };
      if (result.success === false) {
        console.error('[issuePendingOtp] ' + ch + ' rejected:',
          pending.phone, JSON.stringify(result.error));
        return { delivery_error: result.error, channel: ch };
      }
      return { channel: ch };
    });
}

// Helper : génère + stocke + envoie un OTP pour un user existant.
// Reset les compteurs d'attempts (nouveau code = nouvelle fenêtre de tentatives).
// @param {object} user - Ligne user PostgreSQL (au minimum: id, phone, role, email?, last_otp_channel?)
// @param {string} channel - 'sms' | 'email'. Défaut : user.last_otp_channel || 'sms' (sticky)
// @returns {Promise<object>} { dev_otp?, delivery_error?, channel }
function issueOtp(user, channel) {
  var ch = normalizeChannel(channel) || normalizeChannel(user.last_otp_channel) || 'sms';
  var code = generateOtp();
  var expires = otpExpiry(user.role);
  // SEC H2 : hash le code avant store (scrypt, same format que password_hash).
  // En DB on stocke uniquement otp_hash. otp_code legacy nettoyé.
  return auth.hashPassword(code)
    .then(function(hash) {
      return pool.query(
        'UPDATE users SET otp_hash = $1, otp_code = NULL, ' +
        'otp_expires_at = $2, otp_attempts = 0, otp_locked_until = NULL, ' +
        'updated_at = NOW() WHERE id = $3',
        [hash, expires, user.id]
      );
    })
    .then(function() {
      return deliverOtp(ch, { phone: user.phone, email: user.email }, code);
    })
    .then(function(result) {
      // En mode dev, on renvoie l'OTP au client pour faciliter les tests
      if (result.dev) {
        return { dev_otp: code, channel: ch };
      }
      // Mode prod : si le provider a rejeté l'envoi, propager l'erreur au lieu
      // de mentir au client. register/login regardent delivery_error pour
      // renvoyer un 502 explicite (SMS_DELIVERY_FAILED / EMAIL_DELIVERY_FAILED).
      // Permet de diagnostiquer (sandbox non whitelisté, sender ID non approuvé,
      // solde épuisé, DKIM cassé, etc.) sans accès aux logs Render.
      if (result.success === false) {
        console.error('[issueOtp] ' + ch + ' rejected for user', user.id, ':',
          JSON.stringify(result.error));
        return { delivery_error: result.error, channel: ch };
      }
      // Succès : persiste le canal pour le proposer en sticky-default à la
      // prochaine demande. Fire-and-forget (l'OTP est déjà parti).
      pool.query('UPDATE users SET last_otp_channel = $1 WHERE id = $2', [ch, user.id])
        .catch(function(err) {
          console.error('[issueOtp] update last_otp_channel failed:', err.message);
        });
      return { channel: ch };
    });
}

// POST /auth/register — Inscription : envoie un OTP, NE crée PAS le compte.
// Le user n'est créé qu'à la validation de l'OTP (POST /auth/verify-otp).
// Évite le squatting de numéros + pollution DB par tests abandonnés.
// @body {string} nom, prenom, phone, role
router.post('/register', function(req, res) {
  var nom = (req.body.nom || '').trim();
  var prenom = (req.body.prenom || '').trim();
  var phone = (req.body.phone || '').trim();
  var role = req.body.role || 'participant';
  // Email optionnel (cf. plan OTP multi-canal). Si fourni : doit être valide.
  // Sert à recevoir l'OTP par email en fallback du SMS.
  var rawEmail = (req.body.email || '').trim();
  // Canal demandé pour l'OTP de validation du signup. Défaut SMS (le user
  // peut basculer email depuis l'écran OTP via /request-otp).
  var channel = normalizeChannel(req.body.channel) || 'sms';

  if (!nom || !prenom || !phone) {
    return res.status(400).json({
      success: false,
      message: 'Nom, prénom et téléphone sont obligatoires'
    });
  }
  if (nom.length > 100 || prenom.length > 100 || phone.length > 20) {
    return res.status(400).json({ success: false, message: 'Champ(s) trop long(s)' });
  }
  if (['participant', 'organisateur'].indexOf(role) === -1) {
    return res.status(400).json({ success: false, message: 'Rôle invalide' });
  }
  if (rawEmail && !email.isValidEmail(rawEmail)) {
    return res.status(400).json({ success: false, message: 'Email invalide' });
  }
  // Garde-fou : channel='email' impossible sans adresse.
  if (channel === 'email' && !rawEmail) {
    return res.status(400).json({
      success: false,
      code: 'EMAIL_REQUIRED',
      message: 'Renseignez un email pour recevoir le code par email.',
    });
  }

  // Si un user EXISTE déjà avec ce phone → bascule sur le flow login.
  // (UX-friendly : "Connecte-toi" plutôt que "Numéro déjà pris".)
  pool.query('SELECT id, phone FROM users WHERE phone = $1', [phone])
    .then(function(result) {
      if (result.rows.length > 0) {
        return res.status(409).json({
          success: false,
          code: 'PHONE_REGISTERED',
          message: 'Ce numéro est déjà inscrit. Utilise "Se connecter".',
        });
      }

      // Le user n'existe pas → on stocke en pending_registrations et on
      // envoie l'OTP. La création réelle attend la validation du code.
      var pending = { phone: phone, nom: nom, prenom: prenom, role: role };
      if (rawEmail) pending.email = rawEmail;
      return issuePendingOtp(pending, channel)
        .then(function(extra) {
          if (extra.delivery_error) {
            var isEmail = extra.channel === 'email';
            return res.status(502).json({
              success: false,
              code: isEmail ? 'EMAIL_DELIVERY_FAILED' : 'SMS_DELIVERY_FAILED',
              message: isEmail
                ? 'L\'email n\'a pas pu être envoyé. Vérifie l\'adresse ou réessaie en SMS.'
                : 'Le SMS n\'a pas pu être envoyé. Vérifie le numéro ou réessaie.',
              phone: phone,
              channel: extra.channel,
              delivery_error: extra.delivery_error,
            });
          }
          var via = extra.channel === 'email' ? 'email' : 'SMS';
          res.status(201).json(Object.assign({
            success: true,
            message: 'Un code de vérification a été envoyé par ' + via +
              '. Saisis-le pour activer ton compte.',
            phone: phone,
            next: 'verify-otp',
          }, extra));
        });
    })
    .catch(function(err) {
      console.error('Erreur register:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /auth/login — Demande un OTP pour un compte existant
// @body {string} phone
router.post('/login', function(req, res) {
  var phone = req.body.phone;
  // Canal OTP demandé. Sans préférence explicite, issueOtp fallback sur
  // user.last_otp_channel || 'sms' (sticky). Le mobile peut forcer 'email'
  // depuis l'écran OTP (bouton "Pas reçu ? Recevoir par email").
  var channel = normalizeChannel(req.body.channel);

  if (!phone) {
    return res.status(400).json({ success: false, message: 'Numéro de téléphone obligatoire' });
  }

  pool.query(
    'SELECT id, phone, role, email, last_otp_channel FROM users WHERE phone = $1',
    [phone]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Aucun compte trouvé avec ce numéro'
        });
      }

      var user = result.rows[0];

      // Garde-fou : channel='email' demandé mais user sans email en base.
      // Retour 400 explicite plutôt que tenter et logger EMAIL_REQUIRED.
      if (channel === 'email' && !user.email) {
        return res.status(400).json({
          success: false,
          code: 'EMAIL_NOT_SET',
          message: 'Aucun email enregistré pour ce compte. Renseigne ton email dans le profil pour recevoir le code par email.',
        });
      }

      return issueOtp(user, channel).then(function(extra) {
        if (extra.delivery_error) {
          var isEmail = extra.channel === 'email';
          return res.status(502).json({
            success: false,
            code: isEmail ? 'EMAIL_DELIVERY_FAILED' : 'SMS_DELIVERY_FAILED',
            message: isEmail
              ? 'L\'email n\'a pas pu être envoyé. Réessaie ou bascule sur SMS.'
              : 'Le SMS n\'a pas pu être envoyé. Vérifie le numéro ou réessaie plus tard.',
            phone: user.phone,
            channel: extra.channel,
            delivery_error: extra.delivery_error,
          });
        }
        var via = extra.channel === 'email' ? 'email' : 'SMS';
        res.json(Object.assign({
          success: true,
          message: 'Code de vérification envoyé par ' + via,
          phone: user.phone,
          next: 'verify-otp'
        }, extra));
      });
    })
    .catch(function(err) {
      console.error('Erreur login:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /auth/request-otp — Alias explicite de login (renvoyer un nouveau code)
router.post('/request-otp', function(req, res) {
  req.url = '/login';
  router.handle(req, res);
});

// POST /auth/verify-otp — Vérifie l'OTP et retourne un token + user
// @body {string} phone, code
router.post('/verify-otp', function(req, res) {
  var phone = req.body.phone;
  var code = req.body.code;

  if (!phone || !code) {
    return res.status(400).json({
      success: false,
      message: 'Numéro et code obligatoires'
    });
  }

  pool.query(
    'SELECT id, nom, prenom, phone, role, otp_hash, otp_expires_at, otp_attempts, otp_locked_until ' +
    'FROM users WHERE phone = $1',
    [phone]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        // Pas de user existant → check si registration pending. Si oui,
        // valide l'OTP et CRÉE le user. Sinon "Compte introuvable".
        return verifyPendingRegistration(phone, code, req, res);
      }

      var user = result.rows[0];
      var limits = otpLimits(user.role);

      // AUTH-05 : refus si compte verrouillé après trop de tentatives
      if (user.otp_locked_until && new Date(user.otp_locked_until).getTime() > Date.now()) {
        var minutesLeft = Math.ceil((new Date(user.otp_locked_until).getTime() - Date.now()) / 60000);
        return res.status(429).json({
          success: false,
          code: 'LOCKED',
          message: 'Trop de tentatives. Réessayez dans ' + minutesLeft + ' minute' + (minutesLeft > 1 ? 's' : '') + '.'
        });
      }

      if (!user.otp_hash) {
        return res.status(400).json({
          success: false,
          message: 'Aucun code en attente. Demandez un nouveau code.'
        });
      }

      if (new Date(user.otp_expires_at).getTime() < Date.now()) {
        return res.status(400).json({
          success: false,
          message: 'Code expiré. Demandez un nouveau code.'
        });
      }

      // SEC H2 : verify via scrypt (timing-safe). Plus de comparaison en clair.
      return auth.verifyPassword(code, user.otp_hash).then(function(matched) {
        if (!matched) {
          // Incrémente attempts + verrouille si dépassement.
          var newAttempts = (user.otp_attempts || 0) + 1;
          if (newAttempts >= limits.maxAttempts) {
            var lockUntil = new Date(Date.now() + limits.lockoutMinutes * 60 * 1000);
            return pool.query(
              'UPDATE users SET otp_attempts = $1, otp_locked_until = $2, ' +
              'otp_hash = NULL, otp_expires_at = NULL WHERE id = $3',
              [newAttempts, lockUntil, user.id]
            ).then(function() {
              res.status(429).json({
                success: false,
                code: 'LOCKED',
                message: 'Trop de tentatives. Compte temporairement verrouillé pendant ' +
                  limits.lockoutMinutes + ' minutes.'
              });
            });
          }
          return pool.query('UPDATE users SET otp_attempts = $1 WHERE id = $2', [newAttempts, user.id])
            .then(function() {
              res.status(400).json({
                success: false,
                message: 'Code incorrect',
                attempts_left: limits.maxAttempts - newAttempts
              });
            });
        }

        // Code valide — continue avec le flow de génération du token (ci-dessous).
        return acceptOtp(user, req, res);
      });
    })
    .catch(function(err) {
      console.error('Erreur POST /auth/verify-otp:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// Helper extrait : OTP validé, on émet le token + cleanup OTP + compteurs.
// Séparé pour rendre le flow verify-otp lisible après le refactor scrypt.
function acceptOtp(user, req, res) {
  return pool.query(
    'UPDATE users SET otp_hash = NULL, otp_code = NULL, otp_expires_at = NULL, ' +
    'otp_attempts = 0, otp_locked_until = NULL, last_login_at = NOW(), ' +
    'updated_at = NOW() WHERE id = $1',
    [user.id]
  )
    .then(function() {
      var token = auth.generateToken(user.id);
      // SEC H4 : trace login dans user_audit_log (fire-and-forget).
      userAudit.log(user.id, userAudit.ACTIONS.LOGIN, req, { phone: user.phone });
      res.json({
        success: true,
        message: 'Connexion réussie',
        user: {
          id: user.id.toString(),
          nom: user.nom,
          prenom: user.prenom,
          phone: user.phone,
          role: user.role,
        },
        token: token,
      });
    });
}

// Helper : valide l'OTP d'une pending_registration et crée le user si OK.
// Appelé par /auth/verify-otp quand aucun user n'existe pour ce phone.
function verifyPendingRegistration(phone, code, req, res) {
  return pool.query(
    'SELECT phone, nom, prenom, role, email, otp_channel, otp_hash, otp_expires_at, ' +
    'otp_attempts, otp_locked_until FROM pending_registrations WHERE phone = $1',
    [phone]
  ).then(function(pendingResult) {
    if (pendingResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Compte introuvable' });
    }
    var pending = pendingResult.rows[0];
    var limits = otpLimits(pending.role);

    if (pending.otp_locked_until && new Date(pending.otp_locked_until).getTime() > Date.now()) {
      var minutesLeft = Math.ceil((new Date(pending.otp_locked_until).getTime() - Date.now()) / 60000);
      return res.status(429).json({
        success: false,
        code: 'LOCKED',
        message: 'Trop de tentatives. Réessayez dans ' + minutesLeft + ' minute' +
          (minutesLeft > 1 ? 's' : '') + '.',
      });
    }

    if (new Date(pending.otp_expires_at).getTime() < Date.now()) {
      return res.status(400).json({
        success: false,
        message: 'Code expiré. Renvoie une demande d\'inscription.',
      });
    }

    return auth.verifyPassword(code, pending.otp_hash).then(function(matched) {
      if (!matched) {
        var newAttempts = (pending.otp_attempts || 0) + 1;
        if (newAttempts >= limits.maxAttempts) {
          var lockUntil = new Date(Date.now() + limits.lockoutMinutes * 60 * 1000);
          return pool.query(
            'UPDATE pending_registrations SET otp_attempts = $1, otp_locked_until = $2, ' +
            'otp_hash = NULL WHERE phone = $3',
            [newAttempts, lockUntil, phone]
          ).then(function() {
            res.status(429).json({
              success: false,
              code: 'LOCKED',
              message: 'Trop de tentatives. Inscription verrouillée pendant ' +
                limits.lockoutMinutes + ' minutes.',
            });
          });
        }
        return pool.query(
          'UPDATE pending_registrations SET otp_attempts = $1 WHERE phone = $2',
          [newAttempts, phone]
        ).then(function() {
          res.status(400).json({
            success: false,
            message: 'Code incorrect',
            attempts_left: limits.maxAttempts - newAttempts,
          });
        });
      }

      // OTP VALIDÉ : promote pending → user. Génère referral_code, INSERT
      // users (avec email si fourni au signup), DELETE pending, retourne token.
      // Trace REGISTER dans audit.
      return generateUniqueReferralCode()
        .catch(function() { return null; })
        .then(function(referralCode) {
          return pool.query(
            'INSERT INTO users (nom, prenom, phone, role, email, last_otp_channel, ' +
            'referral_code, last_login_at) ' +
            'VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) ' +
            'RETURNING id, nom, prenom, phone, role, email, last_otp_channel',
            [pending.nom, pending.prenom, pending.phone, pending.role,
              pending.email || null, pending.otp_channel || null, referralCode]
          );
        })
        .then(function(insRes) {
          var user = insRes.rows[0];
          // Cleanup pending (le user existe maintenant pour de vrai)
          pool.query('DELETE FROM pending_registrations WHERE phone = $1', [phone])
            .catch(function(err) {
              console.error('Erreur cleanup pending:', err.message);
            });
          var token = auth.generateToken(user.id);
          userAudit.log(user.id, userAudit.ACTIONS.REGISTER, req, { phone: user.phone });
          userAudit.log(user.id, userAudit.ACTIONS.LOGIN, req, { phone: user.phone });
          res.status(201).json({
            success: true,
            message: 'Compte activé. Bienvenue !',
            user: {
              id: user.id.toString(),
              nom: user.nom,
              prenom: user.prenom,
              phone: user.phone,
              role: user.role,
              email: user.email,
            },
            token: token,
          });
        });
    });
  });
}

// GET /auth/me/activity — Le user voit son propre historique d'activité.
// Limité 100 entrées (recent first). Transparence RGPD article 15 :
// l'user a le droit de voir les données qu'on stocke à son sujet.
router.get('/me/activity', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT id, action, ip, user_agent, metadata, created_at ' +
    'FROM user_audit_log WHERE user_id = $1 ' +
    'ORDER BY created_at DESC LIMIT 100',
    [req.userId]
  )
    .then(function(r) {
      res.json({
        success: true,
        activity: r.rows.map(function(row) {
          return {
            id: row.id.toString(),
            action: row.action,
            ip: row.ip,
            user_agent: row.user_agent,
            metadata: row.metadata,
            created_at: row.created_at,
          };
        }),
      });
    })
    .catch(function(err) {
      console.error('Erreur GET /auth/me/activity:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// GET /auth/me — Récupère le profil de l'utilisateur connecté
router.get('/me', auth.authMiddleware, function(req, res) {
  pool.query(
    'SELECT id, nom, prenom, phone, email, last_otp_channel, role, preferences, ville, ' +
    'date_naissance, photo_url, referral_code, points, created_at FROM users WHERE id = $1',
    [req.userId]
  )
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
      }

      var user = result.rows[0];

      return pool.query(
        "SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE statut = 'confirme') as actifs FROM bookings WHERE user_id = $1",
        [req.userId]
      )
        .then(function(statsResult) {
          var stats = statsResult.rows[0];
          res.json({
            success: true,
            user: {
              id: user.id.toString(),
              nom: user.nom,
              prenom: user.prenom,
              phone: user.phone,
              email: user.email,
              last_otp_channel: user.last_otp_channel,
              role: user.role,
              preferences: user.preferences || {},
              ville: user.ville,
              date_naissance: user.date_naissance,
              photo_url: user.photo_url,
              referral_code: user.referral_code,
              points: user.points || 0,
              created_at: user.created_at
            },
            stats: {
              total_billets: parseInt(stats.total),
              billets_actifs: parseInt(stats.actifs)
            }
          });
        });
    })
    .catch(function(err) {
      console.error('Erreur auth/me:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// PATCH /auth/me — Met à jour le profil de l'utilisateur connecté.
// Champs autorisés :
//   - prenom, nom : 1 à 50 caractères
//   - ville : trim, max 120 caractères (PROFILE-01)
//   - date_naissance : ISO YYYY-MM-DD, doit être < aujourd'hui ET > il y a 100 ans
//   - photo_url : URL Cloudinary (anti-injection : doit pointer sur res.cloudinary.com du tenant)
// Le téléphone n'est PAS modifiable ici (nominatif → nécessite re-OTP). Le role
// et l'id ne sont jamais modifiables par l'utilisateur lui-même.
router.patch('/me', auth.authMiddleware, function(req, res) {
  var input = req.body || {};
  var sets = [];
  var values = [];
  var i = 1;

  if (input.prenom !== undefined) {
    var p = String(input.prenom).trim();
    if (!p || p.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'Prénom invalide (1 à 50 caractères).'
      });
    }
    sets.push('prenom = $' + i++);
    values.push(p);
  }

  if (input.nom !== undefined) {
    var n = String(input.nom).trim();
    if (!n || n.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'Nom invalide (1 à 50 caractères).'
      });
    }
    sets.push('nom = $' + i++);
    values.push(n);
  }

  // Email : null pour effacer, string pour set/update. Stocké en lowercase
  // pour éviter les doublons de casse. Sert au canal email du flow OTP.
  if (input.email !== undefined) {
    if (input.email === null || input.email === '') {
      sets.push('email = NULL');
    } else {
      if (!email.isValidEmail(input.email)) {
        return res.status(400).json({
          success: false,
          message: 'Email invalide.'
        });
      }
      sets.push('email = $' + i++);
      values.push(email.normalizeEmail(input.email));
    }
  }

  if (input.ville !== undefined) {
    // null = effacer la ville. String = set/update.
    if (input.ville === null) {
      sets.push('ville = NULL');
    } else {
      var v = String(input.ville).trim();
      if (v.length > 120) {
        return res.status(400).json({
          success: false,
          message: 'Ville invalide (max 120 caractères).'
        });
      }
      sets.push('ville = $' + i++);
      values.push(v);
    }
  }

  if (input.date_naissance !== undefined) {
    if (input.date_naissance === null) {
      sets.push('date_naissance = NULL');
    } else {
      // Format attendu : YYYY-MM-DD (regex strict pour eviter les surprises Postgres)
      var dob = String(input.date_naissance).trim();
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dob)) {
        return res.status(400).json({
          success: false,
          message: 'Date de naissance invalide (format attendu : YYYY-MM-DD).'
        });
      }
      var d = new Date(dob);
      if (isNaN(d.getTime())) {
        return res.status(400).json({
          success: false,
          message: 'Date de naissance invalide.'
        });
      }
      var now = new Date();
      var maxAgo = new Date();
      maxAgo.setFullYear(maxAgo.getFullYear() - 100);
      if (d.getTime() >= now.getTime() || d.getTime() < maxAgo.getTime()) {
        return res.status(400).json({
          success: false,
          message: 'Date de naissance hors plage (entre il y a 100 ans et hier).'
        });
      }
      sets.push('date_naissance = $' + i++);
      values.push(dob);
    }
  }

  if (input.photo_url !== undefined) {
    if (input.photo_url === null) {
      sets.push('photo_url = NULL');
    } else {
      // Validation : doit etre une URL Cloudinary du tenant configure (anti-injection
      // contre stockage d'URLs externes arbitraires). Format Cloudinary :
      //   https://res.cloudinary.com/<cloud_name>/image/upload/...
      var photo = String(input.photo_url).trim();
      var cloudName = process.env.CLOUDINARY_CLOUD_NAME || '';
      var allowedPrefix = 'https://res.cloudinary.com/' + cloudName + '/';
      if (!cloudName || photo.indexOf(allowedPrefix) !== 0) {
        return res.status(400).json({
          success: false,
          message: 'URL photo invalide (doit être une URL Cloudinary du tenant Akwaba).'
        });
      }
      if (photo.length > 500) {
        return res.status(400).json({
          success: false,
          message: 'URL photo trop longue.'
        });
      }
      sets.push('photo_url = $' + i++);
      values.push(photo);
    }
  }

  if (sets.length === 0) {
    return res.status(400).json({
      success: false,
      message: 'Aucun champ à mettre à jour.'
    });
  }

  sets.push('updated_at = NOW()');
  values.push(req.userId);

  pool.query(
    'UPDATE users SET ' + sets.join(', ') + ' WHERE id = $' + i +
    ' RETURNING id, nom, prenom, phone, email, role, preferences, ville, date_naissance, ' +
    'photo_url, created_at',
    values
  )
    .then(function(result) {
      if (result.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'Utilisateur introuvable' });
      }
      var user = result.rows[0];
      // SEC H4 : trace l'update profile. metadata = liste des champs modifiés
      // (sans les valeurs sensibles).
      userAudit.log(req.userId, userAudit.ACTIONS.PROFILE_UPDATE, req, {
        fields: Object.keys(input || {}),
      });
      res.json({
        success: true,
        user: {
          id: user.id.toString(),
          nom: user.nom,
          prenom: user.prenom,
          phone: user.phone,
          email: user.email,
          role: user.role,
          preferences: user.preferences || {},
          ville: user.ville,
          date_naissance: user.date_naissance,
          photo_url: user.photo_url,
          created_at: user.created_at
        }
      });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /auth/me:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

// POST /auth/me/photo-signature — Génère une signature Cloudinary pour upload
// direct de la photo de profil utilisateur depuis l'app mobile.
// Mirror de POST /events/upload-signature (cf. routes/events.js) mais avec
// folder dédié avatars/<user_id> + transformation auto crop sur visage (g_face).
// Auth requise (n'importe quel user, pas juste orga).
router.post('/me/photo-signature', auth.authMiddleware, function(req, res) {
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

  // Folder dédié par user pour faciliter cleanup futur (DELETE user → DELETE photos).
  var folder = 'akwaba/avatars/' + req.userId;
  var timestamp = Math.floor(Date.now() / 1000);
  // Transformation : crop carré 400x400 centré sur le visage si détecté, fallback
  // sur center crop. Réduit l'usage bandwidth + uniformise les avatars dans l'UI.
  var transformation = 'c_thumb,g_face,w_400,h_400';
  // Les params signés doivent être triés alphabétiquement (cf. doc Cloudinary).
  var paramsToSign = 'folder=' + folder + '&timestamp=' + timestamp + '&transformation=' + transformation;
  var signature = crypto.createHash('sha1').update(paramsToSign + apiSecret).digest('hex');

  res.json({
    success: true,
    signature: signature,
    timestamp: timestamp,
    transformation: transformation,
    api_key: apiKey,
    cloud_name: cloudName,
    folder: folder,
    upload_url: 'https://api.cloudinary.com/v1_1/' + cloudName + '/image/upload',
  });
});

// PATCH /auth/me/preferences — Met à jour les préférences de l'utilisateur connecté.
// @body {object} preferences - { categories?: string[], lang?: string }
// On merge avec l'existant pour ne pas écraser les autres clés.
router.patch('/me/preferences', auth.authMiddleware, function(req, res) {
  var input = req.body.preferences;
  if (!input || typeof input !== 'object') {
    return res.status(400).json({ success: false, message: 'preferences (object) requis' });
  }

  // Validation : categories doit être un array de strings si fourni.
  if (input.categories !== undefined) {
    if (!Array.isArray(input.categories) ||
        !input.categories.every(function(c) { return typeof c === 'string'; })) {
      return res.status(400).json({
        success: false, message: 'preferences.categories doit être un array de strings',
      });
    }
  }

  // Merge JSONB : COALESCE pour le cas où preferences est NULL en base.
  pool.query(
    "UPDATE users SET preferences = COALESCE(preferences, '{}') || $1::jsonb, updated_at = NOW() " +
    'WHERE id = $2 RETURNING preferences',
    [JSON.stringify(input), req.userId]
  )
    .then(function(r) {
      res.json({ success: true, preferences: r.rows[0].preferences });
    })
    .catch(function(err) {
      console.error('Erreur PATCH /auth/me/preferences:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
});

module.exports = router;
