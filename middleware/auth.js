// middleware/auth.js — Vérification du token d'authentification
// Token simple basé sur user_id + secret (pas de JWT pour rester compatible .then())

var crypto = require('crypto');
var pool = require('../db/pool');

var TOKEN_SECRET = process.env.TOKEN_SECRET || 'akwaba-secret-dev';

// Génère un token pour un utilisateur
// @param {number} userId - ID de l'utilisateur
// @returns {string} Token d'authentification
function generateToken(userId) {
  var timestamp = Date.now().toString();
  var data = userId + ':' + timestamp;
  var hash = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('hex');
  // Format: userId:timestamp:hash (encodé en base64)
  var token = Buffer.from(data + ':' + hash).toString('base64');
  return token;
}

// Décode un token et retourne le userId
// @param {string} token - Token à décoder
// @returns {number|null} userId ou null si invalide
function decodeToken(token) {
  try {
    var decoded = Buffer.from(token, 'base64').toString('utf8');
    var parts = decoded.split(':');
    if (parts.length !== 3) return null;
    var userId = parseInt(parts[0]);
    var timestamp = parts[1];
    var hash = parts[2];
    // Vérifie le hash
    var expectedHash = crypto.createHmac('sha256', TOKEN_SECRET)
      .update(userId + ':' + timestamp)
      .digest('hex');
    if (hash !== expectedHash) return null;
    return userId;
  } catch (e) {
    return null;
  }
}

// Middleware Express pour vérifier l'authentification
// Ajoute req.userId si le token est valide
function authMiddleware(req, res, next) {
  var authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token manquant' });
  }
  var token = authHeader.replace('Bearer ', '');
  var userId = decodeToken(token);
  if (!userId) {
    return res.status(401).json({ success: false, message: 'Token invalide' });
  }
  req.userId = userId;
  next();
}

// Vérifie que l'utilisateur authentifié est un organisateur
// À chaîner après authMiddleware. Pose req.user = { id, nom, prenom, phone, role }.
function requireOrganizer(req, res, next) {
  pool.query('SELECT id, nom, prenom, phone, role FROM users WHERE id = $1', [req.userId])
    .then(function(result) {
      if (result.rows.length === 0) {
        return res.status(401).json({ success: false, message: 'Utilisateur introuvable' });
      }
      var user = result.rows[0];
      if (user.role !== 'organisateur') {
        return res.status(403).json({ success: false, message: 'Réservé aux organisateurs' });
      }
      req.user = user;
      next();
    })
    .catch(function(err) {
      console.error('Erreur requireOrganizer:', err.message);
      res.status(500).json({ success: false, message: 'Erreur serveur' });
    });
}

module.exports = {
  generateToken: generateToken,
  decodeToken: decodeToken,
  authMiddleware: authMiddleware,
  requireOrganizer: requireOrganizer
};
