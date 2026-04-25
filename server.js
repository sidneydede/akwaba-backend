// server.js — Point d'entrée du backend Akwaba
// API REST pour la billetterie événementielle

require('dotenv').config();

var express = require('express');
var cors = require('cors');

var authRoutes = require('./routes/auth');
var eventsRoutes = require('./routes/events');
var bookingsRoutes = require('./routes/bookings');
var paymentsRoutes = require('./routes/payments');
var devicesRoutes = require('./routes/devices');

var app = express();
var PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json());

// Route santé
app.get('/', function(req, res) {
  res.json({
    message: 'Akwaba API fonctionne !',
    version: '2.0.0',
    database: 'PostgreSQL'
  });
});

// Routes API
app.use('/auth', authRoutes);
app.use('/events', eventsRoutes);
app.use('/bookings', bookingsRoutes);
app.use('/payments', paymentsRoutes);
app.use('/devices', devicesRoutes);

// Démarrage du serveur
app.listen(PORT, function() {
  console.log('Akwaba API démarrée sur le port ' + PORT);
});
