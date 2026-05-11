require('dotenv').config();
const express = require('express');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

const firebaseConfig = JSON.stringify({
  apiKey:            process.env.FIREBASE_API_KEY,
  authDomain:        process.env.FIREBASE_AUTH_DOMAIN,
  projectId:         process.env.FIREBASE_PROJECT_ID,
  storageBucket:     process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId:             process.env.FIREBASE_APP_ID,
});

app.get('/', (req, res) => {
  const tmpl = fs.readFileSync(path.join(__dirname, 'template.html'), 'utf8');
  const html = tmpl.replace('"__FIREBASE_CONFIG__"', firebaseConfig);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

app.use(express.static(__dirname));

app.listen(PORT, () => {
  console.log(`REVIVE Mitarbeiter läuft auf http://localhost:${PORT}`);
});
