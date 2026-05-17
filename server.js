require('dotenv').config();
const express = require('express');
const fs      = require('fs');
const path    = require('path');
const babel   = require('@babel/core');

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

// Pre-compile the JSX template once at startup
let compiledHtml;
try {
  const tmpl = fs.readFileSync(path.join(__dirname, 'template.html'), 'utf8');
  // Extract JSX block and compile server-side
  const compiled = tmpl.replace(
    /<script type="text\/babel">([\s\S]*?)<\/script>/,
    (_, jsx) => {
      const result = babel.transformSync(jsx, {
        presets: [
          ['@babel/preset-env', { targets: { browsers: ['last 2 years'] }, modules: false }],
          ['@babel/preset-react', { runtime: 'classic' }],
        ],
        compact: false,
      });
      return `<script>\n${result.code}\n</script>`;
    }
  );
  // Remove Babel standalone CDN tag (no longer needed)
  compiledHtml = compiled.replace(/<script[^>]*babel[^>]*><\/script>\n?/g, '');
  console.log('JSX compiled successfully at startup');
} catch (err) {
  console.error('Babel compilation error:', err.message);
  // Show error directly in the page so we can diagnose it
  const errMsg = (err.message || 'Unknown error').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  compiledHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Compile Error</title></head><body>
    <pre style="padding:24px;font-family:monospace;font-size:13px;color:#dc2626;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;margin:24px;white-space:pre-wrap">
BABEL COMPILE ERROR:\n${errMsg}
    </pre></body></html>`;
}

app.get('/', (req, res) => {
  const html = compiledHtml.replace('"__FIREBASE_CONFIG__"', firebaseConfig);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

app.use(express.static(__dirname));

app.listen(PORT, () => {
  console.log(`REVIVE Mitarbeiter läuft auf http://localhost:${PORT}`);
});
