const express = require('express');
const fs      = require('fs');
const path    = require('path');
const Babel   = require('@babel/standalone');

const app  = express();
const PORT = process.env.PORT || 3000;

// Firebase web config — intentionally hardcoded (public client config, no secret)
const firebaseConfig = JSON.stringify({
  apiKey:            "AIzaSyAB9ugtPhwbXTJc9mZia6a_x54LEYLz5PE",
  authDomain:        "r3zahlen.firebaseapp.com",
  projectId:         "r3zahlen",
  storageBucket:     "r3zahlen.firebasestorage.app",
  messagingSenderId: "1071865171603",
  appId:             "1:1071865171603:web:399ef56359d043e7544766",
});

// Pre-compile JSX once at startup
let compiledHtml;
try {
  const tmpl = fs.readFileSync(path.join(__dirname, 'template.html'), 'utf8');
  compiledHtml = tmpl.replace(
    /<script type="text\/babel">([\s\S]*?)<\/script>/,
    (_, jsx) => {
      const result = Babel.transform(jsx, {
        presets: ['react'],
        plugins: ['transform-optional-chaining', 'transform-nullish-coalescing-operator'],
        sourceType: 'script',
      });
      return `<script>\n${result.code}\n</script>`;
    }
  );
  console.log('JSX compiled successfully');
} catch (err) {
  console.error('Babel error:', err.message);
  const msg = (err.message || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  compiledHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Build Error</title></head><body>
    <pre style="padding:24px;font-family:monospace;font-size:13px;color:#dc2626;background:#fef2f2;margin:24px;white-space:pre-wrap">BUILD ERROR:\n${msg}</pre>
  </body></html>`;
}

app.get('/', (req, res) => {
  const html = compiledHtml.replace('"__FIREBASE_CONFIG__"', firebaseConfig);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.send(html);
});

app.use(express.static(__dirname));

app.listen(PORT, () => {
  console.log(`REVIVE Mitarbeiter läuft auf http://localhost:${PORT}`);
});
