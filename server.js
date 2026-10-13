// AWAB CLIM — admin/content API (zero-dependency Node)
const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.PORT || 10000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const TOKEN_SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString('hex');
const FILE = path.join(__dirname, 'content.json');

const DEFAULT_CONTENT = {
  brand: 'AWAB CLIM',
  tagline: 'Votre confort, notre priorité !',
  heroTitleFR: "Climatisation professionnelle à Tanger — installation, VRV/VRF & maintenance pour les projets qui ne peuvent pas s'arrêter.",
  heroSubFR: "Hôtels, cliniques, usines, bureaux et résidences : étude, dimensionnement, installation et contrats de maintenance annuels.",
  phoneDisplay: '+212 699-963530',
  phoneIntl: '212699963530',
  email: 'awabclimatisation@gmail.com',
  yearsExperience: 12,
  servicesFR: [],
  testimonials: [
    { name: 'Client villa — Malabata (démo)', text: "Installation gainable propre et silencieuse, chantier terminé dans les délais annoncés.", stars: 5 },
    { name: 'Gérant de café — Centre-ville (démo)', text: "Contrat de maintenance sérieux : visites à l'heure et rapport après chaque passage.", stars: 5 },
    { name: 'Syndic de résidence — Gzenaya (démo)', text: "Devis clair sous 48h et équipe respectueuse. On recommande pour les résidences.", stars: 5 }
  ],
  announcement: ''
};

function loadContent() {
  try { return { ...DEFAULT_CONTENT, ...JSON.parse(fs.readFileSync(FILE, 'utf8')) }; }
  catch { return { ...DEFAULT_CONTENT }; }
}
function saveContent(c) { fs.writeFileSync(FILE, JSON.stringify(c, null, 2)); }

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function verify(token) {
  try {
    const [body, sig] = String(token).split('.');
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    return payload.exp > Date.now() && payload.email === ADMIN_EMAIL;
  } catch { return false; }
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,PUT,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const json = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
  const readBody = () => new Promise((resolve, reject) => {
    let d = ''; req.on('data', c => { d += c; if (d.length > 200000) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch (e) { reject(e); } });
  });

  if (req.url === '/api/health') return json(200, { ok: true, service: 'ayoub-clima-admin' });
  if (req.url === '/' ) { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('AWAB CLIM — admin API'); }
  if (req.url === '/api/content' && req.method === 'GET') return json(200, loadContent());
  if (req.url === '/api/login' && req.method === 'POST') {
    return readBody().then(b => {
      const ok = ADMIN_EMAIL && b.email === ADMIN_EMAIL && typeof b.password === 'string' &&
        crypto.timingSafeEqual(Buffer.from(String(b.password).replace(/\s+/g, '').toLowerCase().padEnd(64, ' ')), Buffer.from(String(ADMIN_PASSWORD || '').replace(/\s+/g, '').toLowerCase().padEnd(64, ' '))) && String(b.password).replace(/\s+/g, '').toLowerCase() === String(ADMIN_PASSWORD || '').replace(/\s+/g, '').toLowerCase();
      if (!ok) return json(401, { error: 'Email ou mot de passe incorrect' });
      json(200, { token: sign({ email: ADMIN_EMAIL, exp: Date.now() + 12 * 3600 * 1000 }) });
    }).catch(() => json(400, { error: 'bad request' }));
  }
  if (req.url === '/api/content' && req.method === 'PUT') {
    const auth = (req.headers.authorization || '').replace('Bearer ', '');
    if (!verify(auth)) return json(401, { error: 'unauthorized' });
    return readBody().then(b => {
      const merged = { ...loadContent(), ...b };
      saveContent(merged); json(200, { ok: true, content: merged });
    }).catch(() => json(400, { error: 'bad request' }));
  }
  json(404, { error: 'not found' });
});
server.listen(PORT, () => console.log('listening on ' + PORT));
