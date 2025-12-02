'use strict';
const fs = require('fs');
const http = require('http');
const https = require('https');
const express = require('express');
const bodyParser = require('body-parser');
const db = require('./db');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(bodyParser.json());

// Basic rate limiting to reduce abuse (demo)
app.use(rateLimit({ windowMs: 10*1000, max: 50 }));

const ADMIN_KEY = process.env.ADMIN_KEY || 'demo-admin-key';
const JWT_SECRET = process.env.JWT_SECRET || 'demo-jwt-secret';

function luhnCheck(cardNumber){
  // strip non-digits
  const digits = cardNumber.replace(/\D/g, '');
  let sum = 0;
  let alt = false;
  for(let i = digits.length - 1; i >= 0; i--){
    let d = parseInt(digits[i], 10);
    if(alt){ d *= 2; if(d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return (sum % 10) === 0;
}

function generateToken(){
  return 'tok_' + crypto.randomBytes(24).toString('hex');
}

// Create merchant and return API JWT (demo)
app.post('/api/merchants', async (req, res) => {
  try {
    const {name, email} = req.body;
    if(!name || !email) return res.status(400).json({error:'missing fields'});
    const id = uuidv4();
    await db.run('INSERT INTO merchants(id,name,email,created_at) VALUES(?,?,?,datetime("now"))', [id,name,email]);
    // create a merchant JWT (demo) — in real life you'd implement proper onboarding and secrets
    const token = jwt.sign({merchant_id:id, name}, JWT_SECRET, {expiresIn:'30d'});
    res.json({id, name, email, api_key: token});
  } catch(e){
    console.error(e);
    res.status(500).json({error:'internal'});
  }
});

// Tokenize card — demo only. Do NOT send real PANs in non-compliant environments.
app.post('/api/tokenize', async (req, res) => {
  try {
    const {card_number, exp_month, exp_year} = req.body;
    if(!card_number || !exp_month || !exp_year) return res.status(400).json({error:'missing card fields'});
    if(!luhnCheck(card_number)) return res.status(400).json({error:'invalid card number (failed Luhn)'});
    // create secure random token and store metadata only (no PAN, no CVV)
    const token = generateToken();
    const last4 = card_number.replace(/\D/g,'').slice(-4);
    const expires_at = Math.floor(Date.now()/1000) + (60*60*24*30); // token 30 days
    await db.run('INSERT INTO tokens(token,last4,exp_month,exp_year,expires_at,created_at) VALUES(?,?,?,?,?,datetime("now"))', [token,last4,exp_month,exp_year,expires_at]);
    res.json({token, last4, expires_at});
  } catch(e){
    console.error(e);
    res.status(500).json({error:'internal'});
  }
});

// Create a charge using token — merchant must authenticate with JWT in Authorization header
app.post('/api/charges', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const match = auth.match(/^Bearer\s+(.*)$/i);
    if(!match) return res.status(401).json({error:'missing auth'});
    const apiKey = match[1];
    let decoded;
    try { decoded = jwt.verify(apiKey, JWT_SECRET); } catch(e){ return res.status(401).json({error:'invalid auth'}); }
    const merchant_id = decoded.merchant_id;
    const {token, amount_cents, currency, description} = req.body;
    if(!token || !amount_cents) return res.status(400).json({error:'missing fields'});
    // check token exists and not expired
    const tkn = await db.get('SELECT * FROM tokens WHERE token = ?', [token]);
    if(!tkn) return res.status(400).json({error:'invalid token'});
    const now = Math.floor(Date.now()/1000);
    if(tkn.expires_at && now > tkn.expires_at) return res.status(400).json({error:'token expired'});
    if(amount_cents > 1000000) return res.status(400).json({error:'amount exceeds demo limit'});
    const id = uuidv4();
    const status = 'succeeded'; // demo always succeeds
    await db.run('INSERT INTO charges(id,merchant_id,token,last4,amount_cents,currency,status,description,created_at) VALUES(?,?,?,?,?,?,?,?,datetime("now"))',
      [id, merchant_id, token, tkn.last4, amount_cents, currency||'USD', status, description||'']);
    console.log('[webhook simulated] charge.succeeded', {id, merchant_id, amount_cents});
    res.json({id, status});
  } catch(e){
    console.error(e);
    res.status(500).json({error:'internal'});
  }
});

// Refund a charge
app.post('/api/refunds', async (req, res) => {
  try {
    const {charge_id, reason} = req.body;
    if(!charge_id) return res.status(400).json({error:'missing charge_id'});
    const charge = await db.get('SELECT * FROM charges WHERE id = ?', [charge_id]);
    if(!charge) return res.status(404).json({error:'charge not found'});
    const id = uuidv4();
    await db.run('INSERT INTO refunds(id,charge_id,amount_cents,reason,created_at) VALUES(?,?,?,?,datetime("now"))', [id, charge_id, charge.amount_cents, reason||'']);
    await db.run('UPDATE charges SET status = ? WHERE id = ?', ['refunded', charge_id]);
    res.json({id, status:'refunded'});
  } catch(e){
    console.error(e);
    res.status(500).json({error:'internal'});
  }
});

// Admin DB view (requires ADMIN_KEY header 'x-admin-key')
app.get('/api/admin/db', async (req, res) => {
  const key = req.headers['x-admin-key'];
  if(key !== ADMIN_KEY) return res.status(403).json({error:'forbidden'});
  const merchants = await db.all('SELECT id,name,email,created_at FROM merchants');
  const tokens = await db.all('SELECT token,last4,exp_month,exp_year,expires_at,created_at FROM tokens');
  const charges = await db.all('SELECT * FROM charges');
  res.json({merchants, tokens, charges});
});

// Serve a demo static frontend
app.use(express.static('public'));

const HTTP_PORT = process.env.PORT || 3000;
const HTTPS_PORT = process.env.HTTPS_PORT || 3443;

// Start server; if cert.pem/key.pem exist, start HTTPS as well (dev)
async function start(){
  await db.init();
  // HTTP server
  http.createServer(app).listen(HTTP_PORT, () => console.log('HTTP running on', HTTP_PORT));
  // HTTPS if certs exist
  if(fs.existsSync('cert.pem') && fs.existsSync('key.pem')){
    const options = { cert: fs.readFileSync('cert.pem'), key: fs.readFileSync('key.pem') };
    https.createServer(options, app).listen(HTTPS_PORT, () => console.log('HTTPS running on', HTTPS_PORT));
  } else {
    console.log('HTTPS cert/key missing; create cert.pem and key.pem to enable HTTPS (see README)');
  }
}

start().catch(e => { console.error(e); process.exit(1); });
