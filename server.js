// BuySmart - single-file bundle for easy deployment (Render/Railway/etc).
// Generated from the full multi-file source (see the project zip for the readable version).
'use strict';
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');
const { URL } = require('url');
const querystring = require('querystring');


// ===== lib/db.js =====
// Zero-dependency JSON-file data layer.
// NOTE: this is intentionally simple so the project runs anywhere with just Node.js
// installed (no npm install, no database server required) for demo/local use.
// Before deploying to a serverless host (Vercel, Netlify, etc.) swap this module out
// for a real database (Postgres via Supabase/Neon + Prisma is recommended - see README)
// because serverless filesystems are read-only / ephemeral.




const DATA_DIR = path.join(__dirname, 'data');

function filePath(name) {
  return path.join(DATA_DIR, `${name}.json`);
}

function readJSON(name, fallback) {
  try {
    const raw = fs.readFileSync(filePath(name), 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    return fallback;
  }
}

function writeJSON(name, data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(filePath(name), JSON.stringify(data, null, 2));
}

function id() {
  return crypto.randomBytes(9).toString('hex');
}

function slugify(str) {
  return String(str)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}

// ---------- Properties ----------
const Properties = {
  all() {
    return readJSON('properties', []);
  },
  get(id) {
    return this.all().find((p) => p.id === id);
  },
  getBySlug(slug) {
    return this.all().find((p) => p.slug === slug);
  },
  create(data) {
    const list = this.all();
    const now = new Date().toISOString();
    const baseSlug = slugify(`${data.title}-${data.suburb}`);
    let slug = baseSlug;
    let n = 1;
    while (list.some((p) => p.slug === slug)) {
      slug = `${baseSlug}-${n++}`;
    }
    const record = Object.assign(
      {
        id: id(),
        slug,
        createdAt: now,
        updatedAt: now,
        status: 'available',
        images: [],
        features: [],
      },
      data,
      { slug }
    );
    list.unshift(record);
    writeJSON('properties', list);
    return record;
  },
  update(idVal, patch) {
    const list = this.all();
    const idx = list.findIndex((p) => p.id === idVal);
    if (idx === -1) return null;
    list[idx] = Object.assign({}, list[idx], patch, {
      id: list[idx].id,
      updatedAt: new Date().toISOString(),
    });
    writeJSON('properties', list);
    return list[idx];
  },
  remove(idVal) {
    const list = this.all();
    const next = list.filter((p) => p.id !== idVal);
    writeJSON('properties', next);
    return next.length !== list.length;
  },
};

// ---------- Leads / form submissions ----------
const Leads = {
  all() {
    return readJSON('leads', []).sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  },
  get(id) {
    return this.all().find((l) => l.id === id);
  },
  create(data) {
    const list = readJSON('leads', []);
    const record = Object.assign(
      {
        id: id(),
        createdAt: new Date().toISOString(),
        status: 'new',
        sentToGHL: false,
        ghlResponse: null,
      },
      data
    );
    list.unshift(record);
    writeJSON('leads', list);
    return record;
  },
  update(idVal, patch) {
    const list = readJSON('leads', []);
    const idx = list.findIndex((l) => l.id === idVal);
    if (idx === -1) return null;
    list[idx] = Object.assign({}, list[idx], patch);
    writeJSON('leads', list);
    return list[idx];
  },
};

// ---------- Users (admin backend accounts) ----------
const Users = {
  all() {
    return readJSON('users', []);
  },
  get(id) {
    return this.all().find((u) => u.id === id);
  },
  getByEmail(email) {
    return this.all().find((u) => u.email.toLowerCase() === String(email).toLowerCase());
  },
  create(data) {
    const list = this.all();
    const record = Object.assign(
      { id: id(), createdAt: new Date().toISOString(), role: 'staff' },
      data
    );
    list.push(record);
    writeJSON('users', list);
    return record;
  },
  update(idVal, patch) {
    const list = this.all();
    const idx = list.findIndex((u) => u.id === idVal);
    if (idx === -1) return null;
    list[idx] = Object.assign({}, list[idx], patch);
    writeJSON('users', list);
    return list[idx];
  },
  remove(idVal) {
    const list = this.all();
    const next = list.filter((u) => u.id !== idVal);
    writeJSON('users', next);
    return next.length !== list.length;
  },
};

// ---------- Site content blocks (editable copy) ----------
const Content = {
  all() {
    return readJSON('content', {});
  },
  get(key, fallback) {
    const c = this.all();
    return key in c ? c[key] : fallback;
  },
  set(key, value) {
    const c = this.all();
    c[key] = value;
    writeJSON('content', c);
    return c;
  },
  setMany(patch) {
    const c = this.all();
    Object.assign(c, patch);
    writeJSON('content', c);
    return c;
  },
};



// ===== lib/auth.js =====
// Zero-dependency auth: scrypt password hashing (Node built-in crypto) +
// HMAC-signed, HTTP-only session cookies. No external packages required.


const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-only-insecure-secret-change-me';
const COOKIE_NAME = 'buysmart_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 12; // 12 hours

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function sign(payloadObj) {
  const payload = base64url(JSON.stringify(payloadObj));
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verify(token) {
  if (!token || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (data.exp && Date.now() > data.exp) return null;
    return data;
  } catch (e) {
    return null;
  }
}

function createSessionCookie(user) {
  const token = sign({ uid: user.id, role: user.role, exp: Date.now() + SESSION_TTL_MS });
  const secure = process.env.NODE_ENV === 'production' ? ' Secure;' : '';
  return `${COOKIE_NAME}=${token}; HttpOnly; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}; SameSite=Lax;${secure}`;
}

function clearSessionCookie() {
  return `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax;`;
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

function getSessionFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[COOKIE_NAME];
  return verify(token);
}

module.exports = {
  COOKIE_NAME,
  hashPassword,
  verifyPassword,
  createSessionCookie,
  clearSessionCookie,
  parseCookies,
  getSessionFromRequest,
};


// ===== lib/ghl.js =====
// Go High Level (GHL) integration hook.
//
// No live GHL credentials were available when this project was built, so this module
// is wired to a configurable *inbound webhook* - the fastest way to connect a GHL
// sub-account to an external site with zero code changes on the GHL side:
//
//   1. In GHL: Automation -> Workflows -> Create Workflow -> Trigger = "Inbound Webhook".
//      Copy the generated webhook URL.
//   2. Paste it into GHL_WEBHOOK_URL in your .env file (see .env.example).
//   3. Every submission from the Property Brief, Contact and Property Enquiry forms on
//      this site will be POSTed to that URL as JSON (shape below), and the workflow can
//      then create/update the Contact, tag them, and kick off nurture sequences.
//
// If you'd rather integrate via the GHL REST API / Private Integration (e.g. to search
// for existing contacts, attach to a specific pipeline, or use custom field IDs) a
// commented-out alternative implementation is included below - swap it in once you have
// GHL_API_KEY and GHL_LOCATION_ID.




function buildGHLPayload(lead) {
  // Field mapping: keep this in sync with the GHL workflow's expected keys.
  return {
    formType: lead.type, // 'property-brief' | 'contact' | 'property-enquiry'
    firstName: lead.firstName || '',
    lastName: lead.lastName || '',
    email: lead.email || '',
    phone: lead.phone || '',
    source: 'BuySmart Website',
    tags: [lead.type === 'property-brief' ? 'buysmart-property-brief' : 'buysmart-lead'],
    message: lead.message || '',
    customFields: {
      suburbPreferences: lead.suburbPreferences || '',
      budgetMin: lead.budgetMin || '',
      budgetMax: lead.budgetMax || '',
      propertyType: lead.propertyType || '',
      bedrooms: lead.bedrooms || '',
      purchaseTimeframe: lead.timeframe || '',
      relatedPropertyId: lead.relatedPropertyId || '',
      relatedPropertyTitle: lead.relatedPropertyTitle || '',
      submittedAt: lead.createdAt,
    },
  };
}

function postJSON(urlString, jsonBody, extraHeaders = {}) {
  return new Promise((resolve) => {
    let target;
    try {
      target = new URL(urlString);
    } catch (e) {
      resolve({ ok: false, error: 'Invalid GHL_WEBHOOK_URL' });
      return;
    }
    const data = JSON.stringify(jsonBody);
    const isHttps = target.protocol === 'https:';
    const transport = isHttps ? https : http;
    const req = transport.request(
      {
        hostname: target.hostname,
        path: target.pathname + (target.search || ''),
        method: 'POST',
        port: target.port || (isHttps ? 443 : 80),
        headers: Object.assign(
          { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
          extraHeaders
        ),
        timeout: 8000,
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () =>
          resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, statusCode: res.statusCode, body })
        );
      }
    );
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, error: 'timeout' });
    });
    req.on('error', (err) => resolve({ ok: false, error: err.message }));
    req.write(data);
    req.end();
  });
}

async function forwardToGHL(lead) {
  const webhookUrl = process.env.GHL_WEBHOOK_URL;
  const payload = buildGHLPayload(lead);

  if (!webhookUrl) {
    return {
      attempted: false,
      ok: false,
      note: 'GHL_WEBHOOK_URL is not configured yet - lead was saved locally only. Add it to your .env and resend from Admin > Leads.',
      payload,
    };
  }

  const result = await postJSON(webhookUrl, payload);
  return { attempted: true, ok: result.ok, detail: result, payload };
}

/* ---------- Alternative: GHL REST API / Private Integration approach ----------
async function forwardToGHLViaAPI(lead) {
  const payload = buildGHLPayload(lead);
  const result = await postJSON('https://services.leadconnectorhq.com/contacts/upsert', {
    locationId: process.env.GHL_LOCATION_ID,
    firstName: payload.firstName,
    lastName: payload.lastName,
    email: payload.email,
    phone: payload.phone,
    tags: payload.tags,
    customFields: payload.customFields,
  }, {
    Authorization: `Bearer ${process.env.GHL_API_KEY}`,
    Version: '2021-07-28',
  });
  return { attempted: true, ok: result.ok, detail: result, payload };
}
module.exports.forwardToGHLViaAPI = forwardToGHLViaAPI;
---------------------------------------------------------------------------- */



// ===== lib/render.js =====
function esc(str) {
  if (str === undefined || str === null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function money(n) {
  if (n === undefined || n === null || n === '') return '';
  const num = Number(n);
  if (Number.isNaN(num)) return esc(n);
  return '$' + num.toLocaleString('en-AU');
}

function priceLabel(p) {
  if (p.priceLabel) return esc(p.priceLabel);
  if (p.priceMin && p.priceMax) return `${money(p.priceMin)} - ${money(p.priceMax)}`;
  if (p.priceMin) return `From ${money(p.priceMin)}`;
  return 'Price on application';
}

function listingTypeBadge(type) {
  const map = {
    'off-market': { label: 'Off-Market', cls: 'badge-offmarket' },
    'pre-market': { label: 'Pre-Market', cls: 'badge-premarket' },
    'on-market': { label: 'On-Market', cls: 'badge-onmarket' },
  };
  const v = map[type] || { label: type, cls: '' };
  return `<span class="badge ${v.cls}">${esc(v.label)}</span>`;
}

function statusBadge(status) {
  const map = {
    available: { label: 'Available', cls: 'badge-available' },
    'under-offer': { label: 'Under Offer', cls: 'badge-underoffer' },
    sold: { label: 'Sold', cls: 'badge-sold' },
  };
  const v = map[status] || { label: status, cls: '' };
  return `<span class="badge ${v.cls}">${esc(v.label)}</span>`;
}

function layout({ title, description = '', activeNav = '', body = '', head = '' }) {
  return `<!doctype html>
<html lang="en-AU">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${esc(title)} | BuySmart</title>
<meta name="description" content="${esc(description)}" />
<link rel="stylesheet" href="/static/styles.css" />
<link rel="icon" href="data:;base64,iVBORw0KGgo=" />
${head}
</head>
<body>
<header class="site-header">
  <div class="container header-inner">
    <a class="brand" href="/">
      <img src="/static/logo.svg" alt="BuySmart" class="brand-logo" />
      <span class="brand-sub">Powered by The Local Experts Buyers Agents Division</span>
    </a>
    <nav class="main-nav">
      <a href="/listings" class="${activeNav === 'listings' ? 'active' : ''}">Listings</a>
      <a href="/about" class="${activeNav === 'about' ? 'active' : ''}">How It Works</a>
      <a href="/contact" class="${activeNav === 'contact' ? 'active' : ''}">Contact</a>
      <a href="/property-brief" class="btn btn-primary btn-sm">Submit a Property Brief</a>
    </nav>
    <button class="nav-toggle" id="navToggle" aria-label="Menu">&#9776;</button>
  </div>
</header>
<main>
${body}
</main>
<footer class="site-footer">
  <div class="container footer-inner">
    <div>
      <img src="/static/logo-white.svg" alt="BuySmart" class="footer-logo" />
      <p class="footer-sub">Powered by The Local Experts Buyers Agents Division</p>
      <p class="footer-copy">&copy; ${new Date().getFullYear()} BuySmart. All rights reserved.</p>
    </div>
    <div class="footer-col">
      <h4>Explore</h4>
      <a href="/listings">Pre &amp; Off-Market Listings</a>
      <a href="/about">How Buyers Agency Works</a>
      <a href="/property-brief">Submit a Property Brief</a>
      <a href="/contact">Contact Us</a>
    </div>
    <div class="footer-col">
      <h4>Legal</h4>
      <a href="/privacy">Privacy Policy</a>
      <a href="/terms">Terms of Service</a>
    </div>
  </div>
</footer>
<script src="/static/app.js"></script>
</body>
</html>`;
}

function adminLayout({ title, activeNav = '', body = '', session = null }) {
  const nav = [
    ['dashboard', '/admin', 'Dashboard'],
    ['properties', '/admin/properties', 'Properties'],
    ['leads', '/admin/leads', 'Leads &amp; Enquiries'],
    ['content', '/admin/content', 'Site Content'],
    ['users', '/admin/users', 'Users &amp; Permissions'],
    ['settings', '/admin/settings', 'Integrations &amp; Settings'],
  ];
  const navHtml = nav
    .map(
      ([key, href, label]) =>
        `<a href="${href}" class="${activeNav === key ? 'active' : ''}">${label}</a>`
    )
    .join('\n');
  return `<!doctype html>
<html lang="en-AU">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${esc(title)} | BuySmart Admin</title>
<link rel="stylesheet" href="/static/styles.css" />
</head>
<body class="admin-body">
<div class="admin-shell">
  <aside class="admin-sidebar">
    <div class="admin-brand"><img src="/static/logo-white.svg" alt="BuySmart" class="admin-logo" /><span>Admin</span></div>
    <nav class="admin-nav">${navHtml}</nav>
    <div class="admin-sidebar-footer">
      <div class="admin-user">${session ? esc(session.name || session.email) : ''}</div>
      <form method="post" action="/admin/logout"><button class="btn btn-ghost btn-sm" type="submit">Log out</button></form>
      <a class="back-to-site" href="/">&larr; View live site</a>
    </div>
  </aside>
  <div class="admin-main">
    <header class="admin-topbar"><h1>${esc(title)}</h1></header>
    <div class="admin-content">${body}</div>
  </div>
</div>
<script src="/static/app.js"></script>
</body>
</html>`;
}

function flash(query, mapping) {
  if (!query) return '';
  for (const key of Object.keys(mapping)) {
    if (query[key]) {
      const msg = mapping[key];
      return `<div class="alert alert-${msg.type}">${esc(msg.text)}</div>`;
    }
  }
  return '';
}



// ===== lib/seed.js =====




const SAMPLE_PROPERTIES = [
  {
    title: 'Character Federation Home',
    suburb: 'Camberwell', state: 'VIC', postcode: '3124',
    propertyType: 'House', listingType: 'off-market', status: 'available',
    priceMin: 1850000, priceMax: 2050000,
    bedrooms: 4, bathrooms: 2, carSpaces: 2, landSize: 612,
    description: 'A beautifully preserved Federation home on a quiet, tree-lined street, secured for our buyer before it ever reached the open market. North-facing rear garden, high ceilings, and a renovated kitchen that opens onto a covered alfresco area.',
    features: ['North-facing rear garden', 'Renovated kitchen', 'Covered alfresco', 'Off-street parking for 2 cars', 'Walk to Camberwell Junction', 'Zoned for Camberwell High School'],
  },
  {
    title: 'Off-Market Riverside Townhouse',
    suburb: 'New Farm', state: 'QLD', postcode: '4005',
    propertyType: 'Townhouse', listingType: 'off-market', status: 'available',
    priceMin: 1150000, priceMax: 1250000,
    bedrooms: 3, bathrooms: 2, carSpaces: 2, landSize: 220,
    description: 'Sourced directly through our agent network before any marketing began. Modern three-level townhouse moments from the river walk and New Farm Park, with a private rooftop terrace.',
    features: ['Private rooftop terrace', 'Two secure car spaces', 'Walk to New Farm Park', 'Low-maintenance courtyard', 'Ducted air conditioning'],
  },
  {
    title: 'Pre-Market Family Acreage',
    suburb: 'Samford Valley', state: 'QLD', postcode: '4520',
    propertyType: 'Acreage', listingType: 'pre-market', status: 'available',
    priceMin: 1650000, priceMax: 1750000,
    bedrooms: 5, bathrooms: 3, carSpaces: 4, landSize: 20234,
    description: 'The owners are preparing to list publicly in the coming weeks - our buyer clients get first access now. Sprawling 5-bedroom homestead on 2 hectares with a pool, shedding, and horse paddocks.',
    features: ['In-ground pool', 'Powered 6-bay shed', 'Fenced horse paddocks', 'Solar power system', 'Renovated homestead kitchen'],
  },
  {
    title: 'Pre-Market Coastal Apartment',
    suburb: 'Cronulla', state: 'NSW', postcode: '2230',
    propertyType: 'Apartment', listingType: 'pre-market', status: 'available',
    priceMin: 980000, priceMax: 1050000,
    bedrooms: 2, bathrooms: 2, carSpaces: 1, landSize: null,
    description: 'The seller has engaged us ahead of a planned campaign next month. Top-floor apartment with ocean glimpses, a short stroll to Cronulla Beach and the esplanade cafes.',
    features: ['Ocean glimpses', 'Top floor, no rear neighbours', 'Secure basement parking', 'Recently updated bathrooms', '450m to the beach'],
  },
  {
    title: 'Off-Market Investment Duplex',
    suburb: 'Mile End', state: 'SA', postcode: '5031',
    propertyType: 'Duplex', listingType: 'off-market', status: 'under-offer',
    priceMin: 720000, priceMax: 760000,
    bedrooms: 3, bathrooms: 2, carSpaces: 2, landSize: 310,
    description: 'A strong-yielding investment secured through our off-market network, 4km from the Adelaide CBD. Currently tenanted with a reliable rental history.',
    features: ['Currently tenanted', 'Separately titled', 'Close to tram line', 'Low-maintenance gardens'],
  },
  {
    title: 'Pre-Market Hills Retreat',
    suburb: 'Aldgate', state: 'SA', postcode: '5154',
    propertyType: 'House', listingType: 'pre-market', status: 'available',
    priceMin: 1050000, priceMax: 1150000,
    bedrooms: 4, bathrooms: 2, carSpaces: 2, landSize: 1840,
    description: 'Nestled in the Adelaide Hills with established gardens and mountain views. The vendor plans to market publicly in 3-4 weeks; buyer brief clients are seeing it first.',
    features: ['Established cottage gardens', 'Mountain views', 'Wood fireplace', 'Double carport', 'Close to Aldgate Primary School'],
  },
  {
    title: 'Off-Market City Fringe Apartment',
    suburb: 'North Perth', state: 'WA', postcode: '6006',
    propertyType: 'Apartment', listingType: 'off-market', status: 'available',
    priceMin: 590000, priceMax: 630000,
    bedrooms: 2, bathrooms: 1, carSpaces: 1, landSize: null,
    description: 'A boutique block of only 8, secured through a direct owner relationship before any public listing. Easy access to the CBD via Fitzgerald Street.',
    features: ['Boutique block of 8', 'North-facing balcony', 'Secure car bay', 'Walk to Hyde Park'],
  },
  {
    title: 'On-Market Executive Home',
    suburb: 'Kew', state: 'VIC', postcode: '3101',
    propertyType: 'House', listingType: 'on-market', status: 'available',
    priceMin: 2450000, priceMax: 2650000,
    bedrooms: 5, bathrooms: 3, carSpaces: 2, landSize: 745,
    description: 'A architect-designed family home currently listed for sale, included here as part of our full-service buyers agency search alongside our exclusive off-market pool.',
    features: ['Architect designed', 'Home theatre', 'Heated pool', 'Double garage with internal access'],
  },
];

const SAMPLE_TESTIMONIALS = [
  { name: 'Sarah & Michael, Camberwell VIC', quote: 'BuySmart found us a home we never would have seen advertised. Their off-market access saved us from a bidding war entirely.' },
  { name: 'David T, New Farm QLD', quote: 'The property brief process was so thorough - by the time they showed us options, every single one was genuinely right for us.' },
  { name: 'Priya K, Cronulla NSW', quote: 'Professional from the first call to settlement. Having a buyers agent negotiate on our behalf was the best money we spent.' },
];

function seedIfEmpty() {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  if (Properties.all().length === 0) {
    SAMPLE_PROPERTIES.forEach((p) => Properties.create(p));
  }

  if (Users.all().length === 0) {
    Users.create({
      name: 'Paul',
      email: 'paul@thelocalexperts.com.au',
      passwordHash: hashPassword('BuySmart2026!'),
      role: 'admin',
    });
  }

  if (Object.keys(Content.all()).length === 0) {
    Content.setMany({
      heroEyebrow: "Australia's Largest Pre & Off-Market Property Network",
      heroHeading: 'Buy the property everyone else never sees.',
      heroSubheading:
        'BuySmart connects everyday Australians with a licensed buyers agent and the country’s largest pool of pre-market and off-market listings - so you can buy well, without the auction-day stress.',
      aboutIntro:
        'BuySmart is the buyer-facing arm of The Local Experts Buyers Agents Division. We pair you with a licensed local buyers agent who negotiates on your behalf, and gives you first access to pre-market and off-market properties that never reach realestate.com.au or Domain.',
      contactPhone: '1300 000 000',
      contactEmail: 'buyers@thelocalexperts.com.au',
      testimonials: SAMPLE_TESTIMONIALS,
    });
  }

  if (Leads.all().length === 0) {
    Leads.create({
      type: 'property-brief',
      firstName: 'Jordan', lastName: 'Ng', email: 'jordan.ng@example.com', phone: '0412 345 678',
      suburbPreferences: 'Camberwell, Hawthorn, Kew (VIC)', budgetMin: 1500000, budgetMax: 1900000,
      propertyType: 'House', bedrooms: '4', timeframe: '0-3 months',
      message: 'Looking for a family home close to good schools, ideally with a north-facing garden.',
      status: 'new',
    });
    Leads.create({
      type: 'contact',
      firstName: 'Amelia', lastName: 'Ross', email: 'amelia.ross@example.com', phone: '0400 111 222',
      message: 'Can you tell me more about how the buyers agent fee works?',
      status: 'contacted',
    });
  }
}



// ===== views/home.js =====

function propertyCard(p) {
  return `<a class="card-property" href="/listings/${p.slug}">
    <div class="thumb">
      <div class="badges">${listingTypeBadge(p.listingType)}</div>
      <div class="price-chip">${priceLabel(p)}</div>
    </div>
    <div class="body">
      <h3>${p.title}</h3>
      <div class="suburb">${p.suburb}, ${p.state} ${p.postcode}</div>
      <div class="meta">
        <span>${p.bedrooms} bed</span>
        <span>${p.bathrooms} bath</span>
        <span>${p.carSpaces} car</span>
      </div>
    </div>
  </a>`;
}

function render_home({ featured, content }) {
  const testimonials = content.testimonials || [];
  const body = `
  <section class="hero">
    <div class="container hero-inner">
      <div>
        <div class="eyebrow">${content.heroEyebrow}</div>
        <h1>${content.heroHeading}</h1>
        <p class="lead">${content.heroSubheading}</p>
        <div class="hero-actions">
          <a class="btn btn-primary" href="/property-brief">Submit a Property Brief</a>
          <a class="btn btn-outline" href="/listings">Browse Current Listings</a>
        </div>
        <div class="hero-stats">
          <div><div class="num">70%</div><div class="label">of our sales never hit the public portals</div></div>
          <div><div class="num">8</div><div class="label">states &amp; territories covered</div></div>
          <div><div class="num">1:1</div><div class="label">dedicated buyers agent per client</div></div>
        </div>
      </div>
      <div class="hero-card">
        <h3>What you get with BuySmart</h3>
        <ul>
          <li>First access to pre-market &amp; off-market properties</li>
          <li>A licensed buyers agent negotiating for you, not the seller</li>
          <li>A tailored Property Brief matched against our national network</li>
          <li>Support from search through to settlement</li>
        </ul>
        <a class="btn btn-navy btn-block" href="/property-brief">Get Started - It's Free</a>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="container">
      <div class="section-head">
        <div class="eyebrow">Featured Opportunities</div>
        <h2>Pre &amp; off-market properties available right now</h2>
        <p class="muted">A small sample of what our buyers agents currently have access to across the country.</p>
      </div>
      <div class="listing-grid">
        ${featured.map(propertyCard).join('\n')}
      </div>
      <div style="text-align:center; margin-top:34px;">
        <a class="btn btn-navy" href="/listings">View All Listings</a>
      </div>
    </div>
  </section>

  <section class="section alt">
    <div class="container">
      <div class="section-head">
        <div class="eyebrow">How It Works</div>
        <h2>From property brief to settlement</h2>
      </div>
      <div class="steps">
        <div class="step"><div class="num">1</div><h4>Tell us what you need</h4><p class="muted">Submit a free Property Brief detailing your budget, must-haves and target suburbs.</p></div>
        <div class="step"><div class="num">2</div><h4>Get matched with a buyers agent</h4><p class="muted">A licensed local buyers agent from The Local Experts network is assigned to you.</p></div>
        <div class="step"><div class="num">3</div><h4>See pre &amp; off-market options first</h4><p class="muted">We search our national network of exclusive listings before anything reaches the public.</p></div>
        <div class="step"><div class="num">4</div><h4>We negotiate, you settle</h4><p class="muted">Your agent negotiates and manages the purchase through to settlement.</p></div>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="container">
      <div class="section-head">
        <div class="eyebrow">What Buyers Say</div>
        <h2>Trusted by everyday Australians</h2>
      </div>
      <div class="grid-3">
        ${testimonials
          .map((t) => `<div class="testimonial"><p>&ldquo;${t.quote}&rdquo;</p><div class="who">${t.name}</div></div>`)
          .join('\n')}
      </div>
    </div>
  </section>

  <section class="section alt">
    <div class="container" style="text-align:center;">
      <h2>Ready to see what's not on the market yet?</h2>
      <p class="muted" style="max-width:520px;margin:0 auto 24px;">Submit a Property Brief and a BuySmart buyers agent will be in touch within one business day.</p>
      <a class="btn btn-primary" href="/property-brief">Submit a Property Brief</a>
    </div>
  </section>
  `;
  return layout({
    title: 'Buy Smarter with Australia’s Largest Pre & Off-Market Property Network',
    description: 'BuySmart, powered by The Local Experts Buyers Agents Division, connects buyers with pre-market and off-market property and a dedicated buyers agent.',
    activeNav: 'home',
    body,
  });
}



// ===== views/listings.js =====

function propertyCard(p) {
  return `<a class="card-property" href="/listings/${p.slug}">
    <div class="thumb">
      <div class="badges">${listingTypeBadge(p.listingType)}</div>
      <div class="price-chip">${priceLabel(p)}</div>
    </div>
    <div class="body">
      <h3>${p.title}</h3>
      <div class="suburb">${p.suburb}, ${p.state} ${p.postcode}</div>
      <div class="meta">
        <span>${p.bedrooms} bed</span>
        <span>${p.bathrooms} bath</span>
        <span>${p.carSpaces} car</span>
      </div>
      ${statusBadge(p.status)}
    </div>
  </a>`;
}

function option(value, label, current) {
  return `<option value="${esc(value)}" ${current === value ? 'selected' : ''}>${esc(label)}</option>`;
}

function render_listings({ properties, filters, states, suburbs }) {
  const body = `
  <section class="section" style="padding-bottom:0;">
    <div class="container">
      <div class="section-head" style="margin-bottom:24px;">
        <div class="eyebrow">Pre &amp; Off-Market Listings</div>
        <h2>Browse what's currently available</h2>
        <p class="muted">These are a sample of properties in our buyers agents' network. Most never appear on realestate.com.au or Domain - submit a Property Brief for full access.</p>
      </div>
      <form class="filters" method="get" action="/listings">
        <div class="field">
          <label>Listing type</label>
          <select name="listingType">
            ${option('', 'All types', filters.listingType)}
            ${option('off-market', 'Off-Market', filters.listingType)}
            ${option('pre-market', 'Pre-Market', filters.listingType)}
            ${option('on-market', 'On-Market', filters.listingType)}
          </select>
        </div>
        <div class="field">
          <label>State</label>
          <select name="state">
            ${option('', 'All states', filters.state)}
            ${states.map((s) => option(s, s, filters.state)).join('')}
          </select>
        </div>
        <div class="field">
          <label>Min bedrooms</label>
          <select name="bedrooms">
            ${option('', 'Any', filters.bedrooms)}
            ${['1', '2', '3', '4', '5'].map((b) => option(b, b + '+', filters.bedrooms)).join('')}
          </select>
        </div>
        <div class="field">
          <label>Max price</label>
          <select name="maxPrice">
            ${option('', 'Any', filters.maxPrice)}
            ${[700000, 1000000, 1500000, 2000000, 3000000]
              .map((v) => option(String(v), '$' + v.toLocaleString('en-AU'), filters.maxPrice))
              .join('')}
          </select>
        </div>
        <div class="field"><button class="btn btn-navy" type="submit">Filter</button></div>
      </form>
    </div>
  </section>
  <section class="section" style="padding-top:0;">
    <div class="container">
      <p class="muted" style="margin-bottom:18px;">${properties.length} propert${properties.length === 1 ? 'y' : 'ies'} found</p>
      <div class="listing-grid">
        ${properties.map(propertyCard).join('\n') || '<p class="muted">No properties match those filters yet - try widening your search or submit a Property Brief so a buyers agent can search on your behalf.</p>'}
      </div>
    </div>
  </section>
  `;
  return layout({
    title: 'Pre & Off-Market Property Listings',
    description: 'Browse pre-market and off-market property listings available through BuySmart buyers agents.',
    activeNav: 'listings',
    body,
  });
}



// ===== views/propertyDetail.js =====

function render_propertyDetail({ property, related }) {
  const body = `
  <section class="detail-hero">
    <div class="container">
      <div style="margin-bottom:10px;">${listingTypeBadge(property.listingType)} ${statusBadge(property.status)}</div>
      <h1 style="color:var(--ink);">${esc(property.title)}</h1>
      <p style="color:var(--ink-soft);">${esc(property.suburb)}, ${esc(property.state)} ${esc(property.postcode)}</p>
      <div style="font-size:26px;font-weight:800;color:var(--ink);">${priceLabel(property)}</div>
    </div>
  </section>
  <section class="section">
    <div class="container">
      <div class="detail-gallery">
        <div class="g-main"></div>
        <div class="g-side"><div></div><div></div></div>
      </div>
      <div class="detail-layout">
        <div>
          <div class="detail-facts">
            <div><div class="num">${property.bedrooms}</div><div class="label">Bedrooms</div></div>
            <div><div class="num">${property.bathrooms}</div><div class="label">Bathrooms</div></div>
            <div><div class="num">${property.carSpaces}</div><div class="label">Car Spaces</div></div>
            ${property.landSize ? `<div><div class="num">${property.landSize}m&sup2;</div><div class="label">Land Size</div></div>` : ''}
          </div>
          <h3>About this property</h3>
          <p>${esc(property.description)}</p>
          <h3>Features</h3>
          <ul class="feature-list">
            ${(property.features || []).map((f) => `<li>${esc(f)}</li>`).join('')}
          </ul>
        </div>
        <div>
          <div class="sticky-enquiry">
            <h3>Enquire about this property</h3>
            <p class="muted">Register your interest and a BuySmart buyers agent will contact you with full details.</p>
            <form data-ajax="true" method="post" action="/api/leads">
              <input type="hidden" name="type" value="property-enquiry" />
              <input type="hidden" name="relatedPropertyId" value="${esc(property.id)}" />
              <input type="hidden" name="relatedPropertyTitle" value="${esc(property.title)}" />
              <div class="field-label">First name</div>
              <input type="text" name="firstName" required style="margin-bottom:12px;" />
              <div class="field-label">Last name</div>
              <input type="text" name="lastName" required style="margin-bottom:12px;" />
              <div class="field-label">Email</div>
              <input type="email" name="email" required style="margin-bottom:12px;" />
              <div class="field-label">Phone</div>
              <input type="tel" name="phone" required style="margin-bottom:12px;" />
              <div class="field-label">Message</div>
              <textarea name="message" placeholder="I'd like more information about this property...">I'd like more information about ${esc(property.title)}.</textarea>
              <button class="btn btn-primary btn-block" style="margin-top:14px;" type="submit" data-label="Send Enquiry">Send Enquiry</button>
              <div class="form-status" style="display:none;margin-top:14px;"></div>
            </form>
          </div>
        </div>
      </div>
    </div>
  </section>
  `;
  return layout({
    title: property.title,
    description: `${property.title} - ${property.suburb}, ${property.state}. ${priceLabel(property)}.`,
    activeNav: 'listings',
    body,
  });
}



// ===== views/about.js =====

function render_about({ content }) {
  const body = `
  <section class="section">
    <div class="container">
      <div class="section-head">
        <div class="eyebrow">About BuySmart</div>
        <h2>Powered by The Local Experts Buyers Agents Division</h2>
      </div>
      <p style="max-width:760px;margin:0 auto 30px;text-align:center;">${content.aboutIntro}</p>
      <div class="steps">
        <div class="step"><div class="num">1</div><h4>Free Property Brief</h4><p class="muted">Tell us your budget, target suburbs, and must-haves. No cost, no obligation.</p></div>
        <div class="step"><div class="num">2</div><h4>Dedicated buyers agent</h4><p class="muted">A licensed local buyers agent from The Local Experts network is matched to your brief.</p></div>
        <div class="step"><div class="num">3</div><h4>Exclusive network search</h4><p class="muted">We tap Australia's largest pool of pre-market and off-market listings before public portals.</p></div>
        <div class="step"><div class="num">4</div><h4>Inspect &amp; shortlist</h4><p class="muted">Your agent arranges private inspections and due diligence on properties that fit.</p></div>
        <div class="step"><div class="num">5</div><h4>Negotiate on your behalf</h4><p class="muted">Your agent negotiates price and terms - working exclusively for you, not the seller.</p></div>
        <div class="step"><div class="num">6</div><h4>Settlement support</h4><p class="muted">We coordinate with your conveyancer/solicitor and lender through to keys-in-hand.</p></div>
      </div>
    </div>
  </section>
  <section class="section alt">
    <div class="container" style="text-align:center;">
      <h2>Why buyers choose a buyers agent</h2>
      <p class="muted" style="max-width:640px;margin:0 auto 24px;">Selling agents work for the seller. A BuySmart buyers agent is engaged exclusively by you - giving you an experienced, licensed advocate at every stage of the purchase, plus access to property you'd otherwise never see.</p>
      <a class="btn btn-primary" href="/property-brief">Submit a Property Brief</a>
    </div>
  </section>
  `;
  return layout({ title: 'How It Works', description: 'How BuySmart buyers agents help you access pre-market and off-market property.', activeNav: 'about', body });
}



// ===== views/contact.js =====

function render_contact({ content }) {
  const body = `
  <section class="section">
    <div class="container">
      <div class="section-head">
        <div class="eyebrow">Get In Touch</div>
        <h2>Contact BuySmart</h2>
        <p class="muted">Phone ${content.contactPhone} &middot; ${content.contactEmail}</p>
      </div>
      <div class="form-card">
        <form data-ajax="true" method="post" action="/api/leads">
          <input type="hidden" name="type" value="contact" />
          <div class="form-grid">
            <div><div class="field-label">First name</div><input type="text" name="firstName" required /></div>
            <div><div class="field-label">Last name</div><input type="text" name="lastName" required /></div>
            <div><div class="field-label">Email</div><input type="email" name="email" required /></div>
            <div><div class="field-label">Phone</div><input type="tel" name="phone" required /></div>
            <div class="full"><div class="field-label">How can we help?</div><textarea name="message" required></textarea></div>
          </div>
          <button class="btn btn-primary btn-block" style="margin-top:16px;" type="submit" data-label="Send Message">Send Message</button>
          <div class="form-status" style="display:none;margin-top:14px;"></div>
        </form>
      </div>
    </div>
  </section>
  `;
  return layout({ title: 'Contact Us', description: 'Contact BuySmart, powered by The Local Experts Buyers Agents Division.', activeNav: 'contact', body });
}



// ===== views/propertyBrief.js =====

function render_propertyBrief() {
  const body = `
  <section class="section">
    <div class="container">
      <div class="section-head">
        <div class="eyebrow">Free &middot; No Obligation</div>
        <h2>Submit Your Property Brief</h2>
        <p class="muted">The more detail you give us, the better we can match you against our pre-market and off-market network. This takes about 3 minutes.</p>
      </div>
      <div class="form-card" style="max-width:820px;">
        <form data-ajax="true" method="post" action="/api/leads">
          <input type="hidden" name="type" value="property-brief" />
          <fieldset>
            <legend>Your details</legend>
            <div class="form-grid">
              <div><div class="field-label">First name</div><input type="text" name="firstName" required /></div>
              <div><div class="field-label">Last name</div><input type="text" name="lastName" required /></div>
              <div><div class="field-label">Email</div><input type="email" name="email" required /></div>
              <div><div class="field-label">Phone</div><input type="tel" name="phone" required /></div>
            </div>
          </fieldset>
          <fieldset>
            <legend>What are you looking for?</legend>
            <div class="form-grid">
              <div class="full">
                <div class="field-label">Target suburbs / regions</div>
                <input type="text" name="suburbPreferences" placeholder="e.g. Camberwell, Hawthorn, Kew (VIC)" required />
              </div>
              <div>
                <div class="field-label">Budget - minimum</div>
                <input type="number" name="budgetMin" placeholder="500000" />
              </div>
              <div>
                <div class="field-label">Budget - maximum</div>
                <input type="number" name="budgetMax" placeholder="750000" required />
              </div>
              <div>
                <div class="field-label">Property type</div>
                <select name="propertyType">
                  <option>House</option>
                  <option>Townhouse</option>
                  <option>Apartment</option>
                  <option>Duplex</option>
                  <option>Acreage</option>
                  <option>Other</option>
                </select>
              </div>
              <div>
                <div class="field-label">Minimum bedrooms</div>
                <select name="bedrooms">
                  <option value="1">1</option>
                  <option value="2">2</option>
                  <option value="3" selected>3</option>
                  <option value="4">4</option>
                  <option value="5">5+</option>
                </select>
              </div>
              <div>
                <div class="field-label">Purchase timeframe</div>
                <select name="timeframe">
                  <option>0-3 months</option>
                  <option>3-6 months</option>
                  <option>6-12 months</option>
                  <option>Just researching</option>
                </select>
              </div>
              <div>
                <div class="field-label">Have you been pre-approved for finance?</div>
                <select name="financeStatus">
                  <option>Yes, pre-approved</option>
                  <option>Applying now</option>
                  <option>Not yet started</option>
                  <option>Paying cash</option>
                </select>
              </div>
            </div>
          </fieldset>
          <fieldset>
            <legend>Anything else we should know?</legend>
            <textarea name="message" placeholder="Must-haves, deal-breakers, school zones, commute requirements..."></textarea>
          </fieldset>
          <button class="btn btn-primary btn-block" type="submit" data-label="Submit Property Brief">Submit Property Brief</button>
          <div class="form-status" style="display:none;margin-top:14px;"></div>
          <p class="field-hint" style="text-align:center;margin-top:14px;">By submitting, you agree to be contacted by a BuySmart buyers agent from The Local Experts Buyers Agents Division.</p>
        </form>
      </div>
    </div>
  </section>
  `;
  return layout({
    title: 'Submit a Property Brief',
    description: 'Tell BuySmart what you are looking for and get matched with a buyers agent and exclusive pre-market and off-market listings.',
    activeNav: 'property-brief',
    body,
  });
}



// ===== views/thankyou.js =====

function render_thankyou() {
  const body = `
  <section class="section" style="text-align:center;">
    <div class="container">
      <h2>Thanks - we've got your details.</h2>
      <p class="muted" style="max-width:520px;margin:0 auto 24px;">A BuySmart buyers agent will be in touch within one business day. In the meantime, feel free to keep browsing our current listings.</p>
      <a class="btn btn-primary" href="/listings">Browse Listings</a>
    </div>
  </section>`;
  return layout({ title: 'Thank You', activeNav: '', body });
}


// ===== views/admin/login.js =====

function render_adminLogin({ error }) {
  return `<!doctype html>
<html lang="en-AU"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Admin Login | BuySmart</title><link rel="stylesheet" href="/static/styles.css" /></head>
<body class="admin-body">
<div class="login-wrap">
  <div class="login-card">
    <img src="/static/logo.svg" alt="BuySmart" style="display:block;margin:0 auto 10px;height:34px;" />
    <span class="brand-sub" style="display:block;text-align:center;color:#8a8f9c;font-size:11px;text-transform:uppercase;">Admin Backend</span>
    ${error ? `<div class="alert alert-error">${esc(error)}</div>` : ''}
    <form method="post" action="/admin/login">
      <div class="field-label">Email</div>
      <input type="email" name="email" required style="margin-bottom:14px;" />
      <div class="field-label">Password</div>
      <input type="password" name="password" required style="margin-bottom:20px;" />
      <button class="btn btn-primary btn-block" type="submit">Log In</button>
    </form>
    <p class="muted" style="margin-top:18px;text-align:center;">Powered by The Local Experts Buyers Agents Division</p>
  </div>
</div>
</body></html>`;
}


// ===== views/admin/dashboard.js =====

function render_adminDashboard({ session, stats, recentLeads }) {
  const body = `
    <div class="admin-cards">
      <div class="admin-card"><div class="num">${stats.totalProperties}</div><div class="label">Total Properties</div></div>
      <div class="admin-card"><div class="num">${stats.offMarket}</div><div class="label">Off-Market Listings</div></div>
      <div class="admin-card"><div class="num">${stats.preMarket}</div><div class="label">Pre-Market Listings</div></div>
      <div class="admin-card"><div class="num">${stats.newLeads}</div><div class="label">New Leads This Week</div></div>
    </div>
    <div class="panel">
      <div class="panel-head">
        <h2>Recent leads &amp; form submissions</h2>
        <a class="btn btn-ghost btn-sm" href="/admin/leads">View all</a>
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Name</th><th>Type</th><th>Contact</th><th>Sent to GHL</th><th>Received</th><th></th></tr></thead>
          <tbody>
          ${recentLeads
            .map(
              (l) => `<tr>
                <td>${l.firstName || ''} ${l.lastName || ''}</td>
                <td><span class="tag-pill">${l.type}</span></td>
                <td>${l.email || ''}<br/><span class="muted">${l.phone || ''}</span></td>
                <td>${l.sentToGHL ? '&#9989; Sent' : '&#9888; Not sent'}</td>
                <td>${new Date(l.createdAt).toLocaleString('en-AU')}</td>
                <td><a class="btn btn-ghost btn-sm" href="/admin/leads/${l.id}">View</a></td>
              </tr>`
            )
            .join('') || '<tr><td colspan="6" class="muted">No leads yet.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>Quick actions</h2></div>
      <div style="display:flex;gap:12px;flex-wrap:wrap;">
        <a class="btn btn-navy" href="/admin/properties/new">+ Add Property</a>
        <a class="btn btn-ghost" href="/admin/content">Edit Site Content</a>
        <a class="btn btn-ghost" href="/admin/users">Manage Users</a>
        <a class="btn btn-ghost" href="/admin/settings">Go High Level Settings</a>
      </div>
    </div>
  `;
  return adminLayout({ title: 'Dashboard', activeNav: 'dashboard', body, session });
}


// ===== views/admin/properties.js =====

function render_adminProperties({ session, properties, query }) {
  const msg = flash(query, {
    created: { type: 'success', text: 'Property created.' },
    updated: { type: 'success', text: 'Property updated.' },
    deleted: { type: 'success', text: 'Property deleted.' },
  });
  const body = `
    ${msg}
    <div class="panel">
      <div class="panel-head">
        <h2>All Properties (${properties.length})</h2>
        <a class="btn btn-primary btn-sm" href="/admin/properties/new">+ Add Property</a>
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Title</th><th>Suburb</th><th>Type</th><th>Status</th><th>Price</th><th></th></tr></thead>
          <tbody>
          ${properties
            .map(
              (p) => `<tr>
                <td>${p.title}</td>
                <td>${p.suburb}, ${p.state}</td>
                <td>${listingTypeBadge(p.listingType)}</td>
                <td>${statusBadge(p.status)}</td>
                <td>${priceLabel(p)}</td>
                <td class="row-actions">
                  <a class="btn btn-ghost btn-sm" href="/listings/${p.slug}" target="_blank">View</a>
                  <a class="btn btn-ghost btn-sm" href="/admin/properties/${p.id}/edit">Edit</a>
                  <form method="post" action="/admin/properties/${p.id}/delete" onsubmit="return confirm('Delete this property?');">
                    <button class="btn btn-danger btn-sm" type="submit">Delete</button>
                  </form>
                </td>
              </tr>`
            )
            .join('') || '<tr><td colspan="6" class="muted">No properties yet.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;
  return adminLayout({ title: 'Properties', activeNav: 'properties', body, session });
}


// ===== views/admin/propertyForm.js =====

function sel(value, current) {
  return value === current ? 'selected' : '';
}

function render_adminPropertyForm({ session, property }) {
  const p = property || {};
  const isEdit = !!p.id;
  const action = isEdit ? `/admin/properties/${p.id}` : '/admin/properties';
  const body = `
    <div class="panel">
      <form method="post" action="${action}">
        <div class="form-grid">
          <div class="full"><div class="field-label">Title</div><input type="text" name="title" value="${esc(p.title)}" required /></div>
          <div><div class="field-label">Suburb</div><input type="text" name="suburb" value="${esc(p.suburb)}" required /></div>
          <div><div class="field-label">State</div><input type="text" name="state" value="${esc(p.state)}" required /></div>
          <div><div class="field-label">Postcode</div><input type="text" name="postcode" value="${esc(p.postcode)}" required /></div>
          <div>
            <div class="field-label">Listing type</div>
            <select name="listingType">
              <option value="off-market" ${sel('off-market', p.listingType)}>Off-Market</option>
              <option value="pre-market" ${sel('pre-market', p.listingType)}>Pre-Market</option>
              <option value="on-market" ${sel('on-market', p.listingType)}>On-Market</option>
            </select>
          </div>
          <div>
            <div class="field-label">Status</div>
            <select name="status">
              <option value="available" ${sel('available', p.status)}>Available</option>
              <option value="under-offer" ${sel('under-offer', p.status)}>Under Offer</option>
              <option value="sold" ${sel('sold', p.status)}>Sold</option>
            </select>
          </div>
          <div><div class="field-label">Property type</div><input type="text" name="propertyType" value="${esc(p.propertyType)}" placeholder="House, Apartment, Townhouse..." /></div>
          <div><div class="field-label">Price label (optional override)</div><input type="text" name="priceLabel" value="${esc(p.priceLabel)}" placeholder="e.g. Offers over $800,000" /></div>
          <div><div class="field-label">Price min ($)</div><input type="number" name="priceMin" value="${esc(p.priceMin)}" /></div>
          <div><div class="field-label">Price max ($)</div><input type="number" name="priceMax" value="${esc(p.priceMax)}" /></div>
          <div><div class="field-label">Bedrooms</div><input type="number" name="bedrooms" value="${esc(p.bedrooms)}" /></div>
          <div><div class="field-label">Bathrooms</div><input type="number" name="bathrooms" value="${esc(p.bathrooms)}" /></div>
          <div><div class="field-label">Car spaces</div><input type="number" name="carSpaces" value="${esc(p.carSpaces)}" /></div>
          <div><div class="field-label">Land size (m&sup2;)</div><input type="number" name="landSize" value="${esc(p.landSize)}" /></div>
          <div class="full"><div class="field-label">Description</div><textarea name="description">${esc(p.description)}</textarea></div>
          <div class="full"><div class="field-label">Features (one per line)</div><textarea name="features">${esc((p.features || []).join('\n'))}</textarea></div>
        </div>
        <div style="margin-top:20px;display:flex;gap:12px;">
          <button class="btn btn-primary" type="submit">${isEdit ? 'Save Changes' : 'Create Property'}</button>
          <a class="btn btn-ghost" href="/admin/properties">Cancel</a>
        </div>
      </form>
    </div>
  `;
  return adminLayout({ title: isEdit ? 'Edit Property' : 'Add Property', activeNav: 'properties', body, session });
}


// ===== views/admin/leads.js =====

function render_adminLeads({ session, leads, filterType }) {
  const types = ['', 'property-brief', 'contact', 'property-enquiry'];
  const body = `
    <div class="panel">
      <div class="panel-head">
        <h2>Leads &amp; Form Submissions (${leads.length})</h2>
        <form method="get" action="/admin/leads">
          <select name="type" onchange="this.form.submit()">
            ${types
              .map((t) => `<option value="${t}" ${t === filterType ? 'selected' : ''}>${t ? t : 'All types'}</option>`)
              .join('')}
          </select>
        </form>
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Name</th><th>Type</th><th>Contact</th><th>Status</th><th>GHL</th><th>Received</th><th></th></tr></thead>
          <tbody>
          ${leads
            .map(
              (l) => `<tr>
                <td>${esc(l.firstName)} ${esc(l.lastName)}</td>
                <td><span class="tag-pill">${esc(l.type)}</span></td>
                <td>${esc(l.email)}<br/><span class="muted">${esc(l.phone)}</span></td>
                <td>${esc(l.status)}</td>
                <td>${l.sentToGHL ? '&#9989;' : '&#9888;'}</td>
                <td>${new Date(l.createdAt).toLocaleString('en-AU')}</td>
                <td><a class="btn btn-ghost btn-sm" href="/admin/leads/${l.id}">View</a></td>
              </tr>`
            )
            .join('') || '<tr><td colspan="7" class="muted">No leads yet.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;
  return adminLayout({ title: 'Leads & Enquiries', activeNav: 'leads', body, session });
}


// ===== views/admin/leadDetail.js =====

function render_adminLeadDetail({ session, lead, query }) {
  const msg = flash(query, {
    resent: { type: 'success', text: 'Lead resent to Go High Level.' },
    resend_failed: { type: 'error', text: 'Could not send to Go High Level - check GHL_WEBHOOK_URL in Settings.' },
  });
  const fields = [
    ['Type', lead.type],
    ['Name', `${lead.firstName || ''} ${lead.lastName || ''}`],
    ['Email', lead.email],
    ['Phone', lead.phone],
    ['Suburb preferences', lead.suburbPreferences],
    ['Budget', lead.budgetMin || lead.budgetMax ? `$${lead.budgetMin || '?'} - $${lead.budgetMax || '?'}` : ''],
    ['Property type', lead.propertyType],
    ['Bedrooms', lead.bedrooms],
    ['Timeframe', lead.timeframe],
    ['Finance status', lead.financeStatus],
    ['Related property', lead.relatedPropertyTitle],
    ['Message', lead.message],
    ['Received', new Date(lead.createdAt).toLocaleString('en-AU')],
    ['Sent to GHL', lead.sentToGHL ? 'Yes' : 'No'],
  ].filter(([, v]) => v !== undefined && v !== null && v !== '');

  const body = `
    ${msg}
    <div class="panel">
      <div class="panel-head"><h2>Submission Detail</h2>
        <form method="post" action="/admin/leads/${lead.id}/resend"><button class="btn btn-navy btn-sm" type="submit">Resend to GHL</button></form>
      </div>
      <dl class="kv">
        ${fields.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}
      </dl>
      ${lead.ghlNote ? `<p class="muted">GHL note: ${esc(lead.ghlNote)}</p>` : ''}
      <a class="btn btn-ghost" href="/admin/leads">&larr; Back to all leads</a>
    </div>
  `;
  return adminLayout({ title: 'Lead Detail', activeNav: 'leads', body, session });
}


// ===== views/admin/content.js =====

function render_adminContent({ session, content, query }) {
  const msg = flash(query, { saved: { type: 'success', text: 'Site content updated.' } });
  const testimonials = content.testimonials || [];
  const body = `
    ${msg}
    <div class="panel">
      <div class="panel-head"><h2>Homepage &amp; About Content</h2></div>
      <form method="post" action="/admin/content">
        <div class="form-grid">
          <div class="full"><div class="field-label">Hero eyebrow</div><input type="text" name="heroEyebrow" value="${esc(content.heroEyebrow)}" /></div>
          <div class="full"><div class="field-label">Hero heading</div><input type="text" name="heroHeading" value="${esc(content.heroHeading)}" /></div>
          <div class="full"><div class="field-label">Hero subheading</div><textarea name="heroSubheading">${esc(content.heroSubheading)}</textarea></div>
          <div class="full"><div class="field-label">About intro paragraph</div><textarea name="aboutIntro">${esc(content.aboutIntro)}</textarea></div>
          <div><div class="field-label">Contact phone</div><input type="text" name="contactPhone" value="${esc(content.contactPhone)}" /></div>
          <div><div class="field-label">Contact email</div><input type="text" name="contactEmail" value="${esc(content.contactEmail)}" /></div>
        </div>
        <fieldset style="margin-top:24px;">
          <legend>Testimonials (one per block: Name | Quote)</legend>
          <textarea name="testimonialsRaw" style="min-height:140px;">${esc(
            testimonials.map((t) => `${t.name} | ${t.quote}`).join('\n')
          )}</textarea>
          <p class="field-hint">One testimonial per line, formatted as: Client Name | Their quote</p>
        </fieldset>
        <button class="btn btn-primary" type="submit">Save Content</button>
      </form>
    </div>
  `;
  return adminLayout({ title: 'Site Content', activeNav: 'content', body, session });
}


// ===== views/admin/users.js =====

function render_adminUsers({ session, users, query }) {
  const msg = flash(query, {
    created: { type: 'success', text: 'User created.' },
    deleted: { type: 'success', text: 'User removed.' },
    error_last_admin: { type: 'error', text: 'Cannot remove the last admin account.' },
    error_email: { type: 'error', text: 'That email is already registered.' },
  });
  const body = `
    ${msg}
    <div class="panel">
      <div class="panel-head"><h2>Users &amp; Permissions</h2></div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Added</th><th></th></tr></thead>
          <tbody>
          ${users
            .map(
              (u) => `<tr>
                <td>${esc(u.name)}</td>
                <td>${esc(u.email)}</td>
                <td><span class="tag-pill">${esc(u.role)}</span></td>
                <td>${new Date(u.createdAt).toLocaleDateString('en-AU')}</td>
                <td>
                  <form method="post" action="/admin/users/${u.id}/delete" onsubmit="return confirm('Remove this user?');">
                    <button class="btn btn-danger btn-sm" type="submit">Remove</button>
                  </form>
                </td>
              </tr>`
            )
            .join('')}
          </tbody>
        </table>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>Add a user</h2></div>
      <form method="post" action="/admin/users">
        <div class="form-grid">
          <div><div class="field-label">Full name</div><input type="text" name="name" required /></div>
          <div><div class="field-label">Email</div><input type="email" name="email" required /></div>
          <div><div class="field-label">Temporary password</div><input type="text" name="password" required /></div>
          <div>
            <div class="field-label">Role</div>
            <select name="role">
              <option value="staff">Staff (properties, leads, content)</option>
              <option value="admin">Admin (full access incl. users)</option>
            </select>
          </div>
        </div>
        <button class="btn btn-primary" style="margin-top:16px;" type="submit">Add User</button>
      </form>
    </div>
  `;
  return adminLayout({ title: 'Users & Permissions', activeNav: 'users', body, session });
}


// ===== views/admin/settings.js =====

function render_adminSettings({ session, ghlConfigured, webhookUrlMasked }) {
  const body = `
    <div class="panel">
      <div class="panel-head"><h2>Go High Level Integration</h2></div>
      <p class="muted">Forms on the live site (Property Brief, Contact, Property Enquiry) POST to <code class="env-var">/api/leads</code>, which saves the lead here in Admin and forwards it to Go High Level via an inbound webhook.</p>
      <dl class="kv">
        <dt>Status</dt>
        <dd>${ghlConfigured ? '<span class="badge badge-available">Connected</span>' : '<span class="badge badge-underoffer">Not configured</span>'}</dd>
        <dt>GHL_WEBHOOK_URL</dt>
        <dd>${ghlConfigured ? esc(webhookUrlMasked) : 'Not set - add it to your .env file'}</dd>
      </dl>
      <h3 style="font-size:15px;">How to connect</h3>
      <ol style="padding-left:20px;">
        <li>In Go High Level: <strong>Automation &rarr; Workflows &rarr; Create Workflow &rarr; Trigger = Inbound Webhook</strong>.</li>
        <li>Copy the generated webhook URL.</li>
        <li>Set <code class="env-var">GHL_WEBHOOK_URL</code> in your <code class="env-var">.env</code> file to that URL and restart the server.</li>
        <li>Every new lead will now be POSTed automatically. You can resend any individual lead from the Leads screen.</li>
      </ol>
      <p class="muted">Prefer the GHL REST API / Private Integration instead of a webhook (e.g. to attach leads to a specific pipeline or use custom field IDs)? See the commented alternative implementation in <code class="env-var">lib/ghl.js</code>.</p>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>Deployment &amp; data notes</h2></div>
      <p class="muted">This build stores data in JSON files under <code class="env-var">/data</code> so it runs anywhere with just Node.js - no database or npm install required. Before going live on a serverless host (Vercel, Netlify, etc.), migrate to a real database (Postgres via Supabase/Neon is a good fit) since serverless filesystems are read-only/ephemeral. See README.md for full deployment guidance.</p>
    </div>
  `;
  return adminLayout({ title: 'Integrations & Settings', activeNav: 'settings', body, session });
}


// ===== embedded static assets =====
const LOGO_SVG = '<svg viewBox="0 0 480 150" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="BuySmart">\n  <text x="2" y="98" font-family="Arial, Helvetica, sans-serif" font-weight="800" font-size="82" fill="#12291d">Buy<tspan font-style="italic" letter-spacing="-1">Smart</tspan></text>\n  <path d="M118 122 C 200 136, 330 128, 430 96 L 430 101 C 332 133, 202 141, 120 128 Z" fill="#12291d"/>\n</svg>\n';
const LOGO_WHITE_SVG = '<svg viewBox="0 0 480 150" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="BuySmart">\n  <text x="2" y="98" font-family="Arial, Helvetica, sans-serif" font-weight="800" font-size="82" fill="#ffffff">Buy<tspan font-style="italic" letter-spacing="-1">Smart</tspan></text>\n  <path d="M118 122 C 200 136, 330 128, 430 96 L 430 101 C 332 133, 202 141, 120 128 Z" fill="#ffffff"/>\n</svg>\n';

const STYLES_CSS = '/* ===== BuySmart Design System ===== */\n:root {\n  --navy: #1c1c1c;\n  --navy-dark: #101010;\n  --navy-light: #333333;\n  --gold: #1c1c1c;\n  --gold-light: #6b6b6b;\n  --cream: #fafafa;\n  --ink: #1c1c1c;\n  --ink-soft: #6b6b6b;\n  --border: #e4e4e4;\n  --green: #2f7a4f;\n  --red: #b3413a;\n  --amber: #8a6d1f;\n  --radius: 10px;\n  --shadow: 0 4px 18px rgba(0, 0, 0, 0.06);\n  --font: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;\n}\n\n* { box-sizing: border-box; }\nhtml, body { margin: 0; padding: 0; }\nbody {\n  font-family: var(--font);\n  color: var(--ink);\n  background: #fff;\n  line-height: 1.55;\n}\na { color: inherit; text-decoration: none; }\nimg { max-width: 100%; display: block; }\nh1, h2, h3, h4 { font-family: var(--font); color: var(--navy); line-height: 1.2; margin: 0 0 .5em; }\np { margin: 0 0 1em; }\n.container { max-width: 1180px; margin: 0 auto; padding: 0 24px; }\n\n/* Buttons */\n.btn { display: inline-block; padding: 12px 22px; border-radius: 999px; font-weight: 600; font-size: 15px; border: 2px solid transparent; cursor: pointer; transition: all .15s ease; }\n.btn-primary { background: var(--gold); color: var(--navy-dark); }\n.btn-primary:hover { background: var(--gold-light); }\n.btn-outline { background: transparent; border-color: var(--ink); color: var(--ink); }\n.btn-outline:hover { background: rgba(0,0,0,.05); }\n.btn-navy { background: var(--navy); color: #fff; }\n.btn-navy:hover { background: var(--navy-light); }\n.btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--ink); }\n.btn-ghost:hover { background: #f2f0ea; }\n.btn-danger { background: var(--red); color: #fff; }\n.btn-sm { padding: 8px 16px; font-size: 13px; }\n.btn-block { width: 100%; text-align: center; }\nbutton.link-btn { background: none; border: none; padding: 0; color: var(--navy); text-decoration: underline; cursor: pointer; font-size: inherit; }\n\n/* Header */\n.site-header { border-bottom: 1px solid var(--border); position: sticky; top: 0; background: #fff; z-index: 50; }\n.header-inner { display: flex; align-items: center; justify-content: space-between; padding: 14px 24px; }\n.brand { display: flex; flex-direction: column; line-height: 1.1; }\n.brand-logo { height: 30px; width: auto; display: block; }\n.brand-mark { font-weight: 800; font-size: 22px; color: var(--navy); letter-spacing: -0.02em; }\n.brand-mark::after { content: \'\'; }\n.brand-sub { font-size: 10px; letter-spacing: .04em; color: var(--ink-soft); text-transform: uppercase; }\n.main-nav { display: flex; align-items: center; gap: 26px; font-weight: 600; font-size: 15px; }\n.main-nav a { color: var(--ink); padding: 6px 0; border-bottom: 2px solid transparent; }\n.main-nav a.active, .main-nav a:hover { color: var(--navy); border-bottom-color: var(--gold); }\n.main-nav a.btn { border-bottom: none; }\n.nav-toggle { display: none; background: none; border: none; font-size: 22px; cursor: pointer; }\n\n@media (max-width: 860px) {\n  .main-nav { display: none; position: absolute; top: 66px; left: 0; right: 0; background: #fff; flex-direction: column; align-items: flex-start; padding: 16px 24px; border-bottom: 1px solid var(--border); gap: 14px; }\n  .main-nav.open { display: flex; }\n  .nav-toggle { display: block; }\n}\n\n/* Hero */\n.hero { background: #ffffff; color: var(--ink); padding: 72px 0 90px; border-bottom: 1px solid var(--border); }\n.hero-inner { display: grid; grid-template-columns: 1.1fr .9fr; gap: 40px; align-items: center; }\n.hero .eyebrow { color: var(--gold-light); font-weight: 700; text-transform: uppercase; letter-spacing: .08em; font-size: 13px; margin-bottom: 14px; }\n.hero h1 { color: var(--ink); font-size: 42px; margin-bottom: 18px; }\n.hero p.lead { color: var(--ink-soft); font-size: 18px; max-width: 520px; }\n.hero-actions { display: flex; gap: 14px; margin-top: 28px; flex-wrap: wrap; }\n.hero-stats { display: flex; gap: 28px; margin-top: 38px; flex-wrap: wrap; }\n.hero-stats div { min-width: 110px; }\n.hero-stats .num { font-size: 28px; font-weight: 800; color: var(--gold-light); }\n.hero-stats .label { font-size: 13px; color: var(--ink-soft); }\n.hero-card { background: #fff; color: var(--ink); border-radius: var(--radius); padding: 26px; box-shadow: var(--shadow); border: 1px solid var(--border); }\n.hero-card h3 { font-size: 18px; }\n.hero-card ul { padding-left: 18px; margin: 0 0 18px; }\n.hero-card li { margin-bottom: 8px; }\n\n@media (max-width: 860px) { .hero-inner { grid-template-columns: 1fr; } .hero h1 { font-size: 32px; } }\n\nsection.section { padding: 64px 0; }\nsection.section.alt { background: var(--cream); }\n.section-head { text-align: center; max-width: 640px; margin: 0 auto 40px; }\n.section-head .eyebrow { color: var(--gold); font-weight: 700; text-transform: uppercase; letter-spacing: .08em; font-size: 13px; }\n\n/* Steps / How it works */\n.steps { display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px; }\n.step { background: #fff; border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; }\n.step .num { display: inline-flex; align-items: center; justify-content: center; width: 34px; height: 34px; border-radius: 50%; background: var(--navy); color: #fff; font-weight: 700; margin-bottom: 14px; }\n@media (max-width: 900px) { .steps { grid-template-columns: 1fr 1fr; } }\n@media (max-width: 560px) { .steps { grid-template-columns: 1fr; } }\n\n/* Listings grid */\n.listing-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 26px; }\n@media (max-width: 980px) { .listing-grid { grid-template-columns: 1fr 1fr; } }\n@media (max-width: 640px) { .listing-grid { grid-template-columns: 1fr; } }\n\n.card-property { border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; background: #fff; transition: box-shadow .15s ease, transform .15s ease; }\n.card-property:hover { box-shadow: var(--shadow); transform: translateY(-2px); }\n.card-property .thumb { height: 190px; background: linear-gradient(135deg,#9a9a9a,#5c5c5c); position: relative; display: flex; align-items: flex-end; }\n.card-property .thumb .badges { position: absolute; top: 12px; left: 12px; display: flex; gap: 6px; }\n.card-property .thumb .price-chip { color: #fff; font-weight: 700; padding: 10px 14px; font-size: 15px; text-shadow: 0 1px 4px rgba(0,0,0,.4); }\n.card-property .body { padding: 16px 18px 20px; }\n.card-property h3 { font-size: 17px; margin-bottom: 4px; }\n.card-property .suburb { color: var(--ink-soft); font-size: 14px; margin-bottom: 12px; }\n.card-property .meta { display: flex; gap: 14px; color: var(--ink-soft); font-size: 13px; margin-bottom: 14px; }\n\n.badge { display: inline-block; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; padding: 4px 9px; border-radius: 999px; }\n.badge-offmarket { background: #e4e4e4; color: #3a3a3a; }\n.badge-premarket { background: #efefef; color: #5a5a5a; }\n.badge-onmarket { background: #f5f5f5; color: #7a7a7a; }\n.badge-available { background: #e3f3e9; color: var(--green); }\n.badge-underoffer { background: #fdf1d8; color: var(--amber); }\n.badge-sold { background: #f4e3e1; color: var(--red); }\n\n/* Filters */\n.filters { display: flex; gap: 14px; flex-wrap: wrap; align-items: flex-end; margin-bottom: 32px; background: var(--cream); padding: 18px; border-radius: var(--radius); }\n.filters .field { display: flex; flex-direction: column; gap: 6px; font-size: 13px; font-weight: 600; color: var(--ink-soft); }\n.filters select, .filters input { padding: 9px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; min-width: 150px; }\n\n/* Forms (generic) */\n.form-card { background: #fff; border: 1px solid var(--border); border-radius: var(--radius); padding: 32px; max-width: 720px; margin: 0 auto; box-shadow: var(--shadow); }\n.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }\n.form-grid .full { grid-column: 1 / -1; }\n@media (max-width: 640px) { .form-grid { grid-template-columns: 1fr; } }\n.field-label { display: block; font-weight: 600; font-size: 14px; margin-bottom: 6px; color: var(--navy); }\n.field-hint { font-size: 12px; color: var(--ink-soft); margin-top: 4px; }\ninput[type=text], input[type=email], input[type=tel], input[type=number], input[type=password], select, textarea {\n  width: 100%; padding: 11px 13px; border: 1px solid var(--border); border-radius: 8px; font-size: 15px; font-family: var(--font); background: #fff;\n}\ntextarea { min-height: 110px; resize: vertical; }\ninput:focus, select:focus, textarea:focus { outline: none; border-color: var(--navy); box-shadow: 0 0 0 3px rgba(11,37,69,.12); }\n.checkbox-row { display: flex; align-items: center; gap: 8px; font-size: 14px; }\nfieldset { border: none; padding: 0; margin: 0 0 18px; }\nlegend { font-weight: 700; color: var(--navy); margin-bottom: 10px; font-size: 15px; }\n.chip-select { display: flex; gap: 8px; flex-wrap: wrap; }\n.chip-select label { border: 1px solid var(--border); border-radius: 999px; padding: 8px 14px; font-size: 13px; cursor: pointer; }\n.chip-select input { width: auto; margin-right: 6px; }\n\n.alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 18px; font-size: 14px; font-weight: 600; }\n.alert-success { background: #e3f3e9; color: var(--green); }\n.alert-error { background: #f4e3e1; color: var(--red); }\n.alert-info { background: #d9e6f5; color: var(--navy); }\n\n/* Property detail */\n.detail-hero { background: #ffffff; color: var(--ink); padding: 40px 0; border-bottom: 1px solid var(--border); }\n.detail-gallery { display: grid; grid-template-columns: 2fr 1fr; gap: 10px; margin: 28px 0; }\n.detail-gallery .g-main { height: 380px; border-radius: var(--radius); background: linear-gradient(135deg,#9a9a9a,#5c5c5c); }\n.detail-gallery .g-side { display: grid; grid-template-rows: 1fr 1fr; gap: 10px; }\n.detail-gallery .g-side div { border-radius: var(--radius); background: linear-gradient(135deg,#b5b5b5,#7a7a7a); }\n.detail-layout { display: grid; grid-template-columns: 2fr 1fr; gap: 40px; }\n@media (max-width: 900px) { .detail-layout { grid-template-columns: 1fr; } .detail-gallery { grid-template-columns: 1fr; } }\n.detail-facts { display: flex; gap: 26px; margin: 18px 0; flex-wrap: wrap; }\n.detail-facts div { text-align: center; }\n.detail-facts .num { font-size: 22px; font-weight: 800; color: var(--navy); }\n.detail-facts .label { font-size: 12px; color: var(--ink-soft); text-transform: uppercase; }\n.feature-list { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; padding: 0; list-style: none; }\n.feature-list li::before { content: \'✓ \'; color: var(--green); font-weight: 700; }\n.sticky-enquiry { border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; box-shadow: var(--shadow); position: sticky; top: 90px; }\n\n/* Testimonials */\n.testimonial { background: #fff; border: 1px solid var(--border); border-radius: var(--radius); padding: 22px; }\n.testimonial p { font-style: italic; color: var(--ink-soft); }\n.testimonial .who { font-weight: 700; color: var(--navy); font-style: normal; }\n.grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; }\n@media (max-width: 860px) { .grid-3 { grid-template-columns: 1fr; } }\n\n/* Footer */\n.site-footer { background: var(--navy-dark); color: #b0b0b0; padding: 48px 0 26px; margin-top: 40px; }\n.footer-inner { display: grid; grid-template-columns: 1.4fr 1fr 1fr; gap: 30px; }\n.footer-logo { height: 26px; width: auto; display: block; }\n.footer-sub { font-size: 12px; text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }\n.footer-copy { font-size: 12px; color: #8a8a8a; margin-top: 20px; }\n.footer-col h4 { color: #fff; font-size: 14px; margin-bottom: 12px; }\n.footer-col a { display: block; color: #b0b0b0; font-size: 14px; margin-bottom: 8px; }\n.footer-col a:hover { color: #ffffff; }\n@media (max-width: 700px) { .footer-inner { grid-template-columns: 1fr; } }\n\n/* Tables */\ntable.data-table { width: 100%; border-collapse: collapse; background: #fff; }\ntable.data-table th, table.data-table td { text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--border); font-size: 14px; }\ntable.data-table th { color: var(--ink-soft); text-transform: uppercase; font-size: 11px; letter-spacing: .04em; }\ntable.data-table tr:hover td { background: #fafaf7; }\n.table-wrap { background: #fff; border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }\n\n/* ===== Admin ===== */\n.admin-body { background: var(--cream); font-family: var(--font); }\n.admin-shell { display: flex; min-height: 100vh; }\n.admin-sidebar { width: 240px; background: var(--navy-dark); color: #fff; display: flex; flex-direction: column; padding: 22px 0; flex-shrink: 0; }\n.admin-brand { padding: 0 22px 22px; border-bottom: 1px solid rgba(255,255,255,.1); margin-bottom: 14px; }\n.admin-logo { height: 24px; width: auto; display: block; margin-bottom: 4px; }\n.admin-brand span { display: block; font-size: 11px; font-weight: 600; color: #9a9a9a; text-transform: uppercase; letter-spacing: .06em; }\n.admin-nav { display: flex; flex-direction: column; flex: 1; }\n.admin-nav a { padding: 12px 22px; color: #c6cde0; font-size: 14px; font-weight: 600; border-left: 3px solid transparent; }\n.admin-nav a:hover { background: rgba(255,255,255,.05); color: #fff; }\n.admin-nav a.active { color: #fff; border-left-color: #ffffff; background: rgba(255,255,255,.08); }\n.admin-sidebar-footer { padding: 18px 22px; border-top: 1px solid rgba(255,255,255,.1); }\n.admin-user { font-size: 13px; color: #c6cde0; margin-bottom: 10px; }\n.back-to-site { display: block; margin-top: 12px; font-size: 12px; color: #9a9a9a; }\n.admin-main { flex: 1; min-width: 0; }\n.admin-topbar { background: #fff; border-bottom: 1px solid var(--border); padding: 20px 32px; }\n.admin-topbar h1 { margin: 0; font-size: 20px; }\n.admin-content { padding: 28px 32px; }\n.admin-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 18px; margin-bottom: 28px; }\n@media (max-width: 1100px) { .admin-cards { grid-template-columns: repeat(2, 1fr); } }\n.admin-card { background: #fff; border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; }\n.admin-card .num { font-size: 26px; font-weight: 800; color: var(--navy); }\n.admin-card .label { font-size: 13px; color: var(--ink-soft); margin-top: 4px; }\n.panel { background: #fff; border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; margin-bottom: 24px; }\n.panel-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }\n.panel-head h2 { font-size: 17px; margin: 0; }\n.row-actions { display: flex; gap: 8px; }\n.login-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #f0f0f0; }\n.login-card { background: #fff; padding: 40px; border-radius: var(--radius); width: 380px; box-shadow: var(--shadow); }\n.login-card .brand-mark { display: block; text-align: center; margin-bottom: 6px; font-size: 24px; }\n.login-card .brand-sub { display: block; text-align: center; margin-bottom: 24px; }\n.tag-pill { display: inline-block; background: var(--cream); border: 1px solid var(--border); border-radius: 999px; padding: 3px 10px; font-size: 12px; margin-right: 4px; }\n.muted { color: var(--ink-soft); font-size: 13px; }\n.kv { display: grid; grid-template-columns: 160px 1fr; gap: 8px 14px; font-size: 14px; margin-bottom: 20px; }\n.kv dt { color: var(--ink-soft); }\n.kv dd { margin: 0; }\ncode.env-var { background: #f2f0ea; padding: 2px 6px; border-radius: 4px; font-size: 13px; }\n';

const APP_JS = 'document.addEventListener(\'DOMContentLoaded\', function () {\n  var toggle = document.getElementById(\'navToggle\');\n  var nav = document.querySelector(\'.main-nav\');\n  if (toggle && nav) {\n    toggle.addEventListener(\'click\', function () {\n      nav.classList.toggle(\'open\');\n    });\n  }\n\n  // Progressive enhancement: submit lead forms via fetch so we can show an\n  // inline success/error message without a full page reload, but the plain\n  // <form method="post"> still works if JS is disabled.\n  document.querySelectorAll(\'form[data-ajax="true"]\').forEach(function (form) {\n    form.addEventListener(\'submit\', function (e) {\n      e.preventDefault();\n      var statusEl = form.querySelector(\'.form-status\');\n      var submitBtn = form.querySelector(\'button[type="submit"]\');\n      var formData = new FormData(form);\n      var payload = {};\n      formData.forEach(function (value, key) {\n        if (payload[key] !== undefined) {\n          payload[key] = Array.isArray(payload[key]) ? payload[key].concat(value) : [payload[key], value];\n        } else {\n          payload[key] = value;\n        }\n      });\n      if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = \'Submitting...\'; }\n      fetch(form.action, {\n        method: \'POST\',\n        headers: { \'Content-Type\': \'application/json\' },\n        body: JSON.stringify(payload),\n      })\n        .then(function (res) { return res.json().then(function (data) { return { ok: res.ok, data: data }; }); })\n        .then(function (result) {\n          if (statusEl) {\n            statusEl.textContent = result.ok\n              ? (result.data.message || \'Thanks - we have received your details and will be in touch shortly.\')\n              : (result.data.error || \'Something went wrong. Please try again.\');\n            statusEl.className = \'alert \' + (result.ok ? \'alert-success\' : \'alert-error\');\n            statusEl.style.display = \'block\';\n          }\n          if (result.ok) {\n            form.reset();\n          }\n        })\n        .catch(function () {\n          if (statusEl) {\n            statusEl.textContent = \'Network error - please try again.\';\n            statusEl.className = \'alert alert-error\';\n            statusEl.style.display = \'block\';\n          }\n        })\n        .finally(function () {\n          if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = submitBtn.getAttribute(\'data-label\') || \'Submit\'; }\n        });\n    });\n  });\n});\n';


// ===== lib/routes.js =====





















function send(res, status, body, headers = {}) {
  res.writeHead(status, Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, headers));
  res.end(body);
}
function sendJSON(res, status, obj, headers = {}) {
  res.writeHead(status, Object.assign({ 'Content-Type': 'application/json' }, headers));
  res.end(JSON.stringify(obj));
}
function redirect(res, location, headers = {}) {
  res.writeHead(302, Object.assign({ Location: location }, headers));
  res.end();
}
function notFound(res) {
  send(res, 404, '<h1>404 - Not Found</h1><a href="/">Back home</a>');
}

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      const contentType = req.headers['content-type'] || '';
      if (contentType.includes('application/json')) {
        try {
          resolve(JSON.parse(body || '{}'));
        } catch (e) {
          resolve({});
        }
      } else {
        resolve(querystring.parse(body));
      }
    });
    req.on('error', () => resolve({}));
  });
}

function requireAdmin(req, res) {
  const session = getSessionFromRequest(req);
  if (!session) {
    redirect(res, '/admin/login');
    return null;
  }
  const user = Users.get(session.uid);
  if (!user) {
    redirect(res, '/admin/login');
    return null;
  }
  return user;
}

async function handle(req, res) {
  const parsed = url.parse(req.url, true);
  const pathname = decodeURIComponent(parsed.pathname);
  const query = parsed.query;
  const method = req.method;

  // ---------- Static assets ----------
  if (pathname.startsWith('/static/')) {
    return serveStatic(req, res, pathname);
  }

  // ---------- Public site ----------
  if (pathname === '/' && method === 'GET') {
    const all = Properties.all().filter((p) => p.status !== 'sold');
    const featured = all.slice(0, 6);
    return send(res, 200, render_home({ featured, content: Content.all() }));
  }

  if (pathname === '/listings' && method === 'GET') {
    let all = Properties.all();
    if (query.listingType) all = all.filter((p) => p.listingType === query.listingType);
    if (query.state) all = all.filter((p) => p.state === query.state);
    if (query.bedrooms) all = all.filter((p) => Number(p.bedrooms) >= Number(query.bedrooms));
    if (query.maxPrice) all = all.filter((p) => !p.priceMax || Number(p.priceMax) <= Number(query.maxPrice));
    const states = Array.from(new Set(Properties.all().map((p) => p.state))).sort();
    return send(
      res,
      200,
      render_listings({
        properties: all,
        filters: { listingType: query.listingType || '', state: query.state || '', bedrooms: query.bedrooms || '', maxPrice: query.maxPrice || '' },
        states,
      })
    );
  }

  if (pathname.startsWith('/listings/') && method === 'GET') {
    const slug = pathname.replace('/listings/', '');
    const property = Properties.getBySlug(slug);
    if (!property) return notFound(res);
    return send(res, 200, render_propertyDetail({ property }));
  }

  if (pathname === '/about' && method === 'GET') {
    return send(res, 200, render_about({ content: Content.all() }));
  }

  if (pathname === '/contact' && method === 'GET') {
    return send(res, 200, render_contact({ content: Content.all() }));
  }

  if (pathname === '/property-brief' && method === 'GET') {
    return send(res, 200, render_propertyBrief());
  }

  if (pathname === '/thank-you' && method === 'GET') {
    return send(res, 200, render_thankyou());
  }

  // ---------- Lead capture API (used by all public forms, GHL-linked) ----------
  if (pathname === '/api/leads' && method === 'POST') {
    const data = await parseBody(req);
    if (!data.email || !data.firstName) {
      return sendJSON(res, 400, { error: 'First name and email are required.' });
    }
    const lead = Leads.create({
      type: data.type || 'contact',
      firstName: data.firstName,
      lastName: data.lastName,
      email: data.email,
      phone: data.phone,
      suburbPreferences: data.suburbPreferences,
      budgetMin: data.budgetMin,
      budgetMax: data.budgetMax,
      propertyType: data.propertyType,
      bedrooms: data.bedrooms,
      timeframe: data.timeframe,
      financeStatus: data.financeStatus,
      relatedPropertyId: data.relatedPropertyId,
      relatedPropertyTitle: data.relatedPropertyTitle,
      message: data.message,
    });
    const ghlResult = await forwardToGHL(lead);
    Leads.update(lead.id, { sentToGHL: ghlResult.ok, ghlNote: ghlResult.note || (ghlResult.ok ? 'Sent successfully.' : 'GHL forward failed.') });

    const wantsJSON = (req.headers.accept || '').includes('application/json') || (req.headers['content-type'] || '').includes('json');
    if (wantsJSON) {
      return sendJSON(res, 200, { ok: true, message: "Thanks - we've received your details and will be in touch shortly." });
    }
    return redirect(res, '/thank-you');
  }

  // ---------- Admin: auth ----------
  if (pathname === '/admin/login' && method === 'GET') {
    return send(res, 200, render_adminLogin({ error: query.error }));
  }
  if (pathname === '/admin/login' && method === 'POST') {
    const data = await parseBody(req);
    const user = Users.getByEmail(data.email || '');
    if (!user || !verifyPassword(data.password || '', user.passwordHash)) {
      return send(res, 200, render_adminLogin({ error: 'Invalid email or password.' }));
    }
    return redirect(res, '/admin', { 'Set-Cookie': createSessionCookie(user) });
  }
  if (pathname === '/admin/logout' && method === 'POST') {
    return redirect(res, '/admin/login', { 'Set-Cookie': clearSessionCookie() });
  }

  // ---------- Admin: everything below requires auth ----------
  if (pathname.startsWith('/admin')) {
    const user = requireAdmin(req, res);
    if (!user) return; // already redirected

    if (pathname === '/admin' && method === 'GET') {
      const all = Properties.all();
      const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
      const stats = {
        totalProperties: all.length,
        offMarket: all.filter((p) => p.listingType === 'off-market').length,
        preMarket: all.filter((p) => p.listingType === 'pre-market').length,
        newLeads: Leads.all().filter((l) => new Date(l.createdAt).getTime() > weekAgo).length,
      };
      return send(res, 200, render_adminDashboard({ session: user, stats, recentLeads: Leads.all().slice(0, 8) }));
    }

    if (pathname === '/admin/properties' && method === 'GET') {
      return send(res, 200, render_adminProperties({ session: user, properties: Properties.all(), query }));
    }
    if (pathname === '/admin/properties/new' && method === 'GET') {
      return send(res, 200, render_adminPropertyForm({ session: user, property: null }));
    }
    if (pathname === '/admin/properties' && method === 'POST') {
      const data = await parseBody(req);
      Properties.create(normalizePropertyInput(data));
      return redirect(res, '/admin/properties?created=1');
    }
    const editMatch = pathname.match(/^\/admin\/properties\/([a-f0-9]+)\/edit$/);
    if (editMatch && method === 'GET') {
      const property = Properties.get(editMatch[1]);
      if (!property) return notFound(res);
      return send(res, 200, render_adminPropertyForm({ session: user, property }));
    }
    const updateMatch = pathname.match(/^\/admin\/properties\/([a-f0-9]+)$/);
    if (updateMatch && method === 'POST') {
      const data = await parseBody(req);
      Properties.update(updateMatch[1], normalizePropertyInput(data));
      return redirect(res, '/admin/properties?updated=1');
    }
    const deleteMatch = pathname.match(/^\/admin\/properties\/([a-f0-9]+)\/delete$/);
    if (deleteMatch && method === 'POST') {
      Properties.remove(deleteMatch[1]);
      return redirect(res, '/admin/properties?deleted=1');
    }

    if (pathname === '/admin/leads' && method === 'GET') {
      let all = Leads.all();
      if (query.type) all = all.filter((l) => l.type === query.type);
      return send(res, 200, render_adminLeads({ session: user, leads: all, filterType: query.type || '' }));
    }
    const leadMatch = pathname.match(/^\/admin\/leads\/([a-f0-9]+)$/);
    if (leadMatch && method === 'GET') {
      const lead = Leads.get(leadMatch[1]);
      if (!lead) return notFound(res);
      return send(res, 200, render_adminLeadDetail({ session: user, lead, query }));
    }
    const resendMatch = pathname.match(/^\/admin\/leads\/([a-f0-9]+)\/resend$/);
    if (resendMatch && method === 'POST') {
      const lead = Leads.get(resendMatch[1]);
      if (!lead) return notFound(res);
      const result = await forwardToGHL(lead);
      Leads.update(lead.id, { sentToGHL: result.ok, ghlNote: result.note || (result.ok ? 'Resent successfully.' : 'GHL forward failed.') });
      return redirect(res, `/admin/leads/${lead.id}?${result.ok ? 'resent=1' : 'resend_failed=1'}`);
    }

    if (pathname === '/admin/content' && method === 'GET') {
      return send(res, 200, render_adminContent({ session: user, content: Content.all(), query }));
    }
    if (pathname === '/admin/content' && method === 'POST') {
      const data = await parseBody(req);
      const testimonials = String(data.testimonialsRaw || '')
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          const [name, ...rest] = line.split('|');
          return { name: (name || '').trim(), quote: rest.join('|').trim() };
        });
      Content.setMany({
        heroEyebrow: data.heroEyebrow,
        heroHeading: data.heroHeading,
        heroSubheading: data.heroSubheading,
        aboutIntro: data.aboutIntro,
        contactPhone: data.contactPhone,
        contactEmail: data.contactEmail,
        testimonials,
      });
      return redirect(res, '/admin/content?saved=1');
    }

    if (pathname === '/admin/users' && method === 'GET') {
      return send(res, 200, render_adminUsers({ session: user, users: Users.all(), query }));
    }
    if (pathname === '/admin/users' && method === 'POST') {
      const data = await parseBody(req);
      if (Users.getByEmail(data.email || '')) {
        return redirect(res, '/admin/users?error_email=1');
      }
      Users.create({ name: data.name, email: data.email, passwordHash: hashPassword(data.password || 'ChangeMe123!'), role: data.role === 'admin' ? 'admin' : 'staff' });
      return redirect(res, '/admin/users?created=1');
    }
    const userDeleteMatch = pathname.match(/^\/admin\/users\/([a-f0-9]+)\/delete$/);
    if (userDeleteMatch && method === 'POST') {
      const admins = Users.all().filter((u) => u.role === 'admin');
      const target = Users.get(userDeleteMatch[1]);
      if (target && target.role === 'admin' && admins.length <= 1) {
        return redirect(res, '/admin/users?error_last_admin=1');
      }
      Users.remove(userDeleteMatch[1]);
      return redirect(res, '/admin/users?deleted=1');
    }

    if (pathname === '/admin/settings' && method === 'GET') {
      const webhook = process.env.GHL_WEBHOOK_URL || '';
      return send(
        res,
        200,
        render_adminSettings({
          session: user,
          ghlConfigured: !!webhook,
          webhookUrlMasked: webhook ? webhook.replace(/(.{20}).*(.{6})/, '$1...$2') : '',
        })
      );
    }

    return notFound(res);
  }

  return notFound(res);
}

function normalizePropertyInput(data) {
  return {
    title: data.title,
    suburb: data.suburb,
    state: data.state,
    postcode: data.postcode,
    listingType: data.listingType,
    status: data.status,
    propertyType: data.propertyType,
    priceLabel: data.priceLabel || undefined,
    priceMin: data.priceMin ? Number(data.priceMin) : undefined,
    priceMax: data.priceMax ? Number(data.priceMax) : undefined,
    bedrooms: data.bedrooms ? Number(data.bedrooms) : undefined,
    bathrooms: data.bathrooms ? Number(data.bathrooms) : undefined,
    carSpaces: data.carSpaces ? Number(data.carSpaces) : undefined,
    landSize: data.landSize ? Number(data.landSize) : undefined,
    description: data.description,
    features: String(data.features || '')
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean),
  };
}



const STATIC_ASSETS = {
  '/static/styles.css': { type: 'text/css', body: STYLES_CSS },
  '/static/app.js': { type: 'application/javascript', body: APP_JS },
  '/static/logo.svg': { type: 'image/svg+xml', body: LOGO_SVG },
  '/static/logo-white.svg': { type: 'image/svg+xml', body: LOGO_WHITE_SVG },
};
function serveStatic(req, res, pathname) {
  const asset = STATIC_ASSETS[pathname];
  if (!asset) return notFound(res);
  res.writeHead(200, { 'Content-Type': asset.type });
  res.end(asset.body);
}



// ===== server.js (entry) =====



seedIfEmpty();

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error(err);
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Internal Server Error');
  });
});

server.listen(PORT, () => {
  console.log(`BuySmart running at http://localhost:${PORT}`);
  console.log(`Admin login at http://localhost:${PORT}/admin/login`);
});
