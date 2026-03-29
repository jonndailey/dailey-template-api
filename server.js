const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { migrate } = require('./migrate');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production-' + Math.random().toString(36);

let pool;
async function getPool() {
  if (!pool) pool = mysql.createPool(process.env.DATABASE_URL);
  return pool;
}

app.set('trust proxy', true);
app.use(express.json());

// CORS
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', process.env.CORS_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Rate limiting (in-memory)
const rateLimits = {};
function rateLimit(limit = 100, windowMs = 60000) {
  return (req, res, next) => {
    const key = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    if (!rateLimits[key] || rateLimits[key].reset < now) {
      rateLimits[key] = { count: 0, reset: now + windowMs };
    }
    rateLimits[key].count++;
    res.setHeader('X-RateLimit-Limit', limit);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, limit - rateLimits[key].count));
    res.setHeader('X-RateLimit-Reset', rateLimits[key].reset);
    if (rateLimits[key].count > limit) {
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }
    next();
  };
}
// Clean up rate limits every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const key of Object.keys(rateLimits)) {
    if (rateLimits[key].reset < now) delete rateLimits[key];
  }
}, 300000);

app.use(rateLimit(200, 60000));

// Auth middleware
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error: 'Authorization header required. Use: Bearer <token>' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch { return res.status(401).json({ error: 'Invalid or expired token' }); }
}

function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try { req.user = jwt.verify(header.slice(7), JWT_SECRET); } catch {}
  }
  next();
}

// Validation helpers
function validate(fields, body) {
  const errors = [];
  for (const [name, rules] of Object.entries(fields)) {
    const val = body[name];
    if (rules.required && (val === undefined || val === null || val === '')) errors.push(`${name} is required`);
    if (rules.minLength && val && val.length < rules.minLength) errors.push(`${name} must be at least ${rules.minLength} characters`);
    if (rules.maxLength && val && val.length > rules.maxLength) errors.push(`${name} must be at most ${rules.maxLength} characters`);
    if (rules.email && val && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) errors.push(`${name} must be a valid email`);
    if (rules.enum && val && !rules.enum.includes(val)) errors.push(`${name} must be one of: ${rules.enum.join(', ')}`);
  }
  return errors;
}

// Pagination helper
function paginate(query, req) {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  const offset = (page - 1) * limit;
  return { page, limit, offset, sql: `${query} LIMIT ${limit} OFFSET ${offset}` };
}

// =====================
// AUTH ENDPOINTS
// =====================
app.post('/api/auth/register', async (req, res) => {
  const errors = validate({
    email: { required: true, email: true },
    password: { required: true, minLength: 6 },
    name: { required: true, minLength: 1, maxLength: 255 }
  }, req.body);
  if (errors.length) return res.status(400).json({ errors });
  try {
    const db = await getPool();
    const { email, password, name } = req.body;
    const [existing] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length) return res.status(409).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(password, 10);
    const [result] = await db.execute('INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)', [email, hash, name]);
    const token = jwt.sign({ id: result.insertId, email, name, role: 'user' }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: result.insertId, email, name, role: 'user' } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const errors = validate({ email: { required: true }, password: { required: true } }, req.body);
  if (errors.length) return res.status(400).json({ errors });
  try {
    const db = await getPool();
    const { email, password } = req.body;
    const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (!users.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = users[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [users] = await db.execute('SELECT id, email, name, role, created_at FROM users WHERE id = ?', [req.user.id]);
    if (!users.length) return res.status(404).json({ error: 'User not found' });
    res.json({ user: users[0] });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// =====================
// USERS ENDPOINTS
// =====================
app.get('/api/users', auth, async (req, res) => {
  try {
    const db = await getPool();
    let where = 'WHERE 1=1';
    const params = [];
    if (req.query.search) { where += ' AND (name LIKE ? OR email LIKE ?)'; params.push(`%${req.query.search}%`, `%${req.query.search}%`); }
    if (req.query.role) { where += ' AND role = ?'; params.push(req.query.role); }
    const sortable = ['name', 'email', 'created_at'];
    const sort = sortable.includes(req.query.sort) ? req.query.sort : 'created_at';
    const order = req.query.order === 'asc' ? 'ASC' : 'DESC';
    const [countResult] = await db.execute(`SELECT COUNT(*) as total FROM users ${where}`, params);
    const { page, limit, sql } = paginate(`SELECT id, email, name, role, created_at FROM users ${where} ORDER BY ${sort} ${order}`, req);
    const [users] = await db.execute(sql, params);
    res.json({ users, pagination: { page, limit, total: countResult[0].total, pages: Math.ceil(countResult[0].total / limit) } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [users] = await db.execute('SELECT id, email, name, role, created_at FROM users WHERE id = ?', [req.params.id]);
    if (!users.length) return res.status(404).json({ error: 'User not found' });
    res.json({ user: users[0] });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// =====================
// POSTS ENDPOINTS
// =====================
app.get('/api/posts', optionalAuth, async (req, res) => {
  try {
    const db = await getPool();
    let where = 'WHERE 1=1';
    const params = [];
    if (req.query.status) { where += ' AND p.status = ?'; params.push(req.query.status); }
    if (req.query.user_id) { where += ' AND p.user_id = ?'; params.push(req.query.user_id); }
    if (req.query.search) { where += ' AND (p.title LIKE ? OR p.body LIKE ?)'; params.push(`%${req.query.search}%`, `%${req.query.search}%`); }
    const sortable = ['title', 'created_at', 'updated_at'];
    const sort = sortable.includes(req.query.sort) ? `p.${req.query.sort}` : 'p.created_at';
    const order = req.query.order === 'asc' ? 'ASC' : 'DESC';
    const [countResult] = await db.execute(`SELECT COUNT(*) as total FROM posts p ${where}`, params);
    const { page, limit, sql } = paginate(`SELECT p.*, u.name as author_name, u.email as author_email FROM posts p JOIN users u ON p.user_id = u.id ${where} ORDER BY ${sort} ${order}`, req);
    const [posts] = await db.execute(sql, params);
    res.json({ posts, pagination: { page, limit, total: countResult[0].total, pages: Math.ceil(countResult[0].total / limit) } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/posts/:id', optionalAuth, async (req, res) => {
  try {
    const db = await getPool();
    const [posts] = await db.execute('SELECT p.*, u.name as author_name FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?', [req.params.id]);
    if (!posts.length) return res.status(404).json({ error: 'Post not found' });
    res.json({ post: posts[0] });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts', auth, async (req, res) => {
  const errors = validate({
    title: { required: true, maxLength: 255 },
    body: { required: true },
    status: { enum: ['draft', 'published', 'archived'] }
  }, req.body);
  if (errors.length) return res.status(400).json({ errors });
  try {
    const db = await getPool();
    const { title, body, status } = req.body;
    const [result] = await db.execute('INSERT INTO posts (user_id, title, body, status) VALUES (?, ?, ?, ?)',
      [req.user.id, title, body, status || 'draft']);
    const [posts] = await db.execute('SELECT * FROM posts WHERE id = ?', [result.insertId]);
    res.status(201).json({ post: posts[0] });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/posts/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [existing] = await db.execute('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    if (!existing.length) return res.status(404).json({ error: 'Post not found' });
    if (existing[0].user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const { title, body, status } = req.body;
    const errors = validate({ title: { maxLength: 255 }, status: { enum: ['draft', 'published', 'archived'] } }, req.body);
    if (errors.length) return res.status(400).json({ errors });
    await db.execute('UPDATE posts SET title=COALESCE(?,title), body=COALESCE(?,body), status=COALESCE(?,status) WHERE id=?',
      [title || null, body || null, status || null, req.params.id]);
    const [posts] = await db.execute('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    res.json({ post: posts[0] });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/posts/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [existing] = await db.execute('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    if (!existing.length) return res.status(404).json({ error: 'Post not found' });
    if (existing[0].user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    await db.execute('DELETE FROM posts WHERE id = ?', [req.params.id]);
    res.json({ message: 'Post deleted' });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// =====================
// COMMENTS ENDPOINTS
// =====================
app.get('/api/posts/:postId/comments', async (req, res) => {
  try {
    const db = await getPool();
    const { page, limit, sql } = paginate(
      `SELECT c.*, u.name as author_name FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at DESC`, req);
    const [comments] = await db.execute(sql, [req.params.postId]);
    const [countResult] = await db.execute('SELECT COUNT(*) as total FROM comments WHERE post_id = ?', [req.params.postId]);
    res.json({ comments, pagination: { page, limit, total: countResult[0].total, pages: Math.ceil(countResult[0].total / limit) } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts/:postId/comments', auth, async (req, res) => {
  const errors = validate({ body: { required: true } }, req.body);
  if (errors.length) return res.status(400).json({ errors });
  try {
    const db = await getPool();
    const [posts] = await db.execute('SELECT id FROM posts WHERE id = ?', [req.params.postId]);
    if (!posts.length) return res.status(404).json({ error: 'Post not found' });
    const [result] = await db.execute('INSERT INTO comments (post_id, user_id, body) VALUES (?, ?, ?)',
      [req.params.postId, req.user.id, req.body.body]);
    const [comments] = await db.execute('SELECT c.*, u.name as author_name FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = ?', [result.insertId]);
    res.status(201).json({ comment: comments[0] });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/comments/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [existing] = await db.execute('SELECT * FROM comments WHERE id = ?', [req.params.id]);
    if (!existing.length) return res.status(404).json({ error: 'Comment not found' });
    if (existing[0].user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    await db.execute('DELETE FROM comments WHERE id = ?', [req.params.id]);
    res.json({ message: 'Comment deleted' });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// =====================
// HEALTH CHECK
// =====================
app.get('/health', async (req, res) => {
  try {
    const db = await getPool();
    await db.execute('SELECT 1');
    res.json({ status: 'ok', database: 'connected' });
  } catch {
    res.json({ status: 'ok', database: 'disconnected' });
  }
});

// =====================
// API DOCS PAGE
// =====================
app.get('/docs', (req, res) => {
  const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
  const protocol = req.headers['x-forwarded-proto'] || (host.endsWith('.dailey.cloud') ? 'https' : req.protocol) || 'http';
  const baseUrl = process.env.BASE_URL || `${protocol}://${host}`;
  const CSS = `
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1a1a2e; background: #f8f9fa; }
    .container { max-width: 900px; margin: 0 auto; padding: 0 24px; }
    header { background: #1a1a2e; color: #fff; padding: 48px 0; }
    header h1 { font-size: 36px; margin-bottom: 8px; }
    header p { color: #aaa; font-size: 18px; }
    .section { margin: 32px 0; }
    .section h2 { font-size: 24px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #e8e8e8; }
    .endpoint { background: #fff; border-radius: 12px; margin-bottom: 16px; border: 1px solid #e8e8e8; overflow: hidden; }
    .endpoint-header { padding: 16px 20px; display: flex; align-items: center; gap: 12px; cursor: pointer; }
    .endpoint-header:hover { background: #f8f9ff; }
    .method { padding: 4px 12px; border-radius: 6px; font-size: 13px; font-weight: 700; color: #fff; font-family: monospace; }
    .method-get { background: #2d6a4f; }
    .method-post { background: #4361ee; }
    .method-put { background: #e6a817; color: #333; }
    .method-delete { background: #e63946; }
    .path { font-family: monospace; font-size: 15px; font-weight: 600; }
    .desc { color: #888; font-size: 14px; margin-left: auto; }
    .auth-badge { background: #fde8e8; color: #c1121f; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; }
    .endpoint-body { padding: 0 20px 20px; border-top: 1px solid #f0f0f0; display: none; }
    .endpoint.open .endpoint-body { display: block; padding-top: 16px; }
    .endpoint.open .endpoint-header { background: #f8f9ff; }
    pre { background: #1a1a2e; color: #e8e8e8; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 14px; margin: 8px 0; }
    code { font-family: 'SF Mono', Menlo, monospace; }
    .param-table { width: 100%; border-collapse: collapse; margin: 8px 0; }
    .param-table th { text-align: left; padding: 8px; font-size: 12px; color: #888; text-transform: uppercase; border-bottom: 1px solid #f0f0f0; }
    .param-table td { padding: 8px; font-size: 14px; border-bottom: 1px solid #f0f0f0; }
    .param-table .type { color: #4361ee; font-family: monospace; font-size: 13px; }
    footer { text-align: center; padding: 32px; color: #888; font-size: 14px; }
    .note { background: #eef0ff; padding: 16px; border-radius: 8px; font-size: 14px; margin: 16px 0; }
  `;

  res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Documentation</title><style>${CSS}</style></head><body>
<header><div class="container"><h1>API Documentation</h1><p>RESTful API with JWT authentication, pagination, and filtering</p></div></header>
<main class="container">
  <div class="note">
    <strong>Base URL:</strong> <code>${baseUrl}</code><br>
    <strong>Authentication:</strong> Include <code>Authorization: Bearer &lt;token&gt;</code> header for protected endpoints.
  </div>

  <div class="section"><h2>Authentication</h2>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-post">POST</span><span class="path">/api/auth/register</span><span class="desc">Create a new account</span></div><div class="endpoint-body"><p>Request body:</p><pre>{ "email": "user@example.com", "password": "secret123", "name": "John Doe" }</pre><p>Response:</p><pre>{ "token": "eyJ...", "user": { "id": 1, "email": "...", "name": "...", "role": "user" } }</pre></div></div>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-post">POST</span><span class="path">/api/auth/login</span><span class="desc">Log in with email/password</span></div><div class="endpoint-body"><p>Request body:</p><pre>{ "email": "user@example.com", "password": "secret123" }</pre><p>Response:</p><pre>{ "token": "eyJ...", "user": { "id": 1, "email": "...", "name": "...", "role": "user" } }</pre></div></div>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-get">GET</span><span class="path">/api/auth/me</span><span class="desc">Get current user</span><span class="auth-badge">Auth</span></div><div class="endpoint-body"><p>Response:</p><pre>{ "user": { "id": 1, "email": "...", "name": "...", "role": "user", "created_at": "..." } }</pre></div></div>
  </div>

  <div class="section"><h2>Users</h2>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-get">GET</span><span class="path">/api/users</span><span class="desc">List all users</span><span class="auth-badge">Auth</span></div><div class="endpoint-body"><p>Query parameters:</p><table class="param-table"><thead><tr><th>Param</th><th>Type</th><th>Description</th></tr></thead><tbody><tr><td>page</td><td class="type">int</td><td>Page number (default: 1)</td></tr><tr><td>limit</td><td class="type">int</td><td>Items per page (default: 20, max: 100)</td></tr><tr><td>search</td><td class="type">string</td><td>Search by name or email</td></tr><tr><td>role</td><td class="type">string</td><td>Filter by role (user, admin)</td></tr><tr><td>sort</td><td class="type">string</td><td>Sort by: name, email, created_at</td></tr><tr><td>order</td><td class="type">string</td><td>asc or desc</td></tr></tbody></table></div></div>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-get">GET</span><span class="path">/api/users/:id</span><span class="desc">Get a specific user</span><span class="auth-badge">Auth</span></div><div class="endpoint-body"><p>Response:</p><pre>{ "user": { "id": 1, "email": "...", "name": "...", "role": "user", "created_at": "..." } }</pre></div></div>
  </div>

  <div class="section"><h2>Posts</h2>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-get">GET</span><span class="path">/api/posts</span><span class="desc">List posts with filtering</span></div><div class="endpoint-body"><p>Query parameters:</p><table class="param-table"><thead><tr><th>Param</th><th>Type</th><th>Description</th></tr></thead><tbody><tr><td>page, limit</td><td class="type">int</td><td>Pagination</td></tr><tr><td>status</td><td class="type">string</td><td>draft, published, archived</td></tr><tr><td>user_id</td><td class="type">int</td><td>Filter by author</td></tr><tr><td>search</td><td class="type">string</td><td>Search title and body</td></tr><tr><td>sort</td><td class="type">string</td><td>title, created_at, updated_at</td></tr></tbody></table></div></div>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-get">GET</span><span class="path">/api/posts/:id</span><span class="desc">Get a specific post</span></div><div class="endpoint-body"><p>Response includes author_name field.</p></div></div>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-post">POST</span><span class="path">/api/posts</span><span class="desc">Create a new post</span><span class="auth-badge">Auth</span></div><div class="endpoint-body"><pre>{ "title": "My Post", "body": "Content here...", "status": "published" }</pre></div></div>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-put">PUT</span><span class="path">/api/posts/:id</span><span class="desc">Update a post</span><span class="auth-badge">Auth</span></div><div class="endpoint-body"><p>Only the post author or an admin can update. All fields optional.</p><pre>{ "title": "Updated Title", "status": "published" }</pre></div></div>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-delete">DELETE</span><span class="path">/api/posts/:id</span><span class="desc">Delete a post</span><span class="auth-badge">Auth</span></div><div class="endpoint-body"><p>Only the post author or an admin can delete.</p></div></div>
  </div>

  <div class="section"><h2>Comments</h2>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-get">GET</span><span class="path">/api/posts/:postId/comments</span><span class="desc">List comments on a post</span></div><div class="endpoint-body"><p>Supports pagination (page, limit).</p></div></div>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-post">POST</span><span class="path">/api/posts/:postId/comments</span><span class="desc">Add a comment</span><span class="auth-badge">Auth</span></div><div class="endpoint-body"><pre>{ "body": "Great post!" }</pre></div></div>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-delete">DELETE</span><span class="path">/api/comments/:id</span><span class="desc">Delete a comment</span><span class="auth-badge">Auth</span></div><div class="endpoint-body"><p>Only the comment author or an admin can delete.</p></div></div>
  </div>

  <div class="section"><h2>Health</h2>
    <div class="endpoint"><div class="endpoint-header" onclick="this.parentElement.classList.toggle('open')"><span class="method method-get">GET</span><span class="path">/health</span><span class="desc">Health check</span></div><div class="endpoint-body"><pre>{ "status": "ok", "database": "connected" }</pre></div></div>
  </div>
</main>
<footer>Powered by <a href="https://dailey.cloud">Dailey OS</a></footer>
</body></html>`);
});

// Redirect root to docs
app.get('/', (req, res) => res.redirect('/docs'));

// =====================
// START
// =====================
async function start() {
  try { await migrate(); } catch (err) { console.error('[startup] Migration failed:', err.message); }

  // Seed data
  if (process.env.DATABASE_URL) {
    try {
      const db = await getPool();
      const [users] = await db.execute('SELECT COUNT(*) as cnt FROM users');
      if (users[0].cnt === 0) {
        const hash1 = await bcrypt.hash('password123', 10);
        const hash2 = await bcrypt.hash('password123', 10);
        await db.execute("INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)", ['admin@example.com', hash1, 'Admin User', 'admin']);
        await db.execute("INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)", ['user@example.com', hash2, 'Regular User', 'user']);

        const titles = ['Getting Started Guide', 'API Best Practices', 'Authentication Deep Dive', 'Building Scalable Systems', 'Deployment Strategies'];
        const bodies = [
          'This guide will walk you through the basics of using this API. You will learn how to authenticate, create resources, and handle pagination.',
          'Learn the best practices for building RESTful APIs including proper status codes, error handling, and resource naming conventions.',
          'A deep dive into JWT authentication, token refresh strategies, and securing your API endpoints against common attacks.',
          'Explore patterns for building systems that scale, including database optimization, caching strategies, and horizontal scaling.',
          'From development to production: CI/CD pipelines, container orchestration, and monitoring strategies for your API.'
        ];
        for (let i = 0; i < 5; i++) {
          await db.execute("INSERT INTO posts (user_id, title, body, status) VALUES (?, ?, ?, ?)",
            [(i % 2) + 1, titles[i], bodies[i], i < 4 ? 'published' : 'draft']);
        }

        const commentBodies = ['Great article!', 'Very helpful, thanks!', 'I have a question about this.', 'Could you elaborate on the security section?',
          'This saved me hours of debugging.', 'Well written!', 'Bookmarked for later.', 'Any plans for a follow-up?', 'The examples are really clear.', 'Love the depth here.'];
        for (let i = 0; i < 10; i++) {
          await db.execute("INSERT INTO comments (post_id, user_id, body) VALUES (?, ?, ?)",
            [(i % 4) + 1, (i % 2) + 1, commentBodies[i]]);
        }
        console.log('[seed] Sample data created');
      }
    } catch (err) { console.error('[seed] Error:', err.message); }
  }

  app.listen(PORT, () => console.log(`API running on port ${PORT}`));
}

start();
