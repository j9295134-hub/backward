import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import client, { initDB } from './database.js';
import bcryptjs from 'bcryptjs';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Helper function to generate IDs
const getId = () => Math.random().toString(36).substring(2, 11);
const normalizeTrackingId = (value = '') => value.trim().replace(/\s+/g, '').toUpperCase();

// Initialize DB tables — store promise so routes can await it
const dbReady = initDB().catch(console.error);

// Middleware to ensure DB is initialized before handling any request
app.use(async (_req, _res, next) => {
  await dbReady;
  next();
});

// ============ PRODUCTS ENDPOINTS ============

app.get('/api/products', async (req, res) => {
  try {
    const result = await client.execute('SELECT * FROM products ORDER BY createdAt DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const result = await client.execute({ sql: 'SELECT * FROM products WHERE id = ?', args: [req.params.id] });
    if (!result.rows[0]) return res.status(404).json({ error: 'Product not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/products', async (req, res) => {
  const { name, description, price, categoryId, image, stock, isFeatured, status, estimatedDelivery } = req.body;
  const id = getId();
  try {
    await client.execute({
      sql: 'INSERT INTO products (id, name, description, price, categoryId, image, stock, isFeatured, status, estimatedDelivery) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      args: [id, name ?? null, description ?? null, price ?? null, categoryId ?? null, image ?? null, stock ?? 0, isFeatured ? 1 : 0, status ?? 'in_stock', estimatedDelivery ?? null],
    });
    res.status(201).json({ id, name, description, price, categoryId, image, stock, isFeatured: !!isFeatured, status: status || 'in_stock', estimatedDelivery });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/products/:id', async (req, res) => {
  const { name, description, price, categoryId, image, stock, isFeatured, status, estimatedDelivery } = req.body;
  try {
    await client.execute({
      sql: 'UPDATE products SET name = ?, description = ?, price = ?, categoryId = ?, image = ?, stock = ?, isFeatured = ?, status = ?, estimatedDelivery = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?',
      args: [name ?? null, description ?? null, price ?? null, categoryId ?? null, image ?? null, stock ?? null, isFeatured ? 1 : 0, status ?? null, estimatedDelivery ?? null, req.params.id],
    });
    res.json({ id: req.params.id, name, description, price, categoryId, image, stock, isFeatured: !!isFeatured, status, estimatedDelivery });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/products/:id', async (req, res) => {
  try {
    await client.execute({ sql: 'DELETE FROM products WHERE id = ?', args: [req.params.id] });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ CATEGORIES ENDPOINTS ============

app.get('/api/categories', async (req, res) => {
  try {
    const result = await client.execute('SELECT * FROM categories ORDER BY createdAt DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/categories/:id', async (req, res) => {
  try {
    const result = await client.execute({ sql: 'SELECT * FROM categories WHERE id = ?', args: [req.params.id] });
    if (!result.rows[0]) return res.status(404).json({ error: 'Category not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/categories', async (req, res) => {
  const { name, slug, description } = req.body;
  const id = getId();
  const computedSlug = slug || name.toLowerCase().replace(/\s+/g, '-');
  try {
    await client.execute({
      sql: 'INSERT INTO categories (id, name, slug, description) VALUES (?, ?, ?, ?)',
      args: [id, name ?? null, computedSlug ?? null, description ?? null],
    });
    res.status(201).json({ id, name, slug: computedSlug, description });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Category name already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/categories/:id', async (req, res) => {
  const { name, slug, description } = req.body;
  const computedSlug = slug || name.toLowerCase().replace(/\s+/g, '-');
  try {
    await client.execute({
      sql: 'UPDATE categories SET name = ?, slug = ?, description = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?',
      args: [name ?? null, computedSlug ?? null, description ?? null, req.params.id],
    });
    res.json({ id: req.params.id, name, slug: computedSlug, description });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/categories/:id', async (req, res) => {
  try {
    await client.execute({ sql: 'DELETE FROM categories WHERE id = ?', args: [req.params.id] });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ ORDERS ENDPOINTS ============

app.post('/api/orders', async (req, res) => {
  const { customerName, customerEmail, customerPhone, items, totalAmount, shippingAddress } = req.body;
  const id = getId();
  try {
    await client.execute({
      sql: 'INSERT INTO orders (id, customerName, customerEmail, customerPhone, items, totalAmount, shippingAddress) VALUES (?, ?, ?, ?, ?, ?, ?)',
      args: [id, customerName ?? null, customerEmail ?? null, customerPhone ?? null, JSON.stringify(items ?? []), totalAmount ?? null, shippingAddress ?? null],
    });
    res.status(201).json({ id, customerName, customerEmail, customerPhone, items, totalAmount, shippingAddress, status: 'pending' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/orders', async (req, res) => {
  try {
    const result = await client.execute('SELECT * FROM orders ORDER BY createdAt DESC');
    const rows = result.rows.map(row => ({ ...row, items: JSON.parse(row.items) }));
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/orders/:id', async (req, res) => {
  try {
    const result = await client.execute({ sql: 'SELECT * FROM orders WHERE id = ?', args: [req.params.id] });
    if (!result.rows[0]) return res.status(404).json({ error: 'Order not found' });
    const row = result.rows[0];
    res.json({ ...row, items: JSON.parse(row.items) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ PACKAGES ENDPOINTS ============

app.get('/api/packages', async (req, res) => {
  try {
    const result = await client.execute('SELECT * FROM packages ORDER BY createdAt DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/packages/track/:trackingId', async (req, res) => {
  try {
    const trackingId = normalizeTrackingId(req.params.trackingId || '');
    if (!trackingId) return res.status(400).json({ error: 'Tracking ID is required' });
    const result = await client.execute({ sql: 'SELECT * FROM packages WHERE UPPER(TRIM(trackingId)) = ?', args: [trackingId] });
    if (!result.rows[0]) return res.status(404).json({ error: 'Package not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/packages', async (req, res) => {
  const { trackingId, orderId, status, shippingRoute, origin, destination, currentLocation, estimatedDelivery, weight, notes } = req.body;
  const id = getId();
  const normalizedTrackingId = normalizeTrackingId(trackingId ?? '');
  try {
    if (!normalizedTrackingId) return res.status(400).json({ error: 'Tracking ID is required' });
    await client.execute({
      sql: 'INSERT INTO packages (id, trackingId, orderId, status, shippingRoute, origin, destination, currentLocation, estimatedDelivery, weight, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      args: [id, normalizedTrackingId, orderId ?? null, status ?? 'pending', shippingRoute ?? 'sea', origin ?? null, destination ?? null, currentLocation ?? null, estimatedDelivery ?? null, weight ?? null, notes ?? null],
    });
    res.status(201).json({ id, trackingId: normalizedTrackingId, orderId, status: status || 'pending', shippingRoute: shippingRoute || 'sea', origin, destination, currentLocation, estimatedDelivery, weight, notes });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Tracking ID already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/packages/:id', async (req, res) => {
  const { status, shippingRoute, currentLocation, estimatedDelivery, notes } = req.body;
  try {
    await client.execute({
      sql: 'UPDATE packages SET status = ?, shippingRoute = ?, currentLocation = ?, estimatedDelivery = ?, notes = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?',
      args: [status ?? null, shippingRoute ?? null, currentLocation ?? null, estimatedDelivery ?? null, notes ?? null, req.params.id],
    });
    res.json({ id: req.params.id, status, shippingRoute, currentLocation, estimatedDelivery, notes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/packages/:id', async (req, res) => {
  try {
    await client.execute({ sql: 'DELETE FROM packages WHERE id = ?', args: [req.params.id] });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ ADMIN AUTHENTICATION ============

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await client.execute({ sql: 'SELECT * FROM admins WHERE email = ?', args: [email] });
    const row = result.rows[0];
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    const isValid = await bcryptjs.compare(password, row.password);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ success: true, email: row.email, name: row.name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ HEALTH CHECK ============

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Backend is running' });
});

// ============ SETTINGS ENDPOINTS ============

app.get('/api/settings', async (req, res) => {
  try {
    const result = await client.execute('SELECT key, value FROM settings');
    const settings = {};
    for (const row of result.rows) {
      settings[row.key] = row.value;
    }
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/settings/:key', async (req, res) => {
  const { value } = req.body;
  const { key } = req.params;
  try {
    await client.execute({
      sql: 'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updatedAt = CURRENT_TIMESTAMP',
      args: [key, value ?? ''],
    });
    res.json({ key, value });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

export default app;
