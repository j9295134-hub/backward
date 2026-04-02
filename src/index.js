import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import client, { initDB } from './database.js';
import bcryptjs from 'bcryptjs';
import crypto from 'crypto';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const ADMIN_TOKEN_SECRET = process.env.ADMIN_TOKEN_SECRET || process.env.TURSO_AUTH_TOKEN || 'change-this-admin-token-secret';
const ADMIN_TOKEN_TTL_MS = 1000 * 60 * 60 * 12;

// Middleware
app.use(cors());
app.use(express.json());

// Helper function to generate IDs
const getId = () => Math.random().toString(36).substring(2, 11);
const normalizeTrackingId = (value = '') => value.trim().replace(/\s+/g, '').toUpperCase();
const normalizeEmail = (value = '') => String(value).trim().toLowerCase();
const parseJsonArray = (value) => {
  if (Array.isArray(value)) return value;
  if (typeof value !== 'string' || !value.trim()) return [];

  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};
const sanitizePackageItems = (value) =>
  parseJsonArray(value)
    .map((item) => {
      const quantity = Math.max(1, Math.round(Number(item?.quantity) || 1));
      const name = String(item?.name ?? '').trim();
      const imageUrl = String(item?.imageUrl ?? item?.image_url ?? '').trim();
      const productId = String(item?.productId ?? item?.product_id ?? '').trim();

      if (!name) return null;

      return {
        productId: productId || undefined,
        name,
        imageUrl,
        quantity,
      };
    })
    .filter(Boolean);
const mapPackageRow = (row) => ({
  ...row,
  packageItems: sanitizePackageItems(row.packageItems),
});
const createTokenSignature = (payload) =>
  crypto.createHmac('sha256', ADMIN_TOKEN_SECRET).update(payload).digest('base64url');
const createAdminToken = (admin) => {
  const payload = Buffer.from(
    JSON.stringify({
      sub: admin.id,
      email: admin.email,
      name: admin.name || 'Admin',
      type: 'admin',
      exp: Date.now() + ADMIN_TOKEN_TTL_MS,
    })
  ).toString('base64url');

  return `${payload}.${createTokenSignature(payload)}`;
};
const verifyAdminToken = (token) => {
  if (!token || typeof token !== 'string') return null;

  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;

  const expectedSignature = createTokenSignature(payload);
  const providedBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expectedSignature);

  if (providedBuffer.length !== expectedBuffer.length) return null;
  if (!crypto.timingSafeEqual(providedBuffer, expectedBuffer)) return null;

  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (decoded.type !== 'admin' || !decoded.sub || !decoded.exp || decoded.exp < Date.now()) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
};
const getBearerToken = (req) => {
  const authorizationHeader = req.headers.authorization || '';
  if (!authorizationHeader.startsWith('Bearer ')) return '';
  return authorizationHeader.slice(7).trim();
};
const getAdminById = async (id) => {
  const result = await client.execute({ sql: 'SELECT id, email, name FROM admins WHERE id = ?', args: [id] });
  return result.rows[0] || null;
};
const requireAdminAuth = async (req, res, next) => {
  try {
    const token = getBearerToken(req);
    const payload = verifyAdminToken(token);

    if (!payload) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const admin = await getAdminById(payload.sub);
    if (!admin) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    req.admin = admin;
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

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

app.post('/api/products', requireAdminAuth, async (req, res) => {
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

app.put('/api/products/:id', requireAdminAuth, async (req, res) => {
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

app.delete('/api/products/:id', requireAdminAuth, async (req, res) => {
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

app.post('/api/categories', requireAdminAuth, async (req, res) => {
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

app.put('/api/categories/:id', requireAdminAuth, async (req, res) => {
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

app.delete('/api/categories/:id', requireAdminAuth, async (req, res) => {
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

app.get('/api/orders', requireAdminAuth, async (req, res) => {
  try {
    const result = await client.execute('SELECT * FROM orders ORDER BY createdAt DESC');
    const rows = result.rows.map(row => ({ ...row, items: JSON.parse(row.items) }));
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/orders/:id', requireAdminAuth, async (req, res) => {
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

app.get('/api/packages', requireAdminAuth, async (req, res) => {
  try {
    const result = await client.execute('SELECT * FROM packages ORDER BY createdAt DESC');
    res.json(result.rows.map(mapPackageRow));
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
    res.json(mapPackageRow(result.rows[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/packages', requireAdminAuth, async (req, res) => {
  const { trackingId, orderId, status, shippingRoute, origin, destination, currentLocation, estimatedDelivery, weight, notes, packageItems } = req.body;
  const id = getId();
  const normalizedTrackingId = normalizeTrackingId(trackingId ?? '');
  const normalizedPackageItems = sanitizePackageItems(packageItems);
  try {
    if (!normalizedTrackingId) return res.status(400).json({ error: 'Tracking ID is required' });
    await client.execute({
      sql: 'INSERT INTO packages (id, trackingId, orderId, status, shippingRoute, origin, destination, currentLocation, estimatedDelivery, weight, notes, packageItems) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      args: [id, normalizedTrackingId, orderId ?? null, status ?? 'pending', shippingRoute ?? 'sea', origin ?? null, destination ?? null, currentLocation ?? null, estimatedDelivery ?? null, weight ?? null, notes ?? null, JSON.stringify(normalizedPackageItems)],
    });
    res.status(201).json({ id, trackingId: normalizedTrackingId, orderId, status: status || 'pending', shippingRoute: shippingRoute || 'sea', origin, destination, currentLocation, estimatedDelivery, weight, notes, packageItems: normalizedPackageItems });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Tracking ID already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/packages/:id', requireAdminAuth, async (req, res) => {
  try {
    const existingResult = await client.execute({ sql: 'SELECT * FROM packages WHERE id = ?', args: [req.params.id] });
    const existingPackage = existingResult.rows[0];

    if (!existingPackage) return res.status(404).json({ error: 'Package not found' });

    const normalizedTrackingId = normalizeTrackingId(req.body.trackingId ?? existingPackage.trackingId ?? '');
    const normalizedPackageItems =
      req.body.packageItems === undefined
        ? sanitizePackageItems(existingPackage.packageItems)
        : sanitizePackageItems(req.body.packageItems);

    if (!normalizedTrackingId) return res.status(400).json({ error: 'Tracking ID is required' });

    const updatedPackage = {
      trackingId: normalizedTrackingId,
      orderId: req.body.orderId ?? existingPackage.orderId ?? null,
      status: req.body.status ?? existingPackage.status ?? 'pending',
      shippingRoute: req.body.shippingRoute ?? existingPackage.shippingRoute ?? 'sea',
      origin: req.body.origin ?? existingPackage.origin ?? null,
      destination: req.body.destination ?? existingPackage.destination ?? null,
      currentLocation: req.body.currentLocation ?? existingPackage.currentLocation ?? null,
      estimatedDelivery: req.body.estimatedDelivery ?? existingPackage.estimatedDelivery ?? null,
      notes: req.body.notes ?? existingPackage.notes ?? null,
      packageItems: normalizedPackageItems,
    };

    await client.execute({
      sql: 'UPDATE packages SET trackingId = ?, orderId = ?, status = ?, shippingRoute = ?, origin = ?, destination = ?, currentLocation = ?, estimatedDelivery = ?, notes = ?, packageItems = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?',
      args: [
        updatedPackage.trackingId,
        updatedPackage.orderId,
        updatedPackage.status,
        updatedPackage.shippingRoute,
        updatedPackage.origin,
        updatedPackage.destination,
        updatedPackage.currentLocation,
        updatedPackage.estimatedDelivery,
        updatedPackage.notes,
        JSON.stringify(updatedPackage.packageItems),
        req.params.id,
      ],
    });
    res.json({ id: req.params.id, ...updatedPackage });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Tracking ID already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/packages/:id', requireAdminAuth, async (req, res) => {
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
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const result = await client.execute({ sql: 'SELECT * FROM admins WHERE email = ?', args: [normalizedEmail] });
    const row = result.rows[0];
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    const isValid = await bcryptjs.compare(password, row.password);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });
    const admin = { id: row.id, email: row.email, name: row.name || 'Admin' };
    const token = createAdminToken(admin);
    res.json({ success: true, token, admin });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', requireAdminAuth, async (req, res) => {
  res.json({ success: true, admin: req.admin });
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

app.put('/api/settings/:key', requireAdminAuth, async (req, res) => {
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
