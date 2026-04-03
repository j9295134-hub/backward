import { createClient } from '@libsql/client';
import dotenv from 'dotenv';
import bcryptjs from 'bcryptjs';
dotenv.config();

const client = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:/tmp/local.db',
  authToken: process.env.TURSO_AUTH_TOKEN,
});

const getColumnName = (row) => String(row.name ?? row.NAME ?? row[1] ?? '');

async function ensureColumnExists(tableName, columnName, definition) {
  const result = await client.execute(`PRAGMA table_info(${tableName})`);
  const hasColumn = result.rows.some((row) => getColumnName(row) === columnName);

  if (!hasColumn) {
    await client.execute(`ALTER TABLE ${tableName} ADD COLUMN ${definition}`);
  }
}

const getId = () => Math.random().toString(36).substring(2, 11);
const sanitizeDomain = (value = '') => value.toLowerCase().replace(/\s+/g, '').replace(/[^a-z0-9]/g, '');
const getDefaultAdminEmail = (brandName) => `admin@${sanitizeDomain(brandName) || 'admin'}.com`;

async function seedAdmin(brandName) {
  const envEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const envPassword = (process.env.ADMIN_PASSWORD || '').trim();
  const envName = (process.env.ADMIN_NAME || '').trim();
  const fallbackEmail = getDefaultAdminEmail(brandName);
  const fallbackPassword = 'admin123';
  const fallbackName = `${brandName} Admin`;
  const shouldUseEnvCredentials = Boolean(envEmail && envPassword);

  if (shouldUseEnvCredentials) {
    const passwordHash = await bcryptjs.hash(envPassword, 10);
    const existingAdmin = await client.execute({ sql: 'SELECT id FROM admins WHERE email = ?', args: [envEmail] });

    if (existingAdmin.rows[0]) {
      await client.execute({
        sql: 'UPDATE admins SET password = ?, name = ? WHERE email = ?',
        args: [passwordHash, envName || fallbackName, envEmail],
      });
      return;
    }

    await client.execute({
      sql: 'INSERT INTO admins (id, email, password, name) VALUES (?, ?, ?, ?)',
      args: [getId(), envEmail, passwordHash, envName || fallbackName],
    });
    return;
  }

  const adminCount = await client.execute('SELECT COUNT(*) as count FROM admins');
  const existingCount = Number(adminCount.rows[0]?.count ?? adminCount.rows[0]?.COUNT ?? 0);

  if (existingCount > 0) {
    return;
  }

  const passwordHash = await bcryptjs.hash(fallbackPassword, 10);
  console.warn('Using fallback admin credentials. Set ADMIN_EMAIL and ADMIN_PASSWORD in the backend environment for production.');
  await client.execute({
    sql: 'INSERT INTO admins (id, email, password, name) VALUES (?, ?, ?, ?)',
    args: [getId(), fallbackEmail, passwordHash, fallbackName],
  });
}

export async function initDB() {
  await client.batch([
    `CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      categoryId TEXT,
      image TEXT,
      images TEXT DEFAULT '[]',
      stock INTEGER DEFAULT 0,
      isFeatured INTEGER DEFAULT 0,
      status TEXT DEFAULT 'in_stock',
      estimatedDelivery TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS categories (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      slug TEXT,
      description TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY,
      customerName TEXT NOT NULL,
      customerEmail TEXT NOT NULL,
      customerPhone TEXT,
      items TEXT NOT NULL,
      totalAmount REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      shippingAddress TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS packages (
      id TEXT PRIMARY KEY,
      trackingId TEXT NOT NULL UNIQUE,
      orderId TEXT,
      status TEXT DEFAULT 'pending',
      shippingRoute TEXT DEFAULT 'sea',
      origin TEXT,
      destination TEXT,
      currentLocation TEXT,
      estimatedDelivery TEXT,
      weight REAL,
      notes TEXT,
      packageItems TEXT DEFAULT '[]',
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS admins (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      name TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
  ], 'deferred');

  await ensureColumnExists('products', 'images', `images TEXT DEFAULT '[]'`);
  await ensureColumnExists('packages', 'packageItems', `packageItems TEXT DEFAULT '[]'`);

  // Seed default settings from env vars (only if not already set)
  const defaultWhatsappNumber = process.env.VITE_WHATSAPP_NUMBER || process.env.WHATSAPP_NUMBER || '';
  const defaultBrandName = process.env.VITE_BRAND_NAME || process.env.BRAND_NAME || 'HopeLink Imports';

  if (defaultWhatsappNumber) {
    await client.execute({
      sql: 'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updatedAt = CURRENT_TIMESTAMP',
      args: ['whatsapp_number', defaultWhatsappNumber],
    });
  }

  await client.execute({
    sql: 'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updatedAt = CURRENT_TIMESTAMP',
    args: ['brand_name', defaultBrandName],
  });

  await seedAdmin(defaultBrandName);

  console.log('Database tables initialized');
}

export default client;
