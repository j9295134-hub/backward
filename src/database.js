import { createClient } from '@libsql/client';
import dotenv from 'dotenv';
dotenv.config();

const client = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:/tmp/local.db',
  authToken: process.env.TURSO_AUTH_TOKEN,
});

export async function initDB() {
  await client.batch([
    `CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      categoryId TEXT,
      image TEXT,
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

  console.log('Database tables initialized');
}

export default client;
