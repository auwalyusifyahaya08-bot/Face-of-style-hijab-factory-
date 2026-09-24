import 'dotenv/config';
import express from 'express';
import pg from 'pg';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const PORT = Number(process.env.PORT || 10000);

const PAYSTACK_SECRET_KEY =
  String(process.env.PAYSTACK_SECRET_KEY || '').trim();

const ADMIN_USERNAME =
  String(process.env.ADMIN_USERNAME || 'admin').trim();

const ADMIN_PASSWORD =
  String(process.env.ADMIN_PASSWORD || 'admin123').trim();

const DATABASE_URL =
  String(process.env.DATABASE_URL || '').trim();

const WHATSAPP_NUMBER =
  String(process.env.WHATSAPP_NUMBER || '').trim();

const PAYSTACK_CALLBACK_URL =
  String(process.env.PAYSTACK_CALLBACK_URL || '').trim();

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl:
        process.env.NODE_ENV === 'production'
          ? { rejectUnauthorized: false }
          : false
    })
  : null;


/* =========================================================
   EXPRESS
========================================================= */

app.use(
  express.json({
    limit: '15mb'
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '15mb'
  })
);

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);


/* =========================================================
   SESSIONS
========================================================= */

const adminSessions = new Map();
const customerSessions = new Map();


function createToken() {
  return crypto.randomBytes(32).toString('hex');
}


function createAdminSession() {
  const token = createToken();

  adminSessions.set(token, {
    createdAt: Date.now()
  });

  return token;
}


function createCustomerSession(customer) {
  const token = createToken();

  customerSessions.set(token, {
    customerId: customer.id,
    email: customer.email,
    createdAt: Date.now()
  });

  return token;
}


function getBearerToken(req) {
  const header =
    String(
      req.headers.authorization || ''
    ).trim();

  if (!header.toLowerCase().startsWith('bearer ')) {
    return '';
  }

  return header.slice(7).trim();
}


function requireAdmin(req, res, next) {
  const token = getBearerToken(req);

  if (!token || !adminSessions.has(token)) {
    return res.status(401).json({
      message: 'Unauthorized'
    });
  }

  req.adminToken = token;

  next();
}


function requireCustomer(req, res, next) {
  const token = getBearerToken(req);

  const session =
    token
      ? customerSessions.get(token)
      : null;

  if (!session) {
    return res.status(401).json({
      message: 'Unauthorized'
    });
  }

  req.customerSession = session;

  next();
}


/* =========================================================
   HELPERS
========================================================= */

function cleanString(value, max = 10000) {
  return String(value ?? '')
    .trim()
    .slice(0, max);
}


function positiveInteger(value, fallback = 0) {
  const number = Number(value);

  if (!Number.isInteger(number) || number < 0) {
    return fallback;
  }

  return number;
}


function safePrice(value) {
  const number = Number(value);

  if (!Number.isFinite(number) || number < 0) {
    return 0;
  }

  return Math.round(number * 100) / 100;
}


function validEmail(value) {
  const email =
    String(value || '')
      .trim()
      .toLowerCase();

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}


function validPhone(value) {
  const phone =
    String(value || '')
      .replace(/[^\d+]/g, '');

  return phone.length >= 7;
}


function createOrderReference() {
  return (
    'FS-' +
    Date.now().toString(36).toUpperCase() +
    '-' +
    crypto
      .randomBytes(3)
      .toString('hex')
      .toUpperCase()
  );
}


function normalizeImage(value) {
  let image =
    String(value || '').trim();

  if (!image) {
    return '/product-1.jpg';
  }

  if (
    /^https?:\/\//i.test(image) ||
    image.startsWith('data:image/')
  ) {
    return image;
  }

  image =
    image.replace(
      /^\.?\/?assets\//i,
      '/'
    );

  if (!image.startsWith('/')) {
    image = '/' + image;
  }

  return image;
}


/* =========================================================
   PASSWORD HASHING
========================================================= */

function hashPassword(password) {
  const salt =
    crypto.randomBytes(16).toString('hex');

  const hash =
    crypto
      .scryptSync(
        String(password),
        salt,
        64
      )
      .toString('hex');

  return `${salt}:${hash}`;
}


function verifyPassword(password, stored) {
  try {
    const [salt, hash] =
      String(stored || '').split(':');

    if (!salt || !hash) {
      return false;
    }

    const calculated =
      crypto
        .scryptSync(
          String(password),
          salt,
          64
        )
        .toString('hex');

    return crypto.timingSafeEqual(
      Buffer.from(hash, 'hex'),
      Buffer.from(calculated, 'hex')
    );
  } catch {
    return false;
  }
}


/* =========================================================
   DATABASE
========================================================= */

async function initDatabase() {
  if (!pool) {
    console.warn(
      'DATABASE_URL is not configured.'
    );

    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT DEFAULT 'Custom',
      description TEXT DEFAULT '',
      price NUMERIC(12,2) NOT NULL DEFAULT 0,
      color TEXT DEFAULT '',
      img TEXT DEFAULT '',
      stock INTEGER NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT DEFAULT '',
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customer_addresses (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER REFERENCES customers(id)
        ON DELETE CASCADE,
      address TEXT DEFAULT '',
      city TEXT DEFAULT '',
      state TEXT DEFAULT '',
      country TEXT DEFAULT 'Nigeria',
      is_default BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      reference TEXT UNIQUE NOT NULL,
      customer_name TEXT NOT NULL,
      customer_email TEXT DEFAULT '',
      customer_phone TEXT DEFAULT '',
      delivery_address TEXT DEFAULT '',
      payment_method TEXT DEFAULT 'paystack',
      payment_status TEXT DEFAULT 'pending',
      order_status TEXT DEFAULT 'new',
      total NUMERIC(12,2) NOT NULL DEFAULT 0,
      currency TEXT DEFAULT 'NGN',
      paystack_reference TEXT DEFAULT '',
      customer_id INTEGER REFERENCES customers(id)
        ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS order_items (
      id SERIAL PRIMARY KEY,
      order_id INTEGER REFERENCES orders(id)
        ON DELETE CASCADE,
      product_id INTEGER REFERENCES products(id)
        ON DELETE SET NULL,
      name TEXT NOT NULL,
      price NUMERIC(12,2) NOT NULL DEFAULT 0,
      qty INTEGER NOT NULL DEFAULT 1,
      color TEXT DEFAULT '',
      image TEXT DEFAULT ''
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS store_credit_transactions (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER REFERENCES customers(id)
        ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      type TEXT DEFAULT 'credit',
      reference TEXT DEFAULT '',
      note TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS refunds (
      id SERIAL PRIMARY KEY,
      order_id INTEGER REFERENCES orders(id)
        ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      reason TEXT DEFAULT '',
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS store_settings (
      id INTEGER PRIMARY KEY DEFAULT 1,
      store_name TEXT DEFAULT 'Face of Style Hijab Factory',
      tagline TEXT DEFAULT 'HIJAB FACTORY',
      whatsapp TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      email TEXT DEFAULT '',
      address TEXT DEFAULT '',
      hero_title TEXT DEFAULT 'Modesty, Elegance & Style.',
      hero_text TEXT DEFAULT 'Discover carefully crafted hijabs, abayas, gowns and modest outfits.',
      about_text TEXT DEFAULT '',
      delivery_text TEXT DEFAULT '',
      delivery_fee NUMERIC(12,2) DEFAULT 0,
      free_delivery_from NUMERIC(12,2) DEFAULT 0,
      bank_name TEXT DEFAULT '',
      account_name TEXT DEFAULT '',
      account_number TEXT DEFAULT '',
      bank_instructions TEXT DEFAULT '',
      logo TEXT DEFAULT '',
      hero_image TEXT DEFAULT '/product-1.jpg',
      primary_color TEXT DEFAULT '#651630',
      secondary_color TEXT DEFAULT '#4d1024',
      gold_color TEXT DEFAULT '#c9a45b',
      background_color TEXT DEFAULT '#fcf8f1',
      text_color TEXT DEFAULT '#251c20',
      low_stock_limit INTEGER DEFAULT 5,
      enable_cart BOOLEAN DEFAULT TRUE,
      enable_whatsapp BOOLEAN DEFAULT TRUE,
      show_stock BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const settings =
    await pool.query(`
      SELECT id
      FROM store_settings
      WHERE id = 1
    `);

  if (!settings.rows.length) {
    await pool.query(`
      INSERT INTO store_settings (
        id,
        store_name,
        tagline,
        whatsapp,
        hero_title,
        hero_text,
        primary_color,
        secondary_color,
        gold_color,
        background_color,
        text_color
      )
      VALUES (
        1,
        'Face of Style Hijab Factory',
        'HIJAB FACTORY',
        $1,
        'Modesty, Elegance & Style.',
        'Discover carefully crafted hijabs, abayas, gowns and modest outfits.',
        '#651630',
        '#4d1024',
        '#c9a45b',
        '#fcf8f1',
        '#251c20'
      )
    `, [
      WHATSAPP_NUMBER
    ]);
  }

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_products_active
    ON products(active)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_products_category
    ON products(category)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_orders_reference
    ON orders(reference)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_orders_payment_status
    ON orders(payment_status)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_orders_order_status
    ON orders(order_status)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_customers_email
    ON customers(email)
  `);

  console.log(
    'Database initialized successfully.'
  );
}


/* =========================================================
   SETTINGS HELPERS
========================================================= */

async function getSettings() {
  if (!pool) {
    return {
      storeName:
        'Face of Style Hijab Factory',
      tagline:
        'HIJAB FACTORY',
      whatsapp:
        WHATSAPP_NUMBER,
      phone: '',
      email: '',
      address: '',
      heroTitle:
        'Modesty, Elegance & Style.',
      heroText:
        'Discover carefully crafted hijabs, abayas, gowns and modest outfits.',
      aboutText: '',
      deliveryText: '',
      deliveryFee: 0,
      freeDeliveryFrom: 0,
      bankName: '',
      accountName: '',
      accountNumber: '',
      bankInstructions: '',
      logo: '',
      heroImage: '/product-1.jpg',
      primaryColor: '#651630',
      secondaryColor: '#4d1024',
      goldColor: '#c9a45b',
      backgroundColor: '#fcf8f1',
      textColor: '#251c20',
      lowStockLimit: 5,
      enableCart: true,
      enableWhatsapp: true,
      showStock: true
    };
  }

  const result =
    await pool.query(`
      SELECT *
      FROM store_settings
      WHERE id = 1
      LIMIT 1
    `);

  const row =
    result.rows[0] || {};

  return {
    storeName:
      row.store_name || '',
    tagline:
      row.tagline || '',
    whatsapp:
      row.whatsapp || WHATSAPP_NUMBER || '',
    phone:
      row.phone || '',
    email:
      row.email || '',
    address:
      row.address || '',
    heroTitle:
      row.hero_title || '',
    heroText:
      row.hero_text || '',
    aboutText:
      row.about_text || '',
    deliveryText:
      row.delivery_text || '',
    deliveryFee:
      Number(row.delivery_fee || 0),
    freeDeliveryFrom:
      Number(row.free_delivery_from || 0),
    bankName:
      row.bank_name || '',
    accountName:
      row.account_name || '',
    accountNumber:
      row.account_number || '',
    bankInstructions:
      row.bank_instructions || '',
    logo:
      row.logo || '',
    heroImage:
      normalizeImage(
        row.hero_image || '/product-1.jpg'
      ),
    primaryColor:
      row.primary_color || '#651630',
    secondaryColor:
      row.secondary_color || '#4d1024',
    goldColor:
      row.gold_color || '#c9a45b',
    backgroundColor:
      row.background_color || '#fcf8f1',
    textColor:
      row.text_color || '#251c20',
    lowStockLimit:
      Number(row.low_stock_limit ?? 5),
    enableCart:
      row.enable_cart !== false,
    enableWhatsapp:
      row.enable_whatsapp !== false,
    showStock:
      row.show_stock !== false
  };
}


/* =========================================================
   CONFIG
========================================================= */

app.get(
  '/api/config',
  async (req, res) => {
    try {
      const settings =
        await getSettings();

      return res.json({
        ...settings,
        paystackConfigured:
          Boolean(PAYSTACK_SECRET_KEY),
        whatsapp:
          settings.whatsapp ||
          WHATSAPP_NUMBER ||
          ''
      });
    } catch (error) {
      console.error(
        'Config error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to load store configuration.'
      });
    }
  }
);


/* =========================================================
   PUBLIC PRODUCTS
========================================================= */

app.get(
  '/api/products',
  async (req, res) => {
    if (!pool) {
      return res.json({
        products: []
      });
    }

    try {
      const result =
        await pool.query(`
          SELECT
            id,
            name,
            category,
            description,
            price,
            color,
            img,
            stock,
            active,
            created_at,
            updated_at
          FROM products
          WHERE active = TRUE
          ORDER BY created_at DESC, id DESC
        `);

      const products =
        result.rows.map(
          product => ({
            id:
              Number(product.id),
            name:
              product.name || '',
            cat:
              product.category || 'Custom',
            category:
              product.category || 'Custom',
            desc:
              product.description || '',
            description:
              product.description || '',
            price:
              Number(product.price || 0),
            color:
              product.color || '',
            image:
              normalizeImage(product.img),
            img:
              normalizeImage(product.img),
            stock:
              Number(product.stock || 0),
            active:
              product.active !== false,
            createdAt:
              product.created_at,
            updatedAt:
              product.updated_at
          })
        );

      return res.json({
        products
      });
    } catch (error) {
      console.error(
        'Public products error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to load products.',
        products: []
      });
    }
  }
);


/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
  '/api/admin/login',
  async (req, res) => {
    const username =
      cleanString(
        req.body?.username,
        200
      );

    const password =
      String(
        req.body?.password || ''
      );

    if (
      username !==
      ADMIN_USERNAME
    ) {
      return res.status(401).json({
        message:
          'Invalid username or password.'
      });
    }

    let valid = false;

    if (
      ADMIN_PASSWORD.includes(':') &&
      ADMIN_PASSWORD.split(':').length === 2
    ) {
      valid =
        verifyPassword(
          password,
          ADMIN_PASSWORD
        );
    } else {
      valid =
        password === ADMIN_PASSWORD;
    }

    if (!valid) {
      return res.status(401).json({
        message:
          'Invalid username or password.'
      });
    }

    const token =
      createAdminSession();

    return res.json({
      token
    });
  }
);


/* =========================================================
   ADMIN LOGOUT
========================================================= */

app.post(
  '/api/admin/logout',
  requireAdmin,
  (req, res) => {
    adminSessions.delete(
      req.adminToken
    );

    return res.json({
      ok: true
    });
  }
);


/* =========================================================
   ADMIN ME
========================================================= */

app.get(
  '/api/admin/me',
  requireAdmin,
  (req, res) => {
    return res.json({
      ok: true,
      username:
        ADMIN_USERNAME
    });
  }
);


/* =========================================================
   ADMIN DASHBOARD
========================================================= */

app.get(
  '/api/admin/dashboard',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.json({
        stats: {
          orders: 0,
          paid: 0,
          pending: 0,
          processing: 0,
          revenue: 0
        }
      });
    }

    try {
      const result =
        await pool.query(`
          SELECT
            COUNT(*)::INTEGER AS orders,

            COUNT(*) FILTER (
              WHERE payment_status = 'paid'
            )::INTEGER AS paid,

            COUNT(*) FILTER (
              WHERE payment_status = 'pending'
            )::INTEGER AS pending,

            COUNT(*) FILTER (
              WHERE order_status = 'processing'
            )::INTEGER AS processing,

            COALESCE(
              SUM(total) FILTER (
                WHERE payment_status = 'paid'
              ),
              0
            ) AS revenue

          FROM orders
        `);

      const row =
        result.rows[0] || {};

      return res.json({
        stats: {
          orders:
            Number(row.orders || 0),
          paid:
            Number(row.paid || 0),
          pending:
            Number(row.pending || 0),
          processing:
            Number(row.processing || 0),
          revenue:
            Number(row.revenue || 0)
        }
      });
    } catch (error) {
      console.error(
        'Dashboard error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to load dashboard.'
      });
    }
  }
);


/* =========================================================
   ADMIN PRODUCTS
========================================================= */

app.get(
  '/api/admin/products',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.json({
        products: []
      });
    }

    try {
      const result =
        await pool.query(`
          SELECT
            id,
            name,
            category,
            description,
            price,
            color,
            img,
            stock,
            active,
            created_at,
            updated_at
          FROM products
          ORDER BY created_at DESC, id DESC
        `);

      const products =
        result.rows.map(
          product => ({
            id:
              Number(product.id),
            name:
              product.name || '',
            cat:
              product.category || 'Custom',
            category:
              product.category || 'Custom',
            desc:
              product.description || '',
            description:
              product.description || '',
            price:
              Number(product.price || 0),
            color:
              product.color || '',
            image:
              normalizeImage(product.img),
            img:
              normalizeImage(product.img),
            stock:
              Number(product.stock || 0),
            active:
              product.active !== false,
            createdAt:
              product.created_at,
            updatedAt:
              product.updated_at
          })
        );

      return res.json({
        products
      });
    } catch (error) {
      console.error(
        'Admin products error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to load products.',
        products: []
      });
    }
  }
);


/* =========================================================
   CREATE PRODUCT
========================================================= */

app.post(
  '/api/admin/products',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        message:
          'Database is not configured.'
      });
    }

    try {
      const body =
        req.body || {};

      const name =
        cleanString(
          body.name,
          300
        );

      const category =
        cleanString(
          body.cat ||
          body.category ||
          'Custom',
          100
        );

      const description =
        cleanString(
          body.desc ||
          body.description ||
          '',
          5000
        );

      const price =
        safePrice(
          body.price
        );

      const color =
        cleanString(
          body.color,
          100
        );

      const stock =
        positiveInteger(
          body.stock,
          0
        );

      const active =
        body.active !== false;

      const image =
        cleanString(
          body.image ||
          body.img ||
          '',
          12000000
        );

      if (
        !name ||
        !Number.isFinite(price)
      ) {
        return res.status(400).json({
          message:
            'Product name and valid price are required.'
        });
      }

      const result =
        await pool.query(
          `
            INSERT INTO products (
              name,
              category,
              description,
              price,
              color,
              img,
              stock,
              active,
              updated_at
            )
            VALUES (
              $1,$2,$3,$4,$5,$6,$7,$8,NOW()
            )
            RETURNING *
          `,
          [
            name,
            category,
            description,
            price,
            color,
            image,
            stock,
            active
          ]
        );

      return res.status(201).json({
        message:
          'Product created successfully.',
        product:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Create product error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to create product.'
      });
    }
  }
);


/* =========================================================
   UPDATE PRODUCT
========================================================= */

app.put(
  '/api/admin/products/:id',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        message:
          'Database is not configured.'
      });
    }

    const id =
      Number(req.params.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        message:
          'Invalid product ID.'
      });
    }

    try {
      const existing =
        await pool.query(
          `
            SELECT *
            FROM products
            WHERE id = $1
            LIMIT 1
          `,
          [id]
        );

      if (!existing.rows.length) {
        return res.status(404).json({
          message:
            'Product not found.'
        });
      }

      const old =
        existing.rows[0];

      const body =
        req.body || {};

      const name =
        cleanString(
          body.name ??
          old.name,
          300
        );

      const category =
        cleanString(
          body.cat ??
          body.category ??
          old.category ??
          'Custom',
          100
        );

      const description =
        cleanString(
          body.desc ??
          body.description ??
          old.description ??
          '',
          5000
        );

      const price =
        safePrice(
          body.price ??
          old.price
        );

      const color =
        cleanString(
          body.color ??
          old.color ??
          '',
          100
        );

      const stock =
        positiveInteger(
          body.stock ??
          old.stock ??
          0,
          0
        );

      const active =
        typeof body.active === 'boolean'
          ? body.active
          : old.active !== false;

      const image =
        cleanString(
          body.image ??
          body.img ??
          old.img ??
          '',
          12000000
        );

      if (!name) {
        return res.status(400).json({
          message:
            'Product name is required.'
        });
      }

      const result =
        await pool.query(
          `
            UPDATE products
            SET
              name = $1,
              category = $2,
              description = $3,
              price = $4,
              color = $5,
              img = $6,
              stock = $7,
              active = $8,
              updated_at = NOW()
            WHERE id = $9
            RETURNING *
          `,
          [
            name,
            category,
            description,
            price,
            color,
            image,
            stock,
            active,
            id
          ]
        );

      return res.json({
        message:
          'Product updated successfully.',
        product:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Update product error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to update product.'
      });
    }
  }
);


/* =========================================================
   DELETE PRODUCT
========================================================= */

app.delete(
  '/api/admin/products/:id',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        message:
          'Database is not configured.'
      });
    }

    const id =
      Number(req.params.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        message:
          'Invalid product ID.'
      });
    }

    try {
      const result =
        await pool.query(
          `
            DELETE FROM products
            WHERE id = $1
            RETURNING id
          `,
          [id]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          message:
            'Product not found.'
        });
      }

      return res.json({
        ok: true,
        message:
          'Product deleted successfully.'
      });
    } catch (error) {
      console.error(
        'Delete product error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to delete product.'
      });
    }
  }
);


/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
  '/api/admin/orders',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.json({
        orders: []
      });
    }

    try {
      const ordersResult =
        await pool.query(`
          SELECT
            id,
            reference,
            customer_name,
            customer_email,
            customer_phone,
            delivery_address,
            payment_method,
            payment_status,
            order_status,
            total,
            currency,
            paystack_reference,
            customer_id,
            created_at,
            updated_at
          FROM orders
          ORDER BY created_at DESC, id DESC
        `);

      const orders =
        ordersResult.rows;

      if (!orders.length) {
        return res.json({
          orders: []
        });
      }

      const ids =
        orders.map(
          order =>
            Number(order.id)
        );

      const itemsResult =
        await pool.query(
          `
            SELECT
              id,
              order_id,
              product_id,
              name,
              price,
              qty,
              color,
              image
            FROM order_items
            WHERE order_id = ANY($1::int[])
            ORDER BY id ASC
          `,
          [ids]
        );

      const itemsByOrder =
        new Map();

      for (
        const item of itemsResult.rows
      ) {
        const orderId =
          Number(item.order_id);

        if (
          !itemsByOrder.has(
            orderId
          )
        ) {
          itemsByOrder.set(
            orderId,
            []
          );
        }

        itemsByOrder
          .get(orderId)
          .push({
            id:
              Number(item.id),
            productId:
              item.product_id
                ? Number(item.product_id)
                : null,
            name:
              item.name || 'Product',
            price:
              Number(item.price || 0),
            qty:
              Number(item.qty || 0),
            color:
              item.color || '',
            image:
              normalizeImage(
                item.image
              )
          });
      }

      const mapped =
        orders.map(
          order => ({
            id:
              Number(order.id),

            reference:
              order.reference,

            customer: {
              name:
                order.customer_name || '',
              email:
                order.customer_email || '',
              phone:
                order.customer_phone || ''
            },

            deliveryAddress:
              order.delivery_address || '',

            payment: {
              method:
                order.payment_method || '',
              provider:
                order.payment_method || '',
              reference:
                order.paystack_reference || ''
            },

            status:
              order.payment_status || 'pending',

            paymentStatus:
              order.payment_status || 'pending',

            orderStatus:
              order.order_status || 'new',

            total:
              Number(order.total || 0),

            currency:
              order.currency || 'NGN',

            items:
              itemsByOrder.get(
                Number(order.id)
              ) || [],

            createdAt:
              order.created_at,

            updatedAt:
              order.updated_at
          })
        );

      return res.json({
        orders: mapped
      });
    } catch (error) {
      console.error(
        'Admin orders error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to load orders.',
        orders: []
      });
    }
  }
);


/* =========================================================
   ADMIN ORDER STATUS
========================================================= */

app.put(
  '/api/admin/orders/:id/status',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        message:
          'Database is not configured.'
      });
    }

    const id =
      Number(req.params.id);

    const status =
      cleanString(
        req.body?.status,
        50
      ).toLowerCase();

    const allowed = [
      'new',
      'processing',
      'ready',
      'shipped',
      'delivered',
      'cancelled'
    ];

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        message:
          'Invalid order ID.'
      });
    }

    if (
      !allowed.includes(status)
    ) {
      return res.status(400).json({
        message:
          'Invalid order status.'
      });
    }

    try {
      const result =
        await pool.query(
          `
            UPDATE orders
            SET
              order_status = $1,
              updated_at = NOW()
            WHERE id = $2
            RETURNING
              id,
              reference,
              order_status,
              payment_status,
              total
          `,
          [
            status,
            id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          message:
            'Order not found.'
        });
      }

      return res.json({
        ok: true,
        message:
          'Order status updated successfully.',
        order:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Order status error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to update order status.'
      });
    }
  }
);


/* =========================================================
   ADMIN SETTINGS
========================================================= */

app.get(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {
    try {
      const settings =
        await getSettings();

      return res.json({
        settings,
        whatsapp:
          settings.whatsapp ||
          WHATSAPP_NUMBER ||
          '',
        paystackConfigured:
          Boolean(PAYSTACK_SECRET_KEY)
      });
    } catch (error) {
      console.error(
        'Admin settings GET error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to load settings.'
      });
    }
  }
);


/* =========================================================
   SAVE ADMIN SETTINGS
========================================================= */

app.put(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        message:
          'Database is not configured.'
      });
    }

    try {
      const body =
        req.body || {};

      const storeName =
        cleanString(
          body.storeName,
          300
        );

      const tagline =
        cleanString(
          body.tagline,
          300
        );

      const whatsapp =
        cleanString(
          body.whatsapp,
          100
        );

      const phone =
        cleanString(
          body.phone,
          100
        );

      const email =
        cleanString(
          body.email,
          300
        );

      const address =
        cleanString(
          body.address,
          1000
        );

      const heroTitle =
        cleanString(
          body.heroTitle,
          500
        );

      const heroText =
        cleanString(
          body.heroText,
          5000
        );

      const aboutText =
        cleanString(
          body.aboutText,
          10000
        );

      const deliveryText =
        cleanString(
          body.deliveryText,
          5000
        );

      const deliveryFee =
        safePrice(
          body.deliveryFee
        );

      const freeDeliveryFrom =
        safePrice(
          body.freeDeliveryFrom
        );

      const bankName =
        cleanString(
          body.bankName,
          300
        );

      const accountName =
        cleanString(
          body.accountName,
          300
        );

      const accountNumber =
        cleanString(
          body.accountNumber,
          100
        );

      const bankInstructions =
        cleanString(
          body.bankInstructions,
          5000
        );

      const logo =
        cleanString(
          body.logo,
          12000000
        );

      const heroImage =
        cleanString(
          body.heroImage,
          2000
        );

      const primaryColor =
        /^#[0-9A-Fa-f]{6}$/.test(
          String(
            body.primaryColor || ''
          )
        )
          ? body.primaryColor
          : '#651630';

      const secondaryColor =
        /^#[0-9A-Fa-f]{6}$/.test(
          String(
            body.secondaryColor || ''
          )
        )
          ? body.secondaryColor
          : '#4d1024';

      const goldColor =
        /^#[0-9A-Fa-f]{6}$/.test(
          String(
            body.goldColor || ''
          )
        )
          ? body.goldColor
          : '#c9a45b';

      const backgroundColor =
        /^#[0-9A-Fa-f]{6}$/.test(
          String(
            body.backgroundColor || ''
          )
        )
          ? body.backgroundColor
          : '#fcf8f1';

      const textColor =
        /^#[0-9A-Fa-f]{6}$/.test(
          String(
            body.textColor || ''
          )
        )
          ? body.textColor
          : '#251c20';

      const lowStockLimit =
        positiveInteger(
          body.lowStockLimit,
          5
        );

      const enableCart =
        body.enableCart !== false;

      const enableWhatsapp =
        body.enableWhatsapp !== false;

      const showStock =
        body.showStock !== false;

      await pool.query(
        `
          INSERT INTO store_settings (
            id,
            store_name,
            tagline,
            whatsapp,
            phone,
            email,
            address,
            hero_title,
            hero_text,
            about_text,
            delivery_text,
            delivery_fee,
            free_delivery_from,
            bank_name,
            account_name,
            account_number,
            bank_instructions,
            logo,
            hero_image,
            primary_color,
            secondary_color,
            gold_color,
            background_color,
            text_color,
            low_stock_limit,
            enable_cart,
            enable_whatsapp,
            show_stock,
            updated_at
          )
          VALUES (
            1,$1,$2,$3,$4,$5,$6,$7,$8,$9,
            $10,$11,$12,$13,$14,$15,$16,$17,$18,
            $19,$20,$21,$22,$23,$24,$25,$26,$27,
            NOW()
          )
          ON CONFLICT (id)
          DO UPDATE SET
            store_name =
              EXCLUDED.store_name,
            tagline =
              EXCLUDED.tagline,
            whatsapp =
              EXCLUDED.whatsapp,
            phone =
              EXCLUDED.phone,
            email =
              EXCLUDED.email,
            address =
              EXCLUDED.address,
            hero_title =
              EXCLUDED.hero_title,
            hero_text =
              EXCLUDED.hero_text,
            about_text =
              EXCLUDED.about_text,
            delivery_text =
              EXCLUDED.delivery_text,
            delivery_fee =
              EXCLUDED.delivery_fee,
            free_delivery_from =
              EXCLUDED.free_delivery_from,
            bank_name =
              EXCLUDED.bank_name,
            account_name =
              EXCLUDED.account_name,
            account_number =
              EXCLUDED.account_number,
            bank_instructions =
              EXCLUDED.bank_instructions,
            logo =
              EXCLUDED.logo,
            hero_image =
              EXCLUDED.hero_image,
            primary_color =
              EXCLUDED.primary_color,
            secondary_color =
              EXCLUDED.secondary_color,
            gold_color =
              EXCLUDED.gold_color,
            background_color =
              EXCLUDED.background_color,
            text_color =
              EXCLUDED.text_color,
            low_stock_limit =
              EXCLUDED.low_stock_limit,
            enable_cart =
              EXCLUDED.enable_cart,
            enable_whatsapp =
              EXCLUDED.enable_whatsapp,
            show_stock =
              EXCLUDED.show_stock,
            updated_at =
              NOW()
        `,
        [
          storeName,
          tagline,
          whatsapp,
          phone,
          email,
          address,
          heroTitle,
          heroText,
          aboutText,
          deliveryText,
          deliveryFee,
          freeDeliveryFrom,
          bankName,
          accountName,
          accountNumber,
          bankInstructions,
          logo,
          heroImage,
          primaryColor,
          secondaryColor,
          goldColor,
          backgroundColor,
          textColor,
          lowStockLimit,
          enableCart,
          enableWhatsapp,
          showStock
        ]
      );

      const settings =
        await getSettings();

      return res.json({
        ok: true,
        message:
          'Store settings saved successfully.',
        settings
      });
    } catch (error) {
      console.error(
        'Admin settings PUT error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to save settings.'
      });
    }
  }
);


/* =========================================================
   CUSTOMER REGISTER
========================================================= */

app.post(
  '/api/customer/register',
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        message:
          'Database is not configured.'
      });
    }

    try {
      const name =
        cleanString(
          req.body?.name,
          200
        );

      const email =
        cleanString(
          req.body?.email,
          300
        ).toLowerCase();

      const phone =
        cleanString(
          req.body?.phone,
          100
        );

      const password =
        String(
          req.body?.password || ''
        );

      if (!name) {
        return res.status(400).json({
          message:
            'Name is required.'
        });
      }

      if (!validEmail(email)) {
        return res.status(400).json({
          message:
            'Please enter a valid email.'
        });
      }

      if (!validPhone(phone)) {
        return res.status(400).json({
          message:
            'Please enter a valid phone number.'
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          message:
            'Password must be at least 6 characters.'
        });
      }

      const exists =
        await pool.query(
          `
            SELECT id
            FROM customers
            WHERE email = $1
            LIMIT 1
          `,
          [email]
        );

      if (exists.rows.length) {
        return res.status(409).json({
          message:
            'An account with this email already exists.'
        });
      }

      const passwordHash =
        hashPassword(
          password
        );

      const result =
        await pool.query(
          `
            INSERT INTO customers (
              name,
              email,
              phone,
              password_hash,
              updated_at
            )
            VALUES (
              $1,$2,$3,$4,NOW()
            )
            RETURNING
              id,
              name,
              email,
              phone
          `,
          [
            name,
            email,
            phone,
            passwordHash
          ]
        );

      const customer =
        result.rows[0];

      const token =
        createCustomerSession(
          customer
        );

      return res.status(201).json({
        token,
        customer
      });
    } catch (error) {
      console.error(
        'Customer register error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to create account.'
      });
    }
  }
);


/* =========================================================
   CUSTOMER LOGIN
========================================================= */

app.post(
  '/api/customer/login',
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        message:
          'Database is not configured.'
      });
    }

    try {
      const email =
        cleanString(
          req.body?.email,
          300
        ).toLowerCase();

      const password =
        String(
          req.body?.password || ''
        );

      if (
        !validEmail(email) ||
        !password
      ) {
        return res.status(401).json({
          message:
            'Invalid email or password.'
        });
      }

      const result =
        await pool.query(
          `
            SELECT
              id,
              name,
              email,
              phone,
              password_hash
            FROM customers
            WHERE email = $1
            LIMIT 1
          `,
          [email]
        );

      if (!result.rows.length) {
        return res.status(401).json({
          message:
            'Invalid email or password.'
        });
      }

      const customer =
        result.rows[0];

      if (
        !verifyPassword(
          password,
          customer.password_hash
        )
      ) {
        return res.status(401).json({
          message:
            'Invalid email or password.'
        });
      }

      delete customer.password_hash;

      const token =
        createCustomerSession(
          customer
        );

      return res.json({
        token,
        customer
      });
    } catch (error) {
      console.error(
        'Customer login error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to login.'
      });
    }
  }
);


/* =========================================================
   CUSTOMER LOGOUT
========================================================= */

app.post(
  '/api/customer/logout',
  requireCustomer,
  (req, res) => {
    const token =
      getBearerToken(req);

    customerSessions.delete(
      token
    );

    return res.json({
      ok: true
    });
  }
);


/* =========================================================
   CUSTOMER PROFILE
========================================================= */

app.get(
  '/api/customer/me',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        message:
          'Database is not configured.'
      });
    }

    try {
      const result =
        await pool.query(
          `
            SELECT
              id,
              name,
              email,
              phone,
              created_at
            FROM customers
            WHERE id = $1
            LIMIT 1
          `,
          [
            req.customerSession.customerId
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          message:
            'Customer not found.'
        });
      }

      return res.json({
        customer:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Customer profile error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to load profile.'
      });
    }
  }
);


/* =========================================================
   CREATE ORDER
========================================================= */

app.post(
  '/api/orders',
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        message:
          'Database is not configured.'
      });
    }

    const client =
      await pool.connect();

    try {
      const body =
        req.body || {};

      const customer =
        body.customer || {};

      const items =
        Array.isArray(body.items)
          ? body.items
          : [];

      const customerName =
        cleanString(
          customer.name ||
          body.customerName,
          200
        );

      const customerEmail =
        cleanString(
          customer.email ||
          body.customerEmail ||
          '',
          300
        ).toLowerCase();

      const customerPhone =
        cleanString(
          customer.phone ||
          body.customerPhone ||
          '',
          100
        );

      const deliveryAddress =
        cleanString(
          body.deliveryAddress ||
          body.address ||
          '',
          2000
        );

      const paymentMethod =
        cleanString(
          body.paymentMethod ||
          'paystack',
          50
        ).toLowerCase();

      if (!customerName) {
        return res.status(400).json({
          message:
            'Customer name is required.'
        });
      }

      if (
        customerEmail &&
        !validEmail(customerEmail)
      ) {
        return res.status(400).json({
          message:
            'Invalid customer email.'
        });
      }

      if (
        customerPhone &&
        !validPhone(customerPhone)
      ) {
        return res.status(400).json({
          message:
            'Invalid customer phone.'
        });
      }

      if (!items.length) {
        return res.status(400).json({
          message:
            'Your cart is empty.'
        });
      }

      await client.query(
        'BEGIN'
      );

      const productIds =
        items
          .map(
            item =>
              Number(
                item.productId ??
                item.id
              )
          )
          .filter(
            id =>
              Number.isInteger(id) &&
              id > 0
          );

      if (!productIds.length) {
        throw new Error(
          'No valid products were supplied.'
        );
      }

      const productsResult =
        await client.query(
          `
            SELECT
              id,
              name,
              price,
              color,
              img,
              stock,
              active
            FROM products
            WHERE id = ANY($1::int[])
            FOR UPDATE
          `,
          [productIds]
        );

      const products =
        new Map(
          productsResult.rows.map(
            product => [
              Number(product.id),
              product
            ]
          )
        );

      const orderItems = [];
      let total = 0;

      for (
        const item of items
      ) {
        const productId =
          Number(
            item.productId ??
            item.id
          );

        const product =
          products.get(
            productId
          );

        if (!product) {
          throw new Error(
            'One of the selected products no longer exists.'
          );
        }

        if (
          product.active === false
        ) {
          throw new Error(
            `${product.name} is no longer available.`
          );
        }

        const qty =
          positiveInteger(
            item.qty ??
            item.quantity ??
            1,
            1
          );

        if (qty <= 0) {
          throw new Error(
            'Invalid product quantity.'
          );
        }

        if (
          Number(product.stock || 0) <
          qty
        ) {
          throw new Error(
            `${product.name} is out of stock or has insufficient stock.`
          );
        }

        const price =
          safePrice(
            product.price
          );

        total +=
          price * qty;

        orderItems.push({
          productId,
          name:
            product.name,
          price,
          qty,
          color:
            product.color || '',
          image:
            normalizeImage(
              product.img
            )
        });
      }

      total =
        Math.round(
          total * 100
        ) / 100;

      const reference =
        createOrderReference();

      const orderResult =
        await client.query(
          `
            INSERT INTO orders (
              reference,
              customer_name,
              customer_email,
              customer_phone,
              delivery_address,
              payment_method,
              payment_status,
              order_status,
              total,
              currency,
              customer_id,
              updated_at
            )
            VALUES (
              $1,$2,$3,$4,$5,$6,
              'pending',
              'new',
              $7,
              'NGN',
              $8,
              NOW()
            )
            RETURNING *
          `,
          [
            reference,
            customerName,
            customerEmail,
            customerPhone,
            deliveryAddress,
            paymentMethod,
            total,
            req.customerSession?.customerId ||
              null
          ]
        );

      const order =
        orderResult.rows[0];

      for (
        const item of orderItems
      ) {
        await client.query(
          `
            INSERT INTO order_items (
              order_id,
              product_id,
              name,
              price,
              qty,
              color,
              image
            )
            VALUES (
              $1,$2,$3,$4,$5,$6,$7
            )
          `,
          [
            order.id,
            item.productId,
            item.name,
            item.price,
            item.qty,
            item.color,
            item.image
          ]
        );

        await client.query(
          `
            UPDATE products
            SET
              stock = stock - $1,
              updated_at = NOW()
            WHERE id = $2
          `,
          [
            item.qty,
            item.productId
          ]
        );
      }

      await client.query(
        'COMMIT'
      );

      return res.status(201).json({
        ok: true,
        reference,
        orderId:
          Number(order.id),
        total,
        currency: 'NGN'
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Create order error:',
        error
      );

      return res.status(400).json({
        message:
          error?.message ||
          'Unable to create order.'
      });
    } finally {
      client.release();
    }
  }
);


/* =========================================================
   PAYSTACK INITIALIZE
========================================================= */

app.post(
  '/api/paystack/initialize',
  async (req, res) => {
    if (!PAYSTACK_SECRET_KEY) {
      return res.status(503).json({
        message:
          'Paystack is not configured.'
      });
    }

    const reference =
      cleanString(
        req.body?.reference,
        200
      );

    if (!reference) {
      return res.status(400).json({
        message:
          'Order reference is required.'
      });
    }

    try {
      const result =
        await pool.query(
          `
            SELECT
              id,
              reference,
              customer_name,
              customer_email,
              total,
              payment_status
            FROM orders
            WHERE reference = $1
            LIMIT 1
          `,
          [reference]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          message:
            'Order not found.'
        });
      }

      const order =
        result.rows[0];

      if (
        order.payment_status ===
        'paid'
      ) {
        return res.json({
          ok: true,
          alreadyPaid: true,
          reference:
            order.reference
        });
      }

      const amount =
        Math.round(
          Number(order.total || 0) *
          100
        );

      const callback =
        PAYSTACK_CALLBACK_URL ||
        `${req.protocol}://${req.get('host')}/payment/callback`;

      const response =
        await fetch(
          'https://api.paystack.co/transaction/initialize',
          {
            method: 'POST',
            headers: {
              Authorization:
                `Bearer ${PAYSTACK_SECRET_KEY}`,
              'Content-Type':
                'application/json'
            },
            body:
              JSON.stringify({
                email:
                  order.customer_email ||
                  'customer@example.com',
                amount,
                reference:
                  order.reference,
                callback_url:
                  callback,
                metadata: {
                  orderId:
                    Number(order.id),
                  orderReference:
                    order.reference
                }
              })
          }
        );

      const data =
        await response.json();

      if (
        !response.ok ||
        !data.status
      ) {
        console.error(
          'Paystack initialize:',
          data
        );

        return res.status(400).json({
          message:
            data.message ||
            'Unable to initialize Paystack payment.'
        });
      }

      await pool.query(
        `
          UPDATE orders
          SET
            paystack_reference = $1,
            updated_at = NOW()
          WHERE id = $2
        `,
        [
          data.data.reference,
          order.id
        ]
      );

      return res.json({
        ok: true,
        authorization_url:
          data.data.authorization_url,
        access_code:
          data.data.access_code,
        reference:
          data.data.reference
      });
    } catch (error) {
      console.error(
        'Paystack initialize error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to initialize payment.'
      });
    }
  }
);


/* =========================================================
   PAYSTACK VERIFY
========================================================= */

app.get(
  '/api/paystack/verify/:reference',
  async (req, res) => {
    if (!PAYSTACK_SECRET_KEY) {
      return res.status(503).json({
        message:
          'Paystack is not configured.'
      });
    }

    const reference =
      cleanString(
        req.params.reference,
        200
      );

    if (!reference) {
      return res.status(400).json({
        message:
          'Payment reference is required.'
      });
    }

    try {
      const response =
        await fetch(
          `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
          {
            method: 'GET',
            headers: {
              Authorization:
                `Bearer ${PAYSTACK_SECRET_KEY}`
            }
          }
        );

      const data =
        await response.json();

      if (
        !response.ok ||
        !data.status
      ) {
        return res.status(400).json({
          message:
            data.message ||
            'Unable to verify payment.'
        });
      }

      const transaction =
        data.data || {};

      const paid =
        transaction.status ===
        'success';

      const orderResult =
        await pool.query(
          `
            SELECT
              id,
              reference,
              total,
              payment_status
            FROM orders
            WHERE
              reference = $1
              OR paystack_reference = $1
            LIMIT 1
          `,
          [reference]
        );

      if (!orderResult.rows.length) {
        return res.status(404).json({
          message:
            'Order not found.'
        });
      }

      const order =
        orderResult.rows[0];

      if (paid) {
        const paidAmount =
          Number(
            transaction.amount || 0
          ) / 100;

        const expectedAmount =
          Number(
            order.total || 0
          );

        if (
          Math.abs(
            paidAmount -
            expectedAmount
          ) > 0.01
        ) {
          return res.status(400).json({
            message:
              'Payment amount does not match the order.'
          });
        }

        await pool.query(
          `
            UPDATE orders
            SET
              payment_status = 'paid',
              paystack_reference = $1,
              updated_at = NOW()
            WHERE id = $2
          `,
          [
            transaction.reference ||
              reference,
            order.id
          ]
        );
      } else {
        await pool.query(
          `
            UPDATE orders
            SET
              payment_status = $1,
              paystack_reference = $2,
              updated_at = NOW()
            WHERE id = $3
          `,
          [
            transaction.status ===
            'failed'
              ? 'failed'
              : 'pending',
            transaction.reference ||
              reference,
            order.id
          ]
        );
      }

      return res.json({
        ok: true,
        paid,
        status:
          transaction.status,
        reference:
          transaction.reference ||
          reference,
        amount:
          Number(
            transaction.amount || 0
          ) / 100
      });
    } catch (error) {
      console.error(
        'Paystack verify error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to verify payment.'
      });
    }
  }
);


/* =========================================================
   PAYSTACK CALLBACK
========================================================= */

app.get(
  '/payment/callback',
  async (req, res) => {
    const reference =
      cleanString(
        req.query.reference,
        200
      );

    if (!reference) {
      return res.redirect(
        '/'
      );
    }

    try {
      if (PAYSTACK_SECRET_KEY) {
        const response =
          await fetch(
            `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
            {
              headers: {
                Authorization:
                  `Bearer ${PAYSTACK_SECRET_KEY}`
              }
            }
          );

        const data =
          await response.json();

        if (
          response.ok &&
          data.status &&
          data.data?.status ===
            'success'
        ) {
          const orderResult =
            await pool.query(
              `
                SELECT
                  id,
                  total
                FROM orders
                WHERE
                  reference = $1
                  OR paystack_reference = $1
                LIMIT 1
              `,
              [reference]
            );

          if (
            orderResult.rows.length
          ) {
            const order =
              orderResult.rows[0];

            const paidAmount =
              Number(
                data.data.amount || 0
              ) / 100;

            const expectedAmount =
              Number(
                order.total || 0
              );

            if (
              Math.abs(
                paidAmount -
                expectedAmount
              ) <= 0.01
            ) {
              await pool.query(
                `
                  UPDATE orders
                  SET
                    payment_status = 'paid',
                    paystack_reference = $1,
                    updated_at = NOW()
                  WHERE id = $2
                `,
                [
                  data.data.reference ||
                    reference,
                  order.id
                ]
              );
            }
          }
        }
      }
    } catch (error) {
      console.error(
        'Payment callback error:',
        error
      );
    }

    return res.redirect(
      `/?payment=complete&reference=${encodeURIComponent(reference)}`
    );
  }
);


/* =========================================================
   ORDER LOOKUP
========================================================= */

app.get(
  '/api/orders/:reference',
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        message:
          'Database is not configured.'
      });
    }

    const reference =
      cleanString(
        req.params.reference,
        200
      );

    try {
      const orderResult =
        await pool.query(
          `
            SELECT
              id,
              reference,
              customer_name,
              customer_email,
              customer_phone,
              delivery_address,
              payment_method,
              payment_status,
              order_status,
              total,
              currency,
              paystack_reference,
              created_at,
              updated_at
            FROM orders
            WHERE reference = $1
            LIMIT 1
          `,
          [reference]
        );

      if (!orderResult.rows.length) {
        return res.status(404).json({
          message:
            'Order not found.'
        });
      }

      const order =
        orderResult.rows[0];

      const itemsResult =
        await pool.query(
          `
            SELECT
              product_id,
              name,
              price,
              qty,
              color,
              image
            FROM order_items
            WHERE order_id = $1
            ORDER BY id ASC
          `,
          [order.id]
        );

      return res.json({
        order: {
          id:
            Number(order.id),
          reference:
            order.reference,
          customer: {
            name:
              order.customer_name,
            email:
              order.customer_email,
            phone:
              order.customer_phone
          },
          deliveryAddress:
            order.delivery_address,
          payment: {
            method:
              order.payment_method,
            reference:
              order.paystack_reference
          },
          paymentStatus:
            order.payment_status,
          orderStatus:
            order.order_status,
          total:
            Number(order.total || 0),
          currency:
            order.currency || 'NGN',
          items:
            itemsResult.rows.map(
              item => ({
                productId:
                  item.product_id
                    ? Number(
                        item.product_id
                      )
                    : null,
                name:
                  item.name,
                price:
                  Number(
                    item.price || 0
                  ),
                qty:
                  Number(
                    item.qty || 0
                  ),
                color:
                  item.color || '',
                image:
                  normalizeImage(
                    item.image
                  )
              })
            ),
          createdAt:
            order.created_at,
          updatedAt:
            order.updated_at
        }
      });
    } catch (error) {
      console.error(
        'Order lookup error:',
        error
      );

      return res.status(500).json({
        message:
          'Unable to load order.'
      });
    }
  }
);


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  '/api/health',
  async (req, res) => {
    let database =
      false;

    if (pool) {
      try {
        await pool.query(
          'SELECT 1'
        );

        database = true;
      } catch {
        database = false;
      }
    }

    return res.json({
      ok: true,
      database,
      paystackConfigured:
        Boolean(
          PAYSTACK_SECRET_KEY
        )
    });
  }
);


/* =========================================================
   SPA FALLBACK
========================================================= */

app.get(
  '*',
  (req, res, next) => {
    if (
      req.path.startsWith('/api/')
    ) {
      return next();
    }

    if (
      req.path.startsWith('/payment/')
    ) {
      return next();
    }

    return res.sendFile(
      path.join(
        __dirname,
        'public',
        'index.html'
      )
    );
  }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      'Unhandled server error:',
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    return res.status(500).json({
      message:
        'Internal server error.'
    });
  }
);


/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await initDatabase();

    app.listen(
      PORT,
      () => {
        console.log(
          `Face of Style server running on port ${PORT}`
        );

        console.log(
          `Paystack configured: ${Boolean(
            PAYSTACK_SECRET_KEY
          )}`
        );

        console.log(
          `Database configured: ${Boolean(
            DATABASE_URL
          )}`
        );
      }
    );
  } catch (error) {
    console.error(
      'Failed to start server:',
      error
    );

    process.exit(1);
  }
}


startServer();
