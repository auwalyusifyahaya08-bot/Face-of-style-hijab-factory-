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
const PORT = process.env.PORT || 10000;

/* =========================================================
   CONFIGURATION
========================================================= */

const PAYSTACK_SECRET_KEY =
  process.env.PAYSTACK_SECRET_KEY || '';

const ADMIN_USERNAME =
  process.env.ADMIN_USERNAME || '';

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || '';

const DATABASE_URL =
  process.env.DATABASE_URL || '';

const WHATSAPP_NUMBER =
  process.env.WHATSAPP_NUMBER || '2349065828886';

const PAYSTACK_CALLBACK_URL =
  process.env.PAYSTACK_CALLBACK_URL || '';

const isProduction =
  process.env.NODE_ENV === 'production';

/* =========================================================
   DATABASE
========================================================= */

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: isProduction
        ? { rejectUnauthorized: false }
        : false
    })
  : null;

/* =========================================================
   EXPRESS
========================================================= */

app.use(
  express.json({
    limit: '8mb',
    verify: (req, res, buf) => {
      req.rawBody = Buffer.from(buf);
    }
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '8mb'
  })
);

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

/* =========================================================
   SESSION CONFIGURATION
========================================================= */

const adminSessions = new Map();
const customerSessions = new Map();

const SESSION_MAX_AGE =
  1000 * 60 * 60 * 24 * 30;

/* =========================================================
   BASIC HELPERS
========================================================= */

function cleanString(value, max = 500) {
  return String(value ?? '')
    .trim()
    .slice(0, max);
}

function positiveInteger(value) {
  const number = Number(value);

  if (
    !Number.isInteger(number) ||
    number < 1
  ) {
    return null;
  }

  return number;
}

function nonNegativeInteger(value) {
  const number = Number(value);

  if (
    !Number.isInteger(number) ||
    number < 0
  ) {
    return null;
  }

  return number;
}

function positivePrice(value) {
  const number = Number(value);

  if (
    !Number.isFinite(number) ||
    number < 0
  ) {
    return null;
  }

  return Math.round(number * 100) / 100;
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    String(email || '').trim()
  );
}

function validPhone(phone) {
  return /^[0-9+\-\s()]{7,25}$/.test(
    String(phone || '').trim()
  );
}

function normalizeCategory(value) {
  const category =
    cleanString(value, 50);

  return category || 'Fashion';
}

function normalizeImage(value) {
  let image =
    cleanString(value, 2500000);

  if (!image) {
    return '';
  }

  image = image.replace(/\\/g, '/');

  if (
    image.startsWith('http://') ||
    image.startsWith('https://') ||
    image.startsWith('data:')
  ) {
    return image;
  }

  image = image.replace(/^\/+/, '');

  if (
    image.startsWith('public/')
  ) {
    image =
      image.slice('public/'.length);
  }

  if (
    image.startsWith('assets/')
  ) {
    return '/' + image;
  }

  if (
    image.startsWith('/assets/')
  ) {
    return image;
  }

  return '/assets/' + image;
}

function createToken() {
  return crypto
    .randomBytes(48)
    .toString('hex');
}

function createOrderReference() {
  return (
    'FS-' +
    Date.now()
      .toString(36)
      .toUpperCase() +
    '-' +
    crypto
      .randomBytes(4)
      .toString('hex')
      .toUpperCase()
  );
}

/* =========================================================
   PASSWORD HELPERS
========================================================= */

function hashPassword(password) {
  const salt =
    crypto.randomBytes(16);

  const derived =
    crypto.scryptSync(
      String(password),
      salt,
      64
    );

  return (
    salt.toString('hex') +
    ':' +
    derived.toString('hex')
  );
}

function verifyPassword(
  password,
  storedHash
) {
  try {
    const parts =
      String(storedHash || '').split(':');

    if (parts.length !== 2) {
      return false;
    }

    const salt =
      Buffer.from(parts[0], 'hex');

    const stored =
      Buffer.from(parts[1], 'hex');

    const derived =
      crypto.scryptSync(
        String(password),
        salt,
        64
      );

    if (
      derived.length !== stored.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      derived,
      stored
    );
  } catch {
    return false;
  }
}

/* =========================================================
   ADMIN SESSION
========================================================= */

function createAdminSession(username) {
  const token = createToken();

  adminSessions.set(token, {
    username,
    createdAt: Date.now()
  });

  return token;
}

function getAdminSession(req) {
  const auth =
    req.headers.authorization || '';

  if (
    !auth.startsWith('Bearer ')
  ) {
    return null;
  }

  const token =
    auth.slice(7).trim();

  if (!token) {
    return null;
  }

  const session =
    adminSessions.get(token);

  if (!session) {
    return null;
  }

  if (
    Date.now() -
      session.createdAt >
    SESSION_MAX_AGE
  ) {
    adminSessions.delete(token);
    return null;
  }

  return {
    token,
    ...session
  };
}

function requireAdmin(
  req,
  res,
  next
) {
  const session =
    getAdminSession(req);

  if (!session) {
    return res.status(401).json({
      ok: false,
      message:
        'Admin authentication required.'
    });
  }

  req.admin = session;
  next();
}

/* =========================================================
   CUSTOMER SESSION
========================================================= */

function createCustomerMemorySession(
  customerId
) {
  const token = createToken();

  customerSessions.set(token, {
    customerId: Number(customerId),
    createdAt: Date.now()
  });

  return token;
}

function getBearerToken(req) {
  const auth =
    req.headers.authorization || '';

  if (
    !auth.startsWith('Bearer ')
  ) {
    return '';
  }

  return auth
    .slice(7)
    .trim();
}

async function createCustomerSession(
  customerId
) {
  const token = createToken();

  if (!pool) {
    return createCustomerMemorySession(
      customerId
    );
  }

  try {
    await pool.query(
      `
      INSERT INTO customer_sessions
      (
        token,
        customer_id,
        expires_at
      )
      VALUES
      (
        $1,
        $2,
        NOW() + INTERVAL '30 days'
      )
      `,
      [
        token,
        customerId
      ]
    );

    return token;
  } catch (error) {
    console.error(
      'Customer session database error:',
      error
    );

    return createCustomerMemorySession(
      customerId
    );
  }
}

async function getCustomerSession(
  req
) {
  const token =
    getBearerToken(req);

  if (!token) {
    return null;
  }

  if (pool) {
    try {
      const result =
        await pool.query(
          `
          SELECT
            cs.token,
            cs.customer_id,
            cs.expires_at,
            c.name,
            c.email,
            c.phone
          FROM customer_sessions cs
          JOIN customers c
            ON c.id = cs.customer_id
          WHERE cs.token = $1
            AND cs.expires_at > NOW()
          LIMIT 1
          `,
          [token]
        );

      if (result.rowCount) {
        return {
          token,
          customerId:
            Number(
              result.rows[0].customer_id
            ),
          name:
            result.rows[0].name,
          email:
            result.rows[0].email,
          phone:
            result.rows[0].phone
        };
      }
    } catch (error) {
      console.error(
        'Customer session lookup error:',
        error
      );
    }
  }

  const memory =
    customerSessions.get(token);

  if (!memory) {
    return null;
  }

  if (
    Date.now() -
      memory.createdAt >
    SESSION_MAX_AGE
  ) {
    customerSessions.delete(token);
    return null;
  }

  return {
    token,
    customerId:
      memory.customerId
  };
}

async function requireCustomer(
  req,
  res,
  next
) {
  const session =
    await getCustomerSession(req);

  if (!session) {
    return res.status(401).json({
      ok: false,
      message:
        'Customer login required.'
    });
  }

  req.customer = session;
  next();
}

/* =========================================================
   DATABASE COLUMN MIGRATION HELPERS
========================================================= */

async function columnExists(
  tableName,
  columnName
) {
  const result =
    await pool.query(
      `
      SELECT 1
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = $1
        AND column_name = $2
      LIMIT 1
      `,
      [
        tableName,
        columnName
      ]
    );

  return Boolean(
    result.rowCount
  );
}

async function ensureColumn(
  tableName,
  columnName,
  definition
) {
  const exists =
    await columnExists(
      tableName,
      columnName
    );

  if (!exists) {
    await pool.query(
      `
      ALTER TABLE ${tableName}
      ADD COLUMN ${columnName}
      ${definition}
      `
    );
  }
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initDatabase() {
  if (!pool) {
    console.warn(
      'DATABASE_URL is not configured.'
    );
    return;
  }

  /* -------------------------------------------------------
     PRODUCTS
  ------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'Fashion',
      description TEXT DEFAULT '',
      price NUMERIC(12,2) NOT NULL DEFAULT 0,
      color TEXT DEFAULT '',
      image TEXT DEFAULT '',
      stock INTEGER NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  /*
     Support older database versions where
     the image column may have been named img.
  */

  const imageExists =
    await columnExists(
      'products',
      'image'
    );

  const oldImgExists =
    await columnExists(
      'products',
      'img'
    );

  if (
    !imageExists &&
    oldImgExists
  ) {
    await pool.query(`
      ALTER TABLE products
      RENAME COLUMN img TO image
    `);
  }

  await ensureColumn(
    'products',
    'category',
    `TEXT NOT NULL DEFAULT 'Fashion'`
  );

  await ensureColumn(
    'products',
    'description',
    `TEXT DEFAULT ''`
  );

  await ensureColumn(
    'products',
    'price',
    `NUMERIC(12,2) NOT NULL DEFAULT 0`
  );

  await ensureColumn(
    'products',
    'color',
    `TEXT DEFAULT ''`
  );

  await ensureColumn(
    'products',
    'image',
    `TEXT DEFAULT ''`
  );

  await ensureColumn(
    'products',
    'stock',
    `INTEGER NOT NULL DEFAULT 0`
  );

  await ensureColumn(
    'products',
    'active',
    `BOOLEAN NOT NULL DEFAULT TRUE`
  );

  await ensureColumn(
    'products',
    'created_at',
    `TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  );

  await ensureColumn(
    'products',
    'updated_at',
    `TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  );

  /* -------------------------------------------------------
     CUSTOMERS
  ------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT DEFAULT '',
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await ensureColumn(
    'customers',
    'phone',
    `TEXT DEFAULT ''`
  );

  await ensureColumn(
    'customers',
    'password_hash',
    `TEXT DEFAULT ''`
  );

  await ensureColumn(
    'customers',
    'created_at',
    `TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  );

  await ensureColumn(
    'customers',
    'updated_at',
    `TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  );

  /* -------------------------------------------------------
     CUSTOMER SESSIONS
  ------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customer_sessions (
      token TEXT PRIMARY KEY,
      customer_id BIGINT NOT NULL
        REFERENCES customers(id)
        ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_customer_sessions_customer
    ON customer_sessions(customer_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_customer_sessions_expires
    ON customer_sessions(expires_at)
  `);

  /* -------------------------------------------------------
     CUSTOMER ADDRESSES
  ------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customer_addresses (
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT NOT NULL
        REFERENCES customers(id)
        ON DELETE CASCADE,
      full_name TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      address TEXT NOT NULL,
      city TEXT DEFAULT '',
      state TEXT DEFAULT '',
      landmark TEXT DEFAULT '',
      is_default BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  /* -------------------------------------------------------
     ORDERS
  ------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,
      reference TEXT UNIQUE NOT NULL,
      customer_name TEXT NOT NULL,
      customer_email TEXT NOT NULL,
      customer_phone TEXT NOT NULL,
      delivery_address TEXT NOT NULL,
      payment_method TEXT NOT NULL DEFAULT 'paystack',
      payment_status TEXT NOT NULL DEFAULT 'PENDING',
      order_status TEXT NOT NULL DEFAULT 'PENDING',
      total NUMERIC(12,2) NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'NGN',
      paystack_reference TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await ensureColumn(
    'orders',
    'customer_id',
    `BIGINT`
  );

  await ensureColumn(
    'orders',
    'paystack_reference',
    `TEXT`
  );

  await ensureColumn(
    'orders',
    'payment_status',
    `TEXT NOT NULL DEFAULT 'PENDING'`
  );

  await ensureColumn(
    'orders',
    'order_status',
    `TEXT NOT NULL DEFAULT 'PENDING'`
  );

  await ensureColumn(
    'orders',
    'updated_at',
    `TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  );

  /* -------------------------------------------------------
     STORE SETTINGS
  ------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS store_settings (
      id INTEGER PRIMARY KEY DEFAULT 1,
      store_name TEXT DEFAULT 'Face of Style Hijab Factory',
      tagline TEXT DEFAULT 'HIJAB FACTORY',
      whatsapp TEXT DEFAULT '2349065828886',
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
      hero_image TEXT DEFAULT '/assets/product-1.jpg',
      primary_color TEXT DEFAULT '#651630',
      secondary_color TEXT DEFAULT '#4d1024',
      gold_color TEXT DEFAULT '#c9a45b',
      background_color TEXT DEFAULT '#fcf8f1',
      text_color TEXT DEFAULT '#251c20',
      low_stock_limit INTEGER DEFAULT 5,
      enable_cart BOOLEAN DEFAULT TRUE,
      enable_whatsapp BOOLEAN DEFAULT TRUE,
      show_stock BOOLEAN DEFAULT TRUE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    INSERT INTO store_settings (id)
    VALUES (1)
    ON CONFLICT (id) DO NOTHING
  `);

  /* -------------------------------------------------------
     ORDER ITEMS
  ------------------------------------------------------- */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS order_items (
      id BIGSERIAL PRIMARY KEY,
      order_id BIGINT NOT NULL
        REFERENCES orders(id)
        ON DELETE CASCADE,
      product_id INTEGER NOT NULL,
      product_name TEXT NOT NULL,
      price NUMERIC(12,2) NOT NULL,
      quantity INTEGER NOT NULL,
      subtotal NUMERIC(12,2) NOT NULL
    )
  `);

  /* -------------------------------------------------------
     INDEXES
  ------------------------------------------------------- */

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_products_active
    ON products(active)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_products_created
    ON products(created_at DESC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_orders_created
    ON orders(created_at DESC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_orders_customer
    ON orders(customer_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_order_items_order
    ON order_items(order_id)
  `);

  /* -------------------------------------------------------
     CLEAN EXPIRED CUSTOMER SESSIONS
  ------------------------------------------------------- */

  try {
    await pool.query(`
      DELETE FROM customer_sessions
      WHERE expires_at <= NOW()
    `);
  } catch {}

  console.log(
    'Database initialized successfully.'
  );
}

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  '/api/health',
  async (req, res) => {
    let database = false;

    if (pool) {
      try {
        await pool.query(
          'SELECT 1'
        );

        database = true;
      } catch (error) {
        console.error(
          'Database health error:',
          error
        );
      }
    }

    res.json({
      ok: true,
      service:
        'Face of Style Hijab Factory',
      database,
      paystackConfigured:
        Boolean(
          PAYSTACK_SECRET_KEY
        ),
      adminConfigured:
        Boolean(
          ADMIN_USERNAME &&
          ADMIN_PASSWORD
        )
    });
  }
);

/* =========================================================
   PUBLIC PRODUCTS
   GET ALL ACTIVE PRODUCTS
========================================================= */

app.get(
  '/api/products',
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        products: [],
        message:
          'Database is not configured.'
      });
    }

    try {
      const result =
        await pool.query(`
          SELECT
            id,
            name,
            category AS cat,
            category,
            description,
            price,
            color,
            image AS img,
            image,
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
            ...product,
            id: Number(product.id),
            price: Number(product.price),
            stock: Number(product.stock),
            img: normalizeImage(
              product.image ||
              product.img
            ),
            image: normalizeImage(
              product.image ||
              product.img
            )
          })
        );

      res.json({
        ok: true,
        products,
        data: products,
        count: products.length
      });
    } catch (error) {
      console.error(
        'Products error:',
        error
      );

      res.status(500).json({
        ok: false,
        products: [],
        message:
          'Unable to load products.'
      });
    }
  }
);

/* =========================================================
   PUBLIC PRODUCT DETAIL
   IMPORTANT FIX:
   /api/products/:id
========================================================= */

app.get(
  '/api/products/:id',
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const id =
      positiveInteger(
        req.params.id
      );

    if (!id) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid product ID.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            name,
            category AS cat,
            category,
            description,
            price,
            color,
            image AS img,
            image,
            stock,
            active,
            created_at,
            updated_at
          FROM products
          WHERE id = $1
            AND active = TRUE
          LIMIT 1
          `,
          [id]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Product not found.'
        });
      }

      const product =
        result.rows[0];

      product.id =
        Number(product.id);

      product.price =
        Number(product.price);

      product.stock =
        Number(product.stock);

      product.img =
        normalizeImage(
          product.image ||
          product.img
        );

      product.image =
        product.img;

      res.json({
        ok: true,
        product
      });
    } catch (error) {
      console.error(
        'Product detail error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to load product.'
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
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const name =
      cleanString(
        req.body?.name,
        150
      );

    const email =
      cleanString(
        req.body?.email,
        200
      ).toLowerCase();

    const phone =
      cleanString(
        req.body?.phone,
        40
      );

    const password =
      String(
        req.body?.password || ''
      );

    if (
      !name ||
      !email ||
      !password
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Name, email and password are required.'
      });
    }

    if (!validEmail(email)) {
      return res.status(400).json({
        ok: false,
        message:
          'Please provide a valid email.'
      });
    }

    if (
      password.length < 6
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Password must be at least 6 characters.'
      });
    }

    if (
      phone &&
      !validPhone(phone)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Please provide a valid phone number.'
      });
    }

    try {
      const existing =
        await pool.query(
          `
          SELECT id
          FROM customers
          WHERE LOWER(email) = LOWER($1)
          LIMIT 1
          `,
          [email]
        );

      if (existing.rowCount) {
        return res.status(409).json({
          ok: false,
          message:
            'An account with this email already exists.'
        });
      }

      const passwordHash =
        hashPassword(password);

      const result =
        await pool.query(
          `
          INSERT INTO customers
          (
            name,
            email,
            phone,
            password_hash
          )
          VALUES
          ($1,$2,$3,$4)
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
        await createCustomerSession(
          customer.id
        );

      res.status(201).json({
        ok: true,
        token,
        customer
      });
    } catch (error) {
      console.error(
        'Customer register error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to create customer account.'
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
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const email =
      cleanString(
        req.body?.email,
        200
      ).toLowerCase();

    const password =
      String(
        req.body?.password || ''
      );

    if (
      !email ||
      !password
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Email and password are required.'
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
            password_hash
          FROM customers
          WHERE LOWER(email) = LOWER($1)
          LIMIT 1
          `,
          [email]
        );

      if (!result.rowCount) {
        return res.status(401).json({
          ok: false,
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
          ok: false,
          message:
            'Invalid email or password.'
        });
      }

      const token =
        await createCustomerSession(
          customer.id
        );

      delete customer.password_hash;

      res.json({
        ok: true,
        token,
        customer
      });
    } catch (error) {
      console.error(
        'Customer login error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to login.'
      });
    }
  }
);

/* =========================================================
   CUSTOMER ME / SESSION CHECK
========================================================= */

app.get(
  '/api/customer/me',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
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
            req.customer.customerId
          ]
        );

      if (!result.rowCount) {
        return res.status(401).json({
          ok: false,
          message:
            'Customer account not found.'
        });
      }

      res.json({
        ok: true,
        customer:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Customer me error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to load customer session.'
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
  async (req, res) => {
    const token =
      req.customer.token;

    customerSessions.delete(token);

    if (pool) {
      try {
        await pool.query(
          `
          DELETE FROM customer_sessions
          WHERE token = $1
          `,
          [token]
        );
      } catch (error) {
        console.error(
          'Customer logout DB error:',
          error
        );
      }
    }

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   CUSTOMER ADDRESSES
   GET
========================================================= */

app.get(
  '/api/customer/addresses',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        addresses: [],
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
            customer_id,
            full_name,
            phone,
            address,
            city,
            state,
            landmark,
            is_default,
            created_at,
            updated_at
          FROM customer_addresses
          WHERE customer_id = $1
          ORDER BY
            is_default DESC,
            created_at DESC
          `,
          [
            req.customer.customerId
          ]
        );

      res.json({
        ok: true,
        addresses:
          result.rows
      });
    } catch (error) {
      console.error(
        'Customer addresses error:',
        error
      );

      res.status(500).json({
        ok: false,
        addresses: [],
        message:
          'Unable to load delivery addresses.'
      });
    }
  }
);

/* =========================================================
   CUSTOMER ADDRESS
   GET DEFAULT
========================================================= */

app.get(
  '/api/customer/address',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM customer_addresses
          WHERE customer_id = $1
          ORDER BY
            is_default DESC,
            created_at DESC
          LIMIT 1
          `,
          [
            req.customer.customerId
          ]
        );

      res.json({
        ok: true,
        address:
          result.rows[0] || null
      });
    } catch (error) {
      console.error(
        'Default address error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to load delivery address.'
      });
    }
  }
);

/* =========================================================
   CUSTOMER ADDRESS
   CREATE
========================================================= */

app.post(
  '/api/customer/addresses',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const address =
      cleanString(
        req.body?.address,
        1000
      );

    const fullName =
      cleanString(
        req.body?.full_name ||
        req.body?.name,
        150
      );

    const phone =
      cleanString(
        req.body?.phone,
        40
      );

    const city =
      cleanString(
        req.body?.city,
        100
      );

    const state =
      cleanString(
        req.body?.state,
        100
      );

    const landmark =
      cleanString(
        req.body?.landmark,
        300
      );

    const isDefault =
      Boolean(
        req.body?.is_default ||
        req.body?.isDefault
      );

    if (!address) {
      return res.status(400).json({
        ok: false,
        message:
          'Delivery address is required.'
      });
    }

    if (
      phone &&
      !validPhone(phone)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Please provide a valid phone number.'
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      if (isDefault) {
        await client.query(
          `
          UPDATE customer_addresses
          SET
            is_default = FALSE,
            updated_at = NOW()
          WHERE customer_id = $1
          `,
          [
            req.customer.customerId
          ]
        );
      }

      const result =
        await client.query(
          `
          INSERT INTO customer_addresses
          (
            customer_id,
            full_name,
            phone,
            address,
            city,
            state,
            landmark,
            is_default
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8)
          RETURNING *
          `,
          [
            req.customer.customerId,
            fullName,
            phone,
            address,
            city,
            state,
            landmark,
            isDefault
          ]
        );

      await client.query(
        'COMMIT'
      );

      res.status(201).json({
        ok: true,
        address:
          result.rows[0]
      });
    } catch (error) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'Create address error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to save delivery address.'
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   CUSTOMER ADDRESS
   UPDATE
========================================================= */

app.put(
  '/api/customer/addresses/:id',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const id =
      positiveInteger(
        req.params.id
      );

    if (!id) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid address ID.'
      });
    }

    const address =
      cleanString(
        req.body?.address,
        1000
      );

    const fullName =
      cleanString(
        req.body?.full_name ||
        req.body?.name,
        150
      );

    const phone =
      cleanString(
        req.body?.phone,
        40
      );

    const city =
      cleanString(
        req.body?.city,
        100
      );

    const state =
      cleanString(
        req.body?.state,
        100
      );

    const landmark =
      cleanString(
        req.body?.landmark,
        300
      );

    const isDefault =
      Boolean(
        req.body?.is_default ||
        req.body?.isDefault
      );

    if (!address) {
      return res.status(400).json({
        ok: false,
        message:
          'Delivery address is required.'
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      if (isDefault) {
        await client.query(
          `
          UPDATE customer_addresses
          SET
            is_default = FALSE,
            updated_at = NOW()
          WHERE customer_id = $1
          `,
          [
            req.customer.customerId
          ]
        );
      }

      const result =
        await client.query(
          `
          UPDATE customer_addresses
          SET
            full_name = $1,
            phone = $2,
            address = $3,
            city = $4,
            state = $5,
            landmark = $6,
            is_default = $7,
            updated_at = NOW()
          WHERE id = $8
            AND customer_id = $9
          RETURNING *
          `,
          [
            fullName,
            phone,
            address,
            city,
            state,
            landmark,
            isDefault,
            id,
            req.customer.customerId
          ]
        );

      if (!result.rowCount) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          ok: false,
          message:
            'Address not found.'
        });
      }

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,
        address:
          result.rows[0]
      });
    } catch (error) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'Update address error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to update delivery address.'
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   CUSTOMER ADDRESS
   DELETE
========================================================= */

app.delete(
  '/api/customer/addresses/:id',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const id =
      positiveInteger(
        req.params.id
      );

    if (!id) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid address ID.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          DELETE FROM customer_addresses
          WHERE id = $1
            AND customer_id = $2
          RETURNING id
          `,
          [
            id,
            req.customer.customerId
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Address not found.'
        });
      }

      res.json({
        ok: true,
        message:
          'Delivery address removed.'
      });
    } catch (error) {
      console.error(
        'Delete address error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to delete address.'
      });
    }
  }
);

/* =========================================================
   CUSTOMER ORDERS
   IMPORTANT FIX:
   MY ORDERS
========================================================= */

app.get(
  '/api/customer/orders',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        orders: [],
        message:
          'Database is not configured.'
      });
    }

    try {
      const ordersResult =
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
          WHERE customer_id = $1
          ORDER BY created_at DESC
          `,
          [
            req.customer.customerId
          ]
        );

      const orders =
        ordersResult.rows;

      if (!orders.length) {
        return res.json({
          ok: true,
          orders: []
        });
      }

      const ids =
        orders.map(
          order => order.id
        );

      const itemsResult =
        await pool.query(
          `
          SELECT
            id,
            order_id,
            product_id,
            product_name,
            price,
            quantity,
            subtotal
          FROM order_items
          WHERE order_id =
            ANY($1::bigint[])
          ORDER BY id ASC
          `,
          [ids]
        );

      const itemsByOrder =
        new Map();

      for (
        const item
        of itemsResult.rows
      ) {
        if (
          !itemsByOrder.has(
            item.order_id
          )
        ) {
          itemsByOrder.set(
            item.order_id,
            []
          );
        }

        itemsByOrder
          .get(item.order_id)
          .push({
            ...item,
            product_id:
              Number(
                item.product_id
              ),
            price:
              Number(item.price),
            quantity:
              Number(item.quantity),
            subtotal:
              Number(item.subtotal)
          });
      }

      const output =
        orders.map(
          order => ({
            ...order,
            id: Number(order.id),
            total: Number(order.total),
            items:
              itemsByOrder.get(
                order.id
              ) || []
          })
        );

      res.json({
        ok: true,
        orders: output
      });
    } catch (error) {
      console.error(
        'Customer orders error:',
        error
      );

      res.status(500).json({
        ok: false,
        orders: [],
        message:
          'Unable to load your orders.'
      });
    }
  }
);

/* =========================================================
   CUSTOMER SINGLE ORDER
========================================================= */

app.get(
  '/api/customer/orders/:id',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const id =
      positiveInteger(
        req.params.id
      );

    if (!id) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid order ID.'
      });
    }

    try {
      const orderResult =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE id = $1
            AND customer_id = $2
          LIMIT 1
          `,
          [
            id,
            req.customer.customerId
          ]
        );

      if (!orderResult.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Order not found.'
        });
      }

      const itemsResult =
        await pool.query(
          `
          SELECT
            id,
            order_id,
            product_id,
            product_name,
            price,
            quantity,
            subtotal
          FROM order_items
          WHERE order_id = $1
          ORDER BY id ASC
          `,
          [id]
        );

      const order =
        orderResult.rows[0];

      order.id =
        Number(order.id);

      order.total =
        Number(order.total);

      order.items =
        itemsResult.rows.map(
          item => ({
            ...item,
            product_id:
              Number(
                item.product_id
              ),
            price:
              Number(item.price),
            quantity:
              Number(item.quantity),
            subtotal:
              Number(item.subtotal)
          })
        );

      res.json({
        ok: true,
        order
      });
    } catch (error) {
      console.error(
        'Customer single order error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to load order.'
      });
    }
  }
);



/* =========================================================
   CUSTOMER DASHBOARD ADDRESS COMPATIBILITY ROUTES
   Supports the Version 2 Customer Dashboard.
========================================================= */

app.get(
  '/api/customer/dashboard/address',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
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
            customer_id,
            full_name,
            phone,
            address,
            city,
            state,
            landmark,
            is_default,
            created_at,
            updated_at
          FROM customer_addresses
          WHERE customer_id = $1
          ORDER BY
            is_default DESC,
            created_at DESC
          LIMIT 1
          `,
          [req.customer.customerId]
        );

      return res.json({
        ok: true,
        address:
          result.rows[0] || null
      });
    } catch (error) {
      console.error(
        'Customer dashboard default address error:',
        error
      );

      return res.status(500).json({
        ok: false,
        message:
          'Unable to load delivery address.'
      });
    }
  }
);

app.post(
  '/api/customer/dashboard/address',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const body =
      req.body || {};

    const address =
      cleanString(
        body.address,
        1000
      );

    const fullName =
      cleanString(
        body.full_name ||
        body.name ||
        body.label,
        150
      );

    const phone =
      cleanString(
        body.phone,
        40
      );

    const city =
      cleanString(
        body.city,
        100
      );

    const state =
      cleanString(
        body.state,
        100
      );

    const landmark =
      cleanString(
        body.landmark,
        300
      );

    const isDefault =
      Boolean(
        body.is_default ||
        body.isDefault
      );

    if (!address) {
      return res.status(400).json({
        ok: false,
        message:
          'Delivery address is required.'
      });
    }

    if (
      phone &&
      !validPhone(phone)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Please provide a valid phone number.'
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      if (isDefault) {
        await client.query(
          `
          UPDATE customer_addresses
          SET
            is_default = FALSE,
            updated_at = NOW()
          WHERE customer_id = $1
          `,
          [req.customer.customerId]
        );
      }

      const result =
        await client.query(
          `
          INSERT INTO customer_addresses
          (
            customer_id,
            full_name,
            phone,
            address,
            city,
            state,
            landmark,
            is_default
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8)
          RETURNING *
          `,
          [
            req.customer.customerId,
            fullName,
            phone,
            address,
            city,
            state,
            landmark,
            isDefault
          ]
        );

      await client.query('COMMIT');

      return res.status(201).json({
        ok: true,
        address:
          result.rows[0]
      });
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {}

      console.error(
        'Customer dashboard address create error:',
        error
      );

      return res.status(500).json({
        ok: false,
        message:
          'Unable to save delivery address.'
      });
    } finally {
      client.release();
    }
  }
);

app.put(
  '/api/customer/dashboard/address/:id',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const id =
      positiveInteger(
        req.params.id
      );

    if (!id) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid address ID.'
      });
    }

    const body =
      req.body || {};

    const address =
      cleanString(
        body.address,
        1000
      );

    const fullName =
      cleanString(
        body.full_name ||
        body.name ||
        body.label,
        150
      );

    const phone =
      cleanString(
        body.phone,
        40
      );

    const city =
      cleanString(
        body.city,
        100
      );

    const state =
      cleanString(
        body.state,
        100
      );

    const landmark =
      cleanString(
        body.landmark,
        300
      );

    const isDefault =
      Boolean(
        body.is_default ||
        body.isDefault
      );

    if (!address) {
      return res.status(400).json({
        ok: false,
        message:
          'Delivery address is required.'
      });
    }

    if (
      phone &&
      !validPhone(phone)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Please provide a valid phone number.'
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      if (isDefault) {
        await client.query(
          `
          UPDATE customer_addresses
          SET
            is_default = FALSE,
            updated_at = NOW()
          WHERE customer_id = $1
          `,
          [req.customer.customerId]
        );
      }

      const result =
        await client.query(
          `
          UPDATE customer_addresses
          SET
            full_name = $1,
            phone = $2,
            address = $3,
            city = $4,
            state = $5,
            landmark = $6,
            is_default = $7,
            updated_at = NOW()
          WHERE id = $8
            AND customer_id = $9
          RETURNING *
          `,
          [
            fullName,
            phone,
            address,
            city,
            state,
            landmark,
            isDefault,
            id,
            req.customer.customerId
          ]
        );

      if (!result.rowCount) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          ok: false,
          message:
            'Address not found.'
        });
      }

      await client.query('COMMIT');

      return res.json({
        ok: true,
        address:
          result.rows[0]
      });
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {}

      console.error(
        'Customer dashboard address update error:',
        error
      );

      return res.status(500).json({
        ok: false,
        message:
          'Unable to update delivery address.'
      });
    } finally {
      client.release();
    }
  }
);

app.delete(
  '/api/customer/dashboard/address/:id',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const id =
      positiveInteger(
        req.params.id
      );

    if (!id) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid address ID.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          DELETE FROM customer_addresses
          WHERE id = $1
            AND customer_id = $2
          RETURNING id
          `,
          [
            id,
            req.customer.customerId
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Address not found.'
        });
      }

      return res.json({
        ok: true,
        message:
          'Delivery address removed.'
      });
    } catch (error) {
      console.error(
        'Customer dashboard address delete error:',
        error
      );

      return res.status(500).json({
        ok: false,
        message:
          'Unable to delete address.'
      });
    }
  }
);

/* =========================================================
   CUSTOMER DASHBOARD
   VERSION 2 COMPATIBILITY ROUTE
   Fixes Customer Dashboard API not found.
========================================================= */

app.get(
  '/api/customer/dashboard',
  requireCustomer,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    try {
      const customerId =
        Number(req.customer.customerId);

      const customerResult =
        await pool.query(
          `
          SELECT
            id,
            name,
            email,
            phone,
            created_at,
            updated_at
          FROM customers
          WHERE id = $1
          LIMIT 1
          `,
          [customerId]
        );

      if (!customerResult.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Customer not found.'
        });
      }

      const customer =
        customerResult.rows[0];

      const ordersResult =
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
          WHERE customer_id = $1
          ORDER BY created_at DESC
          `,
          [customerId]
        );

      const orders =
        ordersResult.rows;

      const orderIds =
        orders.map(
          order => order.id
        );

      let items = [];

      if (orderIds.length) {
        const itemsResult =
          await pool.query(
            `
            SELECT
              id,
              order_id,
              product_id,
              product_name,
              price,
              quantity,
              subtotal
            FROM order_items
            WHERE order_id = ANY($1::bigint[])
            ORDER BY id ASC
            `,
            [orderIds]
          );

        items =
          itemsResult.rows;
      }

      const formattedOrders =
        orders.map(order => ({
          id: Number(order.id),
          reference: order.reference,
          customerName:
            order.customer_name,
          customerEmail:
            order.customer_email,
          customerPhone:
            order.customer_phone,
          deliveryAddress:
            order.delivery_address,
          paymentMethod:
            order.payment_method,
          paymentStatus:
            String(
              order.payment_status || ''
            ).toUpperCase(),
          orderStatus:
            String(
              order.order_status || ''
            ).toUpperCase(),
          total:
            Number(order.total || 0),
          currency:
            order.currency || 'NGN',
          paystackReference:
            order.paystack_reference,
          createdAt:
            order.created_at,
          updatedAt:
            order.updated_at,
          items:
            items
              .filter(
                item =>
                  Number(item.order_id) ===
                  Number(order.id)
              )
              .map(item => ({
                id: item.id,
                productId:
                  Number(item.product_id),
                productName:
                  item.product_name,
                price:
                  Number(item.price || 0),
                quantity:
                  Number(item.quantity || 0),
                subtotal:
                  Number(item.subtotal || 0)
              }))
        }));

      let addresses = [];

      try {
        const addressResult =
          await pool.query(
            `
            SELECT
              id,
              customer_id,
              full_name,
              phone,
              address,
              city,
              state,
              landmark,
              is_default,
              created_at,
              updated_at
            FROM customer_addresses
            WHERE customer_id = $1
            ORDER BY
              is_default DESC,
              created_at DESC
            `,
            [customerId]
          );

        addresses =
          addressResult.rows;
      } catch (addressError) {
        console.error(
          'Customer dashboard address error:',
          addressError
        );
      }

      const totalOrders =
        orders.length;

      const paidOrders =
        orders.filter(
          order =>
            String(
              order.payment_status || ''
            ).toUpperCase() === 'PAID'
        ).length;

      const pendingOrders =
        orders.filter(
          order =>
            String(
              order.payment_status || ''
            ).toUpperCase() === 'PENDING'
        ).length;

      const processingOrders =
        orders.filter(
          order =>
            String(
              order.order_status || ''
            ).toUpperCase() === 'PROCESSING'
        ).length;

      const totalSpent =
        orders
          .filter(
            order =>
              String(
                order.payment_status || ''
              ).toUpperCase() === 'PAID'
          )
          .reduce(
            (sum, order) =>
              sum + Number(order.total || 0),
            0
          );

      const itemsByOrder = new Map();

for (const item of items) {
  const orderId = Number(item.order_id);

  if (!itemsByOrder.has(orderId)) {
    itemsByOrder.set(orderId, []);
  }

  itemsByOrder.get(orderId).push({
    ...item,
    product_id: Number(item.product_id),
    price: Number(item.price),
    quantity: Number(item.quantity),
    subtotal: Number(item.subtotal)
  });
}

      const output =
        orders.map(
          order => {
            const items =
              (itemsByOrder.get(order.id) || [])
                .map(item => ({
                  ...item,
                  qty: Number(item.quantity),
                  quantity: Number(item.quantity)
                }));

            return {
              ...order,
              id: Number(order.id),
              customer_id:
                order.customer_id
                  ? Number(order.customer_id)
                  : null,
              total: Number(order.total),
              status: String(order.payment_status || 'PENDING').toLowerCase(),
              orderStatus: String(order.order_status || 'PENDING').toLowerCase(),
              createdAt: order.created_at,
              updatedAt: order.updated_at,
              customer: {
                name: order.customer_name || '',
                email: order.customer_email || '',
                phone: order.customer_phone || '',
                address: order.delivery_address || ''
              },
              payment: {
                provider: order.payment_method || 'paystack',
                reference: order.paystack_reference || ''
              },
              items
            };
          }
        );

      res.json({
        ok: true,
        orders: output
      });
    } catch (error) {
      console.error(
        'Admin orders error:',
        error
      );

      res.status(500).json({
        ok: false,
        orders: [],
        message:
          'Unable to load orders.'
      });
    }
  }
);

/* =========================================================
   ADMIN SINGLE ORDER
========================================================= */

app.get(
  '/api/admin/orders/:id',
  requireAdmin,
  async (req, res) => {
    if (!pool) return res.status(503).json({ ok:false, message:'Database is not configured.' });

    const id =
      positiveInteger(req.params.id);

    if (!id) return res.status(400).json({ ok:false, message:'Invalid order ID.' });

    try {
      const orderResult =
        await pool.query(
          'SELECT * FROM orders WHERE id = $1 LIMIT 1',
          [id]
        );

      if (!orderResult.rowCount) {
        return res.status(404).json({
          ok:false,
          message:'Order not found.'
        });
      }

      const itemsResult =
        await pool.query(
          `
          SELECT
            id,
            order_id,
            product_id,
            product_name,
            price,
            quantity,
            subtotal
          FROM order_items
          WHERE order_id = $1
          ORDER BY id ASC
          `,
          [id]
        );

      const o =
        orderResult.rows[0];

      const items =
        itemsResult.rows.map(
          i => ({
            ...i,
            product_id:
              Number(i.product_id),
            price:
              Number(i.price),
            quantity:
              Number(i.quantity),
            qty:
              Number(i.quantity),
            subtotal:
              Number(i.subtotal)
          })
        );

      res.json({
        ok:true,
        order:{
          ...o,
          id:Number(o.id),
          total:Number(o.total),
          status:
            String(
              o.payment_status ||
              'PENDING'
            ).toLowerCase(),
          orderStatus:
            String(
              o.order_status ||
              'PENDING'
            ).toLowerCase(),
          createdAt:
            o.created_at,
          customer:{
            name:
              o.customer_name || '',
            email:
              o.customer_email || '',
            phone:
              o.customer_phone || '',
            address:
              o.delivery_address || ''
          },
          payment:{
            provider:
              o.payment_method ||
              'paystack',
            reference:
              o.paystack_reference ||
              ''
          },
          items
        }
      });
    } catch(error) {
      console.error(
        'Admin single order error:',
        error
      );

      res.status(500).json({
        ok:false,
        message:
          'Unable to load order.'
      });
    }
  }
);

/* =========================================================
   UPDATE ORDER STATUS
========================================================= */

app.patch(
  '/api/admin/orders/:id',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const id =
      positiveInteger(
        req.params.id
      );

    const orderStatus =
      cleanString(
        req.body?.order_status ||
        req.body?.status,
        30
      ).toUpperCase();

    const allowed = [
      'NEW',
      'PENDING',
      'PROCESSING',
      'READY',
      'SHIPPED',
      'DELIVERED',
      'CANCELLED'
    ];

    if (!id) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid order ID.'
      });
    }

    if (
      !allowed.includes(
        orderStatus
      )
    ) {
      return res.status(400).json({
        ok: false,
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
          RETURNING *
          `,
          [
            orderStatus,
            id
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Order not found.'
        });
      }

      res.json({
        ok: true,
        order:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Update order status error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to update order.'
      });
    }
  }
);

/* =========================================================
   ADMIN ORDER STATUS COMPATIBILITY ROUTE
   Supports the existing Version 2 Admin UI.
========================================================= */

app.put(
  '/api/admin/orders/:id/status',
  requireAdmin,
  async (req, res) => {
    req.body = {
      ...(req.body || {}),
      status:
        req.body?.status ||
        req.body?.order_status
    };

    const id =
      positiveInteger(
        req.params.id
      );

    const raw =
      cleanString(
        req.body.status,
        30
      ).toUpperCase();

    const map = {
      NEW: 'PENDING',
      PENDING: 'PENDING',
      PROCESSING: 'PROCESSING',
      READY: 'READY',
      SHIPPED: 'SHIPPED',
      DELIVERED: 'DELIVERED',
      CANCELLED: 'CANCELLED'
    };

    if (!id || !map[raw]) {
      return res.status(400).json({
        ok: false,
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
          RETURNING *
          `,
          [
            map[raw],
            id
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Order not found.'
        });
      }

      res.json({
        ok: true,
        order:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Compatibility order status error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to update order.'
      });
    }
  }
);

/* =========================================================
   ADMIN PAYMENT STATUS MANUAL SYNC
========================================================= */

app.patch(
  '/api/admin/orders/:id/payment',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const id =
      positiveInteger(
        req.params.id
      );

    const status =
      cleanString(
        req.body?.payment_status ||
        req.body?.status,
        30
      ).toUpperCase();

    const allowed = [
      'PENDING',
      'PAID',
      'FAILED',
      'REFUNDED'
    ];

    if (!id) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid order ID.'
      });
    }

    if (
      !allowed.includes(status)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid payment status.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          UPDATE orders
          SET
            payment_status = $1,
            order_status =
              CASE
                WHEN $1 = 'PAID'
                  AND order_status = 'PENDING'
                THEN 'PROCESSING'
                ELSE order_status
              END,
            updated_at = NOW()
          WHERE id = $2
          RETURNING *
          `,
          [
            status,
            id
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Order not found.'
        });
      }

      res.json({
        ok: true,
        order:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Admin payment update error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to update payment status.'
      });
    }
  }
);

/* =========================================================
   ADMIN STORE SETTINGS
========================================================= */

app.get(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok:false,
        message:
          'Database is not configured.'
      });
    }

    try {
      const result =
        await pool.query(
          'SELECT * FROM store_settings WHERE id = 1 LIMIT 1'
        );

      const row =
        result.rows[0] || {};

      const settings = {
        storeName:
          row.store_name || '',

        tagline:
          row.tagline || '',

        whatsapp:
          row.whatsapp ||
          WHATSAPP_NUMBER,

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
          Number(
            row.delivery_fee || 0
          ),

        freeDeliveryFrom:
          Number(
            row.free_delivery_from || 0
          ),

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
          row.hero_image ||
          '/assets/product-1.jpg',

        primaryColor:
          row.primary_color ||
          '#651630',

        secondaryColor:
          row.secondary_color ||
          '#4d1024',

        goldColor:
          row.gold_color ||
          '#c9a45b',

        backgroundColor:
          row.background_color ||
          '#fcf8f1',

        textColor:
          row.text_color ||
          '#251c20',

        lowStockLimit:
          Number(
            row.low_stock_limit ??
            5
          ),

        enableCart:
          row.enable_cart !== false,

        enableWhatsapp:
          row.enable_whatsapp !== false,

        showStock:
          row.show_stock !== false
      };

      res.json({
        ok:true,
        settings,
        paystackConfigured:
          Boolean(
            PAYSTACK_SECRET_KEY
          ),
        whatsapp:
          settings.whatsapp
      });
    } catch (error) {
      console.error(
        'Admin settings GET error:',
        error
      );

      res.status(500).json({
        ok:false,
        message:
          'Unable to load settings.'
      });
    }
  }
);

app.put(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok:false,
        message:
          'Database is not configured.'
      });
    }

    const b =
      req.body || {};

    const text =
      (
        v,
        max = 2500000
      ) =>
        String(
          v ?? ''
        )
          .trim()
          .slice(
            0,
            max
          );

    const num =
      v =>
        Number.isFinite(
          Number(v)
        ) &&
        Number(v) >= 0
          ? Number(v)
          : 0;

    try {
      const result =
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
            1,
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            $11,
            $12,
            $13,
            $14,
            $15,
            $16,
            $17,
            $18,
            $19,
            $20,
            $21,
            $22,
            $23,
            $24,
            $25,
            $26,
            $27,
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

          RETURNING *
          `,
          [
            text(
              b.storeName,
              200
            ),

            text(
              b.tagline,
              200
            ),

            text(
              b.whatsapp,
              50
            ),

            text(
              b.phone,
              50
            ),

            text(
              b.email,
              200
            ),

            text(
              b.address,
              1000
            ),

            text(
              b.heroTitle,
              300
            ),

            text(
              b.heroText,
              2000
            ),

            text(
              b.aboutText,
              5000
            ),

            text(
              b.deliveryText,
              5000
            ),

            num(
              b.deliveryFee
            ),

            num(
              b.freeDeliveryFrom
            ),

            text(
              b.bankName,
              200
            ),

            text(
              b.accountName,
              200
            ),

            text(
              b.accountNumber,
              100
            ),

            text(
              b.bankInstructions,
              5000
            ),

            text(
              b.logo
            ),

            text(
              b.heroImage,
              2500000
            ),

            text(
              b.primaryColor,
              20
            ),

            text(
              b.secondaryColor,
              20
            ),

            text(
              b.goldColor,
              20
            ),

            text(
              b.backgroundColor,
              20
            ),

            text(
              b.textColor,
              20
            ),

            Math.max(
              0,
              Math.floor(
                num(
                  b.lowStockLimit
                )
              )
            ),

            b.enableCart !==
              false,

            b.enableWhatsapp !==
              false,

            b.showStock !==
              false
          ]
        );

      res.json({
        ok:true,
        message:
          'Store settings saved successfully.',
        settings:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Admin settings PUT error:',
        error
      );

      res.status(500).json({
        ok:false,
        message:
          'Unable to save settings.'
      });
    }
  }
);

/* =========================================================
   PAYSTACK INITIALIZE
========================================================= */

app.post(
  '/api/paystack/initialize',
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    if (!PAYSTACK_SECRET_KEY) {
      return res.status(503).json({
        ok: false,
        message:
          'Paystack is not configured on the server.'
      });
    }

    const customer =
      req.body?.customer ||
      {};

    const name =
      cleanString(
        customer.name,
        150
      );

    const email =
      cleanString(
        customer.email,
        200
      ).toLowerCase();

    const phone =
      cleanString(
        customer.phone,
        40
      );

    const address =
      cleanString(
        customer.address,
        1000
      );

    const rawItems =
      Array.isArray(
        req.body?.items
      )
        ? req.body.items
        : [];

    if (
      !name ||
      !email ||
      !phone ||
      !address
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Complete customer details are required.'
      });
    }

    if (!validEmail(email)) {
      return res.status(400).json({
        ok: false,
        message:
          'Please provide a valid email address.'
      });
    }

    if (!validPhone(phone)) {
      return res.status(400).json({
        ok: false,
        message:
          'Please provide a valid phone number.'
      });
    }

    if (!rawItems.length) {
      return res.status(400).json({
        ok: false,
        message:
          'Your cart is empty.'
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const customerSession =
        await getCustomerSession(
          req
        );

      let customerId =
        customerSession?.customerId ||
        null;

      const productIds =
        rawItems
          .map(
            item =>
              positiveInteger(
                item.id
              )
          )
          .filter(Boolean);

      if (!productIds.length) {
        throw new Error(
          'Invalid cart items.'
        );
      }

      const uniqueProductIds =
        [
          ...new Set(
            productIds
          )
        ];

      const productsResult =
        await client.query(
          `
          SELECT
            id,
            name,
            price,
            stock,
            active
          FROM products
          WHERE id =
            ANY($1::int[])
          FOR UPDATE
          `,
          [
            uniqueProductIds
          ]
        );

      const productMap =
        new Map(
          productsResult.rows.map(
            product => [
              Number(
                product.id
              ),
              product
            ]
          )
        );

      const orderItems = [];

      let total = 0;

      for (
        const rawItem
        of rawItems
      ) {
        const productId =
          positiveInteger(
            rawItem.id
          );

        const quantity =
          positiveInteger(
            rawItem.qty ||
            rawItem.quantity
          );

        if (
          !productId ||
          !quantity
        ) {
          throw new Error(
            'Invalid cart quantity.'
          );
        }

        if (
          quantity > 99
        ) {
          throw new Error(
            'Maximum quantity per item is 99.'
          );
        }

        const product =
          productMap.get(
            productId
          );

        if (
          !product ||
          !product.active
        ) {
          throw new Error(
            'One of the products is no longer available.'
          );
        }

        if (
          Number(product.stock) <
          quantity
        ) {
          throw new Error(
            `${product.name} does not have enough stock.`
          );
        }

        const price =
          Number(
            product.price
          );

        const subtotal =
          Math.round(
            price *
              quantity *
              100
          ) / 100;

        total +=
          subtotal;

        orderItems.push({
          productId,
          name:
            product.name,
          price,
          quantity,
          subtotal
        });
      }

      total =
        Math.round(
          total * 100
        ) / 100;

      if (
        !Number.isFinite(
          total
        ) ||
        total <= 0
      ) {
        throw new Error(
          'Invalid order total.'
        );
      }

      /*
         If customer is logged in,
         attach order to account.
      */

      if (!customerId) {
        try {
          const customerResult =
            await client.query(
              `
              SELECT id
              FROM customers
              WHERE LOWER(email) =
                LOWER($1)
              LIMIT 1
              `,
              [
                email
              ]
            );

          if (
            customerResult.rowCount
          ) {
            customerId =
              Number(
                customerResult
                  .rows[0]
                  .id
              );
          }
        } catch {}
      }

      const reference =
        createOrderReference();

      const orderResult =
        await client.query(
          `
          INSERT INTO orders
          (
            reference,
            customer_id,
            customer_name,
            customer_email,
            customer_phone,
            delivery_address,
            payment_method,
            payment_status,
            order_status,
            total,
            currency
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            'paystack',
            'PENDING',
            'PENDING',
            $7,
            'NGN'
          )
          RETURNING
            id,
            reference,
            total
          `,
          [
            reference,
            customerId,
            name,
            email,
            phone,
            address,
            total
          ]
        );

      const order =
        orderResult.rows[0];

      for (
        const item
        of orderItems
      ) {
        await client.query(
          `
          INSERT INTO order_items
          (
            order_id,
            product_id,
            product_name,
            price,
            quantity,
            subtotal
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6
          )
          `,
          [
            order.id,
            item.productId,
            item.name,
            item.price,
            item.quantity,
            item.subtotal
          ]
        );
      }

      await client.query(
        'COMMIT'
      );

      const amountInKobo =
        Math.round(
          total * 100
        );

      const paystackPayload = {
        email,
        amount:
          amountInKobo,
        currency:
          'NGN',
        reference,
        metadata: {
          order_id:
            String(
              order.id
            ),
          order_reference:
            reference,
          customer_name:
            name,
          customer_phone:
            phone
        }
      };

      if (
        PAYSTACK_CALLBACK_URL
      ) {
        paystackPayload
          .callback_url =
          PAYSTACK_CALLBACK_URL;
      }

      const response =
        await fetch(
          'https://api.paystack.co/transaction/initialize',
          {
            method:
              'POST',

            headers: {
              Authorization:
                `Bearer ${PAYSTACK_SECRET_KEY}`,

              'Content-Type':
                'application/json'
            },

            body:
              JSON.stringify(
                paystackPayload
              )
          }
        );

      const data =
        await response.json();

      if (
        !response.ok ||
        !data.status ||
        !data.data?.authorization_url
      ) {
        console.error(
          'Paystack initialize error:',
          data
        );

        await pool.query(
          `
          UPDATE orders
          SET
            payment_status = 'FAILED',
            updated_at = NOW()
          WHERE reference = $1
          `,
          [
            reference
          ]
        );

        return res.status(502).json({
          ok: false,
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
        WHERE reference = $2
        `,
        [
          data.data.reference ||
            reference,
          reference
        ]
      );

      res.json({
        ok: true,
        reference,
        authorization_url:
          data.data.authorization_url,
        access_code:
          data.data.access_code ||
          null
      });
    } catch (error) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'Payment initialization error:',
        error
      );

      res.status(400).json({
        ok: false,
        message:
          error.message ||
          'Payment initialization failed.'
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   COMPLETE PAID ORDER
   CENTRAL FUNCTION
========================================================= */

async function completePaidOrder(
  reference,
  transaction
) {
  if (!pool) {
    throw new Error(
      'Database is not configured.'
    );
  }

  const client =
    await pool.connect();

  try {
    await client.query(
      'BEGIN'
    );

    const orderResult =
      await client.query(
        `
        SELECT *
        FROM orders
        WHERE reference = $1
        FOR UPDATE
        `,
        [
          reference
        ]
      );

    if (!orderResult.rowCount) {
      throw new Error(
        'Order not found.'
      );
    }

    const order =
      orderResult.rows[0];

    const expectedAmount =
      Math.round(
        Number(
          order.total
        ) * 100
      );

    const paidAmount =
      Number(
        transaction.amount
      );

    if (
      transaction.status !==
        'success' ||
      transaction.currency !==
        'NGN' ||
      paidAmount !==
        expectedAmount
    ) {
      throw new Error(
        'Payment amount or status does not match the order.'
      );
    }

    /*
       CRITICAL:
       Do not reduce stock twice.
    */

    if (
      order.payment_status !==
      'PAID'
    ) {
      const itemsResult =
        await client.query(
          `
          SELECT *
          FROM order_items
          WHERE order_id = $1
          ORDER BY id ASC
          `,
          [
            order.id
          ]
        );

      for (
        const item
        of itemsResult.rows
      ) {
        const stockResult =
          await client.query(
            `
            UPDATE products
            SET
              stock =
                stock - $1,
              updated_at = NOW()
            WHERE id = $2
              AND active = TRUE
              AND stock >= $1
            RETURNING id
            `,
            [
              item.quantity,
              item.product_id
            ]
          );

        if (
          !stockResult.rowCount
        ) {
          throw new Error(
            `Insufficient stock for ${item.product_name}.`
          );
        }
      }
    }

    await client.query(
      `
      UPDATE orders
      SET
        payment_status = 'PAID',
        order_status =
          CASE
            WHEN order_status = 'PENDING'
            THEN 'PROCESSING'
            ELSE order_status
          END,
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

    await client.query(
      'COMMIT'
    );

    return {
      id:
        Number(
          order.id
        ),

      reference:
        order.reference,

      total:
        Number(
          order.total
        ),

      customer_name:
        order.customer_name
    };
  } catch (error) {
    try {
      await client.query(
        'ROLLBACK'
      );
    } catch {}

    throw error;
  } finally {
    client.release();
  }
}

/* =========================================================
   PAYSTACK VERIFY
========================================================= */

app.get(
  '/api/paystack/verify/:reference',
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    if (!PAYSTACK_SECRET_KEY) {
      return res.status(503).json({
        ok: false,
        message:
          'Paystack is not configured on the server.'
      });
    }

    const reference =
      cleanString(
        req.params.reference,
        200
      );

    if (!reference) {
      return res.status(400).json({
        ok: false,
        message:
          'Payment reference is required.'
      });
    }

    try {
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
        !response.ok ||
        !data.status ||
        !data.data
      ) {
        return res.status(502).json({
          ok: false,
          paid: false,
          message:
            data.message ||
            'Unable to verify payment.'
        });
      }

      const transaction =
        data.data;

      if (
        transaction.status !==
        'success'
      ) {
        await pool.query(
          `
          UPDATE orders
          SET
            payment_status = 'FAILED',
            updated_at = NOW()
          WHERE reference = $1
            AND payment_status <> 'PAID'
          `,
          [
            reference
          ]
        );

        return res.status(400).json({
          ok: false,
          paid: false,
          message:
            'Payment was not successful.'
        });
      }

      const completed =
        await completePaidOrder(
          reference,
          transaction
        );

      res.json({
        ok: true,
        paid: true,
        reference,
        order_reference:
          completed.reference,
        amount:
          completed.total,
        customer_name:
          completed.customer_name
      });
    } catch (error) {
      console.error(
        'Paystack verify error:',
        error
      );

      res.status(500).json({
        ok: false,
        paid: false,
        message:
          error.message ||
          'Payment verification error.'
      });
    }
  }
);

/* =========================================================
   PAYSTACK CALLBACK
========================================================= */

app.get(
  '/api/paystack/callback',
  async (req, res) => {
    const reference =
      cleanString(
        req.query?.reference,
        200
      );

    if (!reference) {
      return res.redirect(
        '/payment-failed'
      );
    }

    return res.redirect(
      `/payment-success?reference=${encodeURIComponent(reference)}`
    );
  }
);

/* =========================================================
   PAYSTACK WEBHOOK
========================================================= */

app.post(
  '/api/paystack/webhook',
  async (req, res) => {
    if (
      !PAYSTACK_SECRET_KEY ||
      !pool
    ) {
      return res.sendStatus(200);
    }

    const signature =
      String(
        req.headers[
          'x-paystack-signature'
        ] || ''
      );

    if (
      !signature ||
      !req.rawBody
    ) {
      return res.sendStatus(401);
    }

    const hash =
      crypto
        .createHmac(
          'sha512',
          PAYSTACK_SECRET_KEY
        )
        .update(req.rawBody)
        .digest('hex');

    try {
      const expected =
        Buffer.from(
          hash,
          'utf8'
        );

      const received =
        Buffer.from(
          signature,
          'utf8'
        );

      if (
        expected.length !==
          received.length ||
        !crypto.timingSafeEqual(
          expected,
          received
        )
      ) {
        return res.sendStatus(401);
      }
    } catch {
      return res.sendStatus(401);
    }

    try {
      const event =
        req.body || {};

      if (
        event.event !==
        'charge.success'
      ) {
        return res.sendStatus(200);
      }

      const transaction =
        event.data || {};

      const reference =
        cleanString(
          transaction.reference,
          200
        );

      if (!reference) {
        return res.sendStatus(200);
      }

      await completePaidOrder(
        reference,
        transaction
      );

      return res.sendStatus(200);
    } catch (error) {
      console.error(
        'Paystack webhook error:',
        error
      );

      /*
         Paystack webhook should still
         receive 200 so it does not
         repeatedly retry a malformed
         or already processed event.
      */

      return res.sendStatus(200);
    }
  }
);

/* =========================================================
   APP CONFIG
========================================================= */

app.get(
  '/api/config',
  (req, res) => {
    res.json({
      ok: true,

      whatsapp:
        WHATSAPP_NUMBER,

      paystackConfigured:
        Boolean(
          PAYSTACK_SECRET_KEY
        ),

      customerAuth:
        true,

      customerAddresses:
        true,

      customerOrders:
        true
    });
  }
);

/* =========================================================
   FRONTEND ROUTES
========================================================= */

app.get(
  '/',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'index.html'
      )
    );
  }
);

app.get(
  '/admin',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'admin.html'
      )
    );
  }
);

app.get(
  '/payment-success',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'payment-success.html'
      )
    );
  }
);

app.get(
  '/payment-failed',
  (req, res) => {
    const file =
      path.join(
        __dirname,
        'public',
        'payment-failed.html'
      );

    res.sendFile(
      file,
      error => {
        if (error) {
          res.redirect('/');
        }
      }
    );
  }
);

/* =========================================================
   API 404
========================================================= */

app.use(
  '/api',
  (req, res) => {
    res.status(404).json({
      ok: false,
      message:
        'API endpoint not found.',
      path:
        req.originalUrl
    });
  }
);

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      'Server error:',
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    res.status(500).json({
      ok: false,
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
      '0.0.0.0',
      () => {
        console.log(
          `Face of Style Hijab Factory running on port ${PORT}`
        );

        console.log(
          `Paystack configured: ${Boolean(
            PAYSTACK_SECRET_KEY
          )}`
        );

        console.log(
          `Admin configured: ${Boolean(
            ADMIN_USERNAME &&
            ADMIN_PASSWORD
          )}`
        );

        console.log(
          `Database configured: ${Boolean(
            pool
          )}`
        );

        console.log(
          'Customer authentication: ENABLED'
        );

        console.log(
          'Customer orders: ENABLED'
        );

        console.log(
          'Customer addresses: ENABLED'
        );

        console.log(
          'Public product detail: ENABLED'
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
