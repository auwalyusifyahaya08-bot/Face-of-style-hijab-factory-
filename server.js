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

/* =========================================================
   FACE OF STYLE HIJAB FACTORY
   VERSION 2 MASTER SERVER
========================================================= */

/* =========================================================
   CONFIGURATION
========================================================= */

const PAYSTACK_SECRET_KEY =
  process.env.PAYSTACK_SECRET_KEY || '';

const ADMIN_USERNAME =
  process.env.ADMIN_USERNAME ||
  process.env.ADMIN_USER ||
  '';

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || '';

const DATABASE_URL =
  process.env.DATABASE_URL || '';

const WHATSAPP_NUMBER =
  process.env.WHATSAPP_NUMBER ||
  '2349065828886';

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

/*
  Version 2 uses public/ as the main frontend folder.
*/
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

const SESSION_MAX_AGE =
  1000 * 60 * 60 * 24 * 30;

/* =========================================================
   HELPERS
========================================================= */

function cleanString(value, max = 500) {
  return String(value ?? '')
    .trim()
    .slice(0, max);
}

function positiveInteger(value) {
  const n = Number(value);

  if (
    !Number.isInteger(n) ||
    n < 1
  ) {
    return null;
  }

  return n;
}

function nonNegativeInteger(value) {
  const n = Number(value);

  if (
    !Number.isInteger(n) ||
    n < 0
  ) {
    return null;
  }

  return n;
}

function positivePrice(value) {
  const n = Number(value);

  if (
    !Number.isFinite(n) ||
    n < 0
  ) {
    return null;
  }

  return Math.round(n * 100) / 100;
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
  return (
    cleanString(value, 50) ||
    'Fashion'
  );
}

function normalizeImage(value) {
  let image =
    cleanString(value, 2500000);

  if (!image) return '';

  image = image.replace(/\\/g, '/');

  if (
    image.startsWith('http://') ||
    image.startsWith('https://') ||
    image.startsWith('data:')
  ) {
    return image;
  }

  image = image.replace(/^\/+/, '');

  if (image.startsWith('public/')) {
    image =
      image.slice('public/'.length);
  }

  if (
    image.startsWith('assets/')
  ) {
    return '/' + image;
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
   PASSWORD
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
      String(storedHash || '')
        .split(':');

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
      derived.length !==
      stored.length
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

  if (!auth.startsWith('Bearer ')) {
    return null;
  }

  const token =
    auth.slice(7).trim();

  if (!token) return null;

  const session =
    adminSessions.get(token);

  if (!session) return null;

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

function getBearerToken(req) {
  const auth =
    req.headers.authorization || '';

  if (!auth.startsWith('Bearer ')) {
    return '';
  }

  return auth.slice(7).trim();
}

async function createCustomerSession(
  customerId
) {
  const token = createToken();

  if (!pool) {
    customerSessions.set(token, {
      customerId: Number(customerId),
      createdAt: Date.now()
    });

    return token;
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
      'Customer session error:',
      error
    );

    customerSessions.set(token, {
      customerId: Number(customerId),
      createdAt: Date.now()
    });

    return token;
  }
}

async function getCustomerSession(req) {
  const token =
    getBearerToken(req);

  if (!token) return null;

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
        const row =
          result.rows[0];

        return {
          token,
          customerId:
            Number(row.customer_id),
          name: row.name,
          email: row.email,
          phone: row.phone
        };
      }
    } catch (error) {
      console.error(
        'Customer session lookup:',
        error
      );
    }
  }

  const memory =
    customerSessions.get(token);

  if (!memory) return null;

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
   DATABASE INITIALIZATION
========================================================= */

async function initDatabase() {
  if (!pool) {
    console.warn(
      'DATABASE_URL is not configured.'
    );
    return;
  }

  /* PRODUCTS */

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

  /* CUSTOMERS */

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

  /* CUSTOMER SESSIONS */

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

  /* CUSTOMER ADDRESSES */

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

  /* ORDERS */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,
      reference TEXT UNIQUE NOT NULL,
      customer_id BIGINT,
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

  /* ORDER ITEMS */

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

  /* STORE SETTINGS */

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
      hero_text TEXT DEFAULT '',
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

  /* OLD DATABASE COMPATIBILITY */

  const columns = [
    [
      'products',
      'description',
      `TEXT DEFAULT ''`
    ],
    [
      'products',
      'color',
      `TEXT DEFAULT ''`
    ],
    [
      'products',
      'image',
      `TEXT DEFAULT ''`
    ],
    [
      'products',
      'stock',
      `INTEGER NOT NULL DEFAULT 0`
    ],
    [
      'products',
      'active',
      `BOOLEAN NOT NULL DEFAULT TRUE`
    ],
    [
      'orders',
      'customer_id',
      `BIGINT`
    ],
    [
      'orders',
      'paystack_reference',
      `TEXT`
    ],
    [
      'orders',
      'payment_status',
      `TEXT NOT NULL DEFAULT 'PENDING'`
    ],
    [
      'orders',
      'order_status',
      `TEXT NOT NULL DEFAULT 'PENDING'`
    ],
    [
      'orders',
      'updated_at',
      `TIMESTAMPTZ NOT NULL DEFAULT NOW()`
    ]
  ];

  for (const [
    table,
    column,
    definition
  ] of columns) {
    const exists =
      await pool.query(
        `
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema='public'
          AND table_name=$1
          AND column_name=$2
        LIMIT 1
        `,
        [table, column]
      );

    if (!exists.rowCount) {
      await pool.query(
        `
        ALTER TABLE ${table}
        ADD COLUMN ${column}
        ${definition}
        `
      );
    }
  }

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_products_active
    ON products(active)
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

  console.log(
    'Face of Style Version 2 database ready.'
  );
}

/* =========================================================
   HEALTH
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
      } catch {}
    }

    res.json({
      ok: true,
      service:
        'Face of Style Hijab Factory',
      version: '2',
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
        result.rows.map(p => ({
          ...p,
          id: Number(p.id),
          price: Number(p.price),
          stock: Number(p.stock),
          img: normalizeImage(
            p.image || p.img
          ),
          image: normalizeImage(
            p.image || p.img
          )
        }));

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

app.get(
  '/api/products/:id',
  async (req, res) => {
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
          WHERE id=$1
            AND active=TRUE
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

      const p =
        result.rows[0];

      p.id = Number(p.id);
      p.price = Number(p.price);
      p.stock = Number(p.stock);

      p.img =
        normalizeImage(
          p.image || p.img
        );

      p.image = p.img;

      res.json({
        ok: true,
        product: p
      });
    } catch (error) {
      console.error(error);

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

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        message:
          'Password must be at least 6 characters.'
      });
    }

    try {
      const existing =
        await pool.query(
          `
          SELECT id
          FROM customers
          WHERE LOWER(email)=LOWER($1)
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
            phone,
            created_at
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

    if (!email || !password) {
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
          WHERE LOWER(email)=LOWER($1)
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

      delete customer.password_hash;

      const token =
        await createCustomerSession(
          customer.id
        );

      res.json({
        ok: true,
        token,
        customer
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to login.'
      });
    }
  }
);

/* =========================================================
   CUSTOMER ME
========================================================= */

app.get(
  '/api/customer/me',
  requireCustomer,
  async (req, res) => {
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
          WHERE id=$1
          LIMIT 1
          `,
          [
            req.customer.customerId
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
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
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to load customer.'
      });
    }
  }
);

/* =========================================================
   CUSTOMER PROFILE
========================================================= */

app.put(
  '/api/customer/profile',
  requireCustomer,
  async (req, res) => {
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

    if (!name || !validEmail(email)) {
      return res.status(400).json({
        ok: false,
        message:
          'Valid name and email are required.'
      });
    }

    try {
      const duplicate =
        await pool.query(
          `
          SELECT id
          FROM customers
          WHERE LOWER(email)=LOWER($1)
            AND id<>$2
          LIMIT 1
          `,
          [
            email,
            req.customer.customerId
          ]
        );

      if (duplicate.rowCount) {
        return res.status(409).json({
          ok: false,
          message:
            'Email is already in use.'
        });
      }

      const result =
        await pool.query(
          `
          UPDATE customers
          SET
            name=$1,
            email=$2,
            phone=$3,
            updated_at=NOW()
          WHERE id=$4
          RETURNING
            id,
            name,
            email,
            phone,
            created_at
          `,
          [
            name,
            email,
            phone,
            req.customer.customerId
          ]
        );

      res.json({
        ok: true,
        message:
          'Profile updated successfully.',
        customer:
          result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to update profile.'
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
    try {
      if (pool) {
        await pool.query(
          `
          DELETE FROM customer_sessions
          WHERE token=$1
          `,
          [req.customer.token]
        );
      }

      customerSessions.delete(
        req.customer.token
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(error);

      res.json({
        ok: true
      });
    }
  }
);

/* =========================================================
   CUSTOMER ADDRESSES
========================================================= */

app.get(
  '/api/customer/addresses',
  requireCustomer,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM customer_addresses
          WHERE customer_id=$1
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
      console.error(error);

      res.status(500).json({
        ok: false,
        addresses: [],
        message:
          'Unable to load addresses.'
      });
    }
  }
);

app.post(
  '/api/customer/addresses',
  requireCustomer,
  async (req, res) => {
    const address =
      cleanString(
        req.body?.address,
        1000
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

    const phone =
      cleanString(
        req.body?.phone ||
        req.customer.phone ||
        '',
        40
      );

    if (!address) {
      return res.status(400).json({
        ok: false,
        message:
          'Delivery address is required.'
      });
    }

    try {
      await pool.query(
        `
        UPDATE customer_addresses
        SET
          is_default=FALSE,
          updated_at=NOW()
        WHERE customer_id=$1
        `,
        [
          req.customer.customerId
        ]
      );

      const result =
        await pool.query(
          `
          INSERT INTO customer_addresses
          (
            customer_id,
            full_name,
            phone,
            address,
            city,
            state,
            is_default
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,TRUE)
          RETURNING *
          `,
          [
            req.customer.customerId,
            req.customer.name || '',
            phone,
            address,
            city,
            state
          ]
        );

      res.status(201).json({
        ok: true,
        message:
          'Delivery information saved.',
        address:
          result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to save address.'
      });
    }
  }
);

app.delete(
  '/api/customer/addresses/:id',
  requireCustomer,
  async (req, res) => {
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
          WHERE id=$1
            AND customer_id=$2
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
        ok: true
      });
    } catch (error) {
      console.error(error);

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
========================================================= */

app.get(
  '/api/customer/orders',
  requireCustomer,
  async (req, res) => {
    try {
      const orders =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE customer_id=$1
          ORDER BY created_at DESC
          `,
          [
            req.customer.customerId
          ]
        );

      const ids =
        orders.rows.map(
          o => Number(o.id)
        );

      let items = [];

      if (ids.length) {
        const result =
          await pool.query(
            `
            SELECT *
            FROM order_items
            WHERE order_id = ANY($1::bigint[])
            ORDER BY id ASC
            `,
            [ids]
          );

        items = result.rows;
      }

      const output =
        orders.rows.map(order => ({
          ...order,
          id: Number(order.id),
          total: Number(order.total),
          status:
            String(
              order.payment_status ||
              'PENDING'
            ).toLowerCase(),
          orderStatus:
            String(
              order.order_status ||
              'PENDING'
            ).toLowerCase(),
          createdAt:
            order.created_at,
          customer: {
            name:
              order.customer_name,
            email:
              order.customer_email,
            phone:
              order.customer_phone,
            address:
              order.delivery_address
          },
          items:
            items
              .filter(
                item =>
                  Number(
                    item.order_id
                  ) ===
                  Number(order.id)
              )
              .map(item => ({
                ...item,
                price:
                  Number(item.price),
                quantity:
                  Number(item.quantity),
                qty:
                  Number(item.quantity),
                subtotal:
                  Number(item.subtotal)
              }))
        }));

      res.json({
        ok: true,
        orders: output
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        orders: [],
        message:
          'Unable to load customer orders.'
      });
    }
  }
);

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
  '/api/admin/login',
  (req, res) => {
    const username =
      cleanString(
        req.body?.username,
        100
      );

    const password =
      String(
        req.body?.password || ''
      );

    if (
      !ADMIN_USERNAME ||
      !ADMIN_PASSWORD
    ) {
      return res.status(503).json({
        ok: false,
        message:
          'Admin credentials are not configured on the server.'
      });
    }

    if (
      username !==
        ADMIN_USERNAME ||
      password !==
        ADMIN_PASSWORD
    ) {
      return res.status(401).json({
        ok: false,
        message:
          'Invalid admin credentials.'
      });
    }

    const token =
      createAdminSession(
        username
      );

    res.json({
      ok: true,
      token,
      username
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
      req.admin.token
    );

    res.json({
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
    res.json({
      ok: true,
      username:
        req.admin.username
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
      return res.status(503).json({
        ok: false,
        stats: {},
        message:
          'Database is not configured.'
      });
    }

    try {
      const result =
        await pool.query(`
          SELECT
            COUNT(*)::int AS orders,

            COUNT(*)
            FILTER(
              WHERE payment_status='PAID'
            )::int AS paid,

            COUNT(*)
            FILTER(
              WHERE payment_status='PENDING'
            )::int AS pending,

            COUNT(*)
            FILTER(
              WHERE order_status='PROCESSING'
            )::int AS processing,

            COALESCE(
              SUM(total)
              FILTER(
                WHERE payment_status='PAID'
              ),
              0
            )::numeric AS revenue

          FROM orders
        `);

      const row =
        result.rows[0] || {};

      res.json({
        ok: true,
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
      console.error(error);

      res.status(500).json({
        ok: false,
        stats: {},
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
    try {
      const result =
        await pool.query(`
          SELECT *
          FROM products
          ORDER BY created_at DESC, id DESC
        `);

      const products =
        result.rows.map(p => ({
          ...p,
          id: Number(p.id),
          price: Number(p.price),
          stock: Number(p.stock),
          img:
            normalizeImage(
              p.image
            ),
          image:
            normalizeImage(
              p.image
            )
        }));

      res.json({
        ok: true,
        products,
        data: products,
        count:
          products.length
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        products: [],
        message:
          'Unable to load admin products.'
      });
    }
  }
);

app.post(
  '/api/admin/products',
  requireAdmin,
  async (req, res) => {
    const name =
      cleanString(
        req.body?.name,
        150
      );

    const category =
      normalizeCategory(
        req.body?.category ||
        req.body?.cat
      );

    const description =
      cleanString(
        req.body?.description ||
        req.body?.desc,
        3000
      );

    const color =
      cleanString(
        req.body?.color,
        100
      );

    const image =
      cleanString(
        req.body?.image ||
        req.body?.img,
        2500000
      );

    const price =
      positivePrice(
        req.body?.price
      );

    const stock =
      nonNegativeInteger(
        req.body?.stock || 0
      );

    if (!name) {
      return res.status(400).json({
        ok: false,
        message:
          'Product name is required.'
      });
    }

    if (price === null) {
      return res.status(400).json({
        ok: false,
        message:
          'Valid product price is required.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          INSERT INTO products
          (
            name,
            category,
            description,
            price,
            color,
            image,
            stock,
            active
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,$7,TRUE)
          RETURNING *
          `,
          [
            name,
            category,
            description,
            price,
            color,
            image,
            stock ?? 0
          ]
        );

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
          product.image
        );

      product.image =
        product.img;

      res.status(201).json({
        ok: true,
        product
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to create product.'
      });
    }
  }
);

app.put(
  '/api/admin/products/:id',
  requireAdmin,
  async (req, res) => {
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

    const name =
      cleanString(
        req.body?.name,
        150
      );

    const category =
      normalizeCategory(
        req.body?.category ||
        req.body?.cat
      );

    const description =
      cleanString(
        req.body?.description ||
        req.body?.desc,
        3000
      );

    const color =
      cleanString(
        req.body?.color,
        100
      );

    const price =
      positivePrice(
        req.body?.price
      );

    const stock =
      nonNegativeInteger(
        req.body?.stock || 0
      );

    const image =
      cleanString(
        req.body?.image ||
        req.body?.img,
        2500000
      );

    if (!name || price === null) {
      return res.status(400).json({
        ok: false,
        message:
          'Product name and valid price are required.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          UPDATE products
          SET
            name=$1,
            category=$2,
            description=$3,
            price=$4,
            color=$5,
            image=$6,
            stock=$7,
            updated_at=NOW()
          WHERE id=$8
          RETURNING *
          `,
          [
            name,
            category,
            description,
            price,
            color,
            image,
            stock ?? 0,
            id
          ]
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
          product.image
        );

      product.image =
        product.img;

      res.json({
        ok: true,
        product
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to update product.'
      });
    }
  }
);

app.delete(
  '/api/admin/products/:id',
  requireAdmin,
  async (req, res) => {
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
      /*
        Soft delete:
        We keep old order history intact.
      */
      const result =
        await pool.query(
          `
          UPDATE products
          SET
            active=FALSE,
            updated_at=NOW()
          WHERE id=$1
          RETURNING id
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

      res.json({
        ok: true,
        message:
          'Product removed from the store.'
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
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
    try {
      const ordersResult =
        await pool.query(`
          SELECT *
          FROM orders
          ORDER BY created_at DESC
        `);

      const ids =
        ordersResult.rows.map(
          o => Number(o.id)
        );

      let items = [];

      if (ids.length) {
        const result =
          await pool.query(
            `
            SELECT *
            FROM order_items
            WHERE order_id =
              ANY($1::bigint[])
            ORDER BY id ASC
            `,
            [ids]
          );

        items = result.rows;
      }

      const orders =
        ordersResult.rows.map(o => ({
          ...o,
          id: Number(o.id),
          customer_id:
            o.customer_id
              ? Number(o.customer_id)
              : null,
          total:
            Number(o.total),
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
          updatedAt:
            o.updated_at,
          customer: {
            name:
              o.customer_name || '',
            email:
              o.customer_email || '',
            phone:
              o.customer_phone || '',
            address:
              o.delivery_address || ''
          },
          payment: {
            provider:
              o.payment_method ||
              'paystack',
            reference:
              o.paystack_reference ||
              ''
          },
          items:
            items
              .filter(
                item =>
                  Number(
                    item.order_id
                  ) ===
                  Number(o.id)
              )
              .map(item => ({
                ...item,
                price:
                  Number(item.price),
                quantity:
                  Number(item.quantity),
                qty:
                  Number(item.quantity),
                subtotal:
                  Number(item.subtotal)
              }))
        }));

      res.json({
        ok: true,
        orders
      });
    } catch (error) {
      console.error(error);

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
          WHERE id=$1
          LIMIT 1
          `,
          [id]
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
          SELECT *
          FROM order_items
          WHERE order_id=$1
          ORDER BY id ASC
          `,
          [id]
        );

      const o =
        orderResult.rows[0];

      res.json({
        ok: true,
        order: {
          ...o,
          id: Number(o.id),
          total:
            Number(o.total),
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
          customer: {
            name:
              o.customer_name || '',
            email:
              o.customer_email || '',
            phone:
              o.customer_phone || '',
            address:
              o.delivery_address || ''
          },
          payment: {
            provider:
              o.payment_method ||
              'paystack',
            reference:
              o.paystack_reference ||
              ''
          },
          items:
            itemsResult.rows.map(
              item => ({
                ...item,
                price:
                  Number(item.price),
                quantity:
                  Number(item.quantity),
                qty:
                  Number(item.quantity),
                subtotal:
                  Number(item.subtotal)
              })
            )
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to load order.'
      });
    }
  }
);

/* =========================================================
   ADMIN PAYMENT STATUS
========================================================= */

app.patch(
  '/api/admin/orders/:id/payment',
  requireAdmin,
  async (req, res) => {
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

    if (!allowed.includes(status)) {
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
            payment_status=$1,
            order_status=
              CASE
                WHEN $1='PAID'
                  AND order_status='PENDING'
                THEN 'PROCESSING'
                ELSE order_status
              END,
            updated_at=NOW()
          WHERE id=$2
          RETURNING *
          `,
          [status, id]
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
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to update payment status.'
      });
    }
  }
);

/* =========================================================
   ADMIN ORDER STATUS
========================================================= */

app.patch(
  '/api/admin/orders/:id/status',
  requireAdmin,
  async (req, res) => {
    const id =
      positiveInteger(
        req.params.id
      );

    const status =
      cleanString(
        req.body?.order_status ||
        req.body?.status,
        30
      ).toUpperCase();

    const allowed = [
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

    if (!allowed.includes(status)) {
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
            order_status=$1,
            updated_at=NOW()
          WHERE id=$2
          RETURNING *
          `,
          [status, id]
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
      console.error(error);

      res.status(500).json({
        ok: false,
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
      const result =
        await pool.query(
          `
          SELECT *
          FROM store_settings
          WHERE id=1
          LIMIT 1
          `
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
            row.free_delivery_from ||
            0
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
            row.low_stock_limit ?? 5
          ),
        enableCart:
          row.enable_cart !== false,
        enableWhatsapp:
          row.enable_whatsapp !== false,
        showStock:
          row.show_stock !== false
      };

      res.json({
        ok: true,
        settings,
        paystackConfigured:
          Boolean(
            PAYSTACK_SECRET_KEY
          ),
        whatsapp:
          settings.whatsapp
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
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
    const b =
      req.body || {};

    const text = (
      value,
      max = 2500000
    ) =>
      String(value ?? '')
        .trim()
        .slice(0, max);

    const num = value => {
      const n =
        Number(value);

      return Number.isFinite(n) &&
        n >= 0
        ? n
        : 0;
    };

    try {
      const result =
        await pool.query(
          `
          INSERT INTO store_settings
          (
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
          VALUES
          (
            1,$1,$2,$3,$4,$5,$6,$7,
            $8,$9,$10,$11,$12,$13,$14,
            $15,$16,$17,$18,$19,$20,$21,
            $22,$23,$24,$25,$26,$27,
            NOW()
          )
          ON CONFLICT(id)
          DO UPDATE SET
            store_name=
              EXCLUDED.store_name,
            tagline=
              EXCLUDED.tagline,
            whatsapp=
              EXCLUDED.whatsapp,
            phone=
              EXCLUDED.phone,
            email=
              EXCLUDED.email,
            address=
              EXCLUDED.address,
            hero_title=
              EXCLUDED.hero_title,
            hero_text=
              EXCLUDED.hero_text,
            about_text=
              EXCLUDED.about_text,
            delivery_text=
              EXCLUDED.delivery_text,
            delivery_fee=
              EXCLUDED.delivery_fee,
            free_delivery_from=
              EXCLUDED.free_delivery_from,
            bank_name=
              EXCLUDED.bank_name,
            account_name=
              EXCLUDED.account_name,
            account_number=
              EXCLUDED.account_number,
            bank_instructions=
              EXCLUDED.bank_instructions,
            logo=
              EXCLUDED.logo,
            hero_image=
              EXCLUDED.hero_image,
            primary_color=
              EXCLUDED.primary_color,
            secondary_color=
              EXCLUDED.secondary_color,
            gold_color=
              EXCLUDED.gold_color,
            background_color=
              EXCLUDED.background_color,
            text_color=
              EXCLUDED.text_color,
            low_stock_limit=
              EXCLUDED.low_stock_limit,
            enable_cart=
              EXCLUDED.enable_cart,
            enable_whatsapp=
              EXCLUDED.enable_whatsapp,
            show_stock=
              EXCLUDED.show_stock,
            updated_at=NOW()
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
              b.whatsapp ||
              WHATSAPP_NUMBER,
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
              3000
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
              b.heroImage
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
            b.enableCart !== false,
            b.enableWhatsapp !== false,
            b.showStock !== false
          ]
        );

      res.json({
        ok: true,
        message:
          'Store settings saved successfully.',
        settings:
          result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to save settings.'
      });
    }
  }
);

/* =========================================================
   PUBLIC SITE SETTINGS
========================================================= */

app.get(
  '/api/site-settings',
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM store_settings
          WHERE id=1
          LIMIT 1
          `
        );

      const row =
        result.rows[0] || {};

      res.json({
        ok: true,
        settings: {
          id: 1,
          storeName:
            row.store_name ||
            'Face of Style Hijab Factory',
          tagline:
            row.tagline ||
            'HIJAB FACTORY',
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
            row.hero_title ||
            'Modesty, Elegance & Style.',
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
              row.free_delivery_from ||
              0
            ),
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
              row.low_stock_limit ?? 5
            ),
          enableCart:
            row.enable_cart !== false,
          enableWhatsapp:
            row.enable_whatsapp !== false,
          showStock:
            row.show_stock !== false
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to load site settings.'
      });
    }
  }
);

/* =========================================================
   CONFIG COMPATIBILITY ENDPOINT
========================================================= */

app.get(
  '/api/config',
  async (req, res) => {
    res.json({
      ok: true,
      whatsapp:
        WHATSAPP_NUMBER,
      paystackConfigured:
        Boolean(
          PAYSTACK_SECRET_KEY
        ),
      currency: 'NGN'
    });
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
      req.body?.customer || {};

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

      const session =
        await getCustomerSession(
          req
        );

      let customerId =
        session?.customerId ||
        null;

      if (!customerId) {
        const existing =
          await client.query(
            `
            SELECT id
            FROM customers
            WHERE LOWER(email)=LOWER($1)
            LIMIT 1
            `,
            [email]
          );

        if (existing.rowCount) {
          customerId =
            Number(
              existing.rows[0].id
            );
        }
      }

      const ids =
        rawItems
          .map(
            item =>
              positiveInteger(
                item.id
              )
          )
          .filter(Boolean);

      if (!ids.length) {
        throw new Error(
          'Invalid cart items.'
        );
      }

      const uniqueIds =
        [
          ...new Set(ids)
        ];

      const products =
        await client.query(
          `
          SELECT
            id,
            name,
            price,
            stock,
            active
          FROM products
          WHERE id=ANY($1::int[])
          FOR UPDATE
          `,
          [uniqueIds]
        );

      const productMap =
        new Map(
          products.rows.map(
            p => [
              Number(p.id),
              p
            ]
          )
        );

      const orderItems = [];
      let total = 0;

      for (
        const item
        of rawItems
      ) {
        const productId =
          positiveInteger(
            item.id
          );

        const quantity =
          positiveInteger(
            item.qty ||
            item.quantity
          );

        if (
          !productId ||
          !quantity ||
          quantity > 99
        ) {
          throw new Error(
            'Invalid cart quantity.'
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
          Number(product.price);

        const subtotal =
          Math.round(
            price *
            quantity *
            100
          ) / 100;

        total += subtotal;

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
            $1,$2,$3,$4,$5,$6,
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
          ($1,$2,$3,$4,$5,$6)
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

      const payload = {
        email,
        amount:
          Math.round(
            total * 100
          ),
        currency: 'NGN',
        reference,
        metadata: {
          order_id:
            String(order.id),
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
        payload.callback_url =
          PAYSTACK_CALLBACK_URL;
      }

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
              JSON.stringify(
                payload
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
        await pool.query(
          `
          UPDATE orders
          SET
            payment_status='FAILED',
            updated_at=NOW()
          WHERE reference=$1
          `,
          [reference]
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
          paystack_reference=$1,
          updated_at=NOW()
        WHERE reference=$2
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
        'Paystack initialize:',
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
========================================================= */

async function completePaidOrder(
  reference,
  transaction
) {
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
        WHERE reference=$1
        FOR UPDATE
        `,
        [reference]
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
        Number(order.total) *
        100
      );

    if (
      transaction.status !==
        'success' ||
      transaction.currency !==
        'NGN' ||
      Number(transaction.amount) !==
        expectedAmount
    ) {
      throw new Error(
        'Payment amount or status does not match the order.'
      );
    }

    /*
      IMPORTANT:
      Stock is reduced only once.
    */

    if (
      order.payment_status !==
      'PAID'
    ) {
      const items =
        await client.query(
          `
          SELECT *
          FROM order_items
          WHERE order_id=$1
          ORDER BY id ASC
          `,
          [order.id]
        );

      for (
        const item
        of items.rows
      ) {
        const stock =
          await client.query(
            `
            UPDATE products
            SET
              stock=stock-$1,
              updated_at=NOW()
            WHERE id=$2
              AND active=TRUE
              AND stock >= $1
            RETURNING id
            `,
            [
              item.quantity,
              item.product_id
            ]
          );

        if (!stock.rowCount) {
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
        payment_status='PAID',
        order_status=
          CASE
            WHEN order_status='PENDING'
            THEN 'PROCESSING'
            ELSE order_status
          END,
        paystack_reference=$1,
        updated_at=NOW()
      WHERE id=$2
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
        Number(order.id),
      reference:
        order.reference,
      total:
        Number(order.total)
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

      if (
        data.data.status !==
        'success'
      ) {
        await pool.query(
          `
          UPDATE orders
          SET
            payment_status='FAILED',
            updated_at=NOW()
          WHERE reference=$1
            AND payment_status<>'PAID'
          `,
          [reference]
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
          data.data
        );

      res.json({
        ok: true,
        paid: true,
        reference:
          completed.reference,
        order:
          completed
      });
    } catch (error) {
      console.error(
        'Paystack verify:',
        error
      );

      res.status(500).json({
        ok: false,
        paid: false,
        message:
          error.message ||
          'Payment verification failed.'
      });
    }
  }
);

/* =========================================================
   PAYSTACK WEBHOOK
========================================================= */

app.post(
  '/api/paystack/webhook',
  async (req, res) => {
    try {
      const signature =
        req.headers[
          'x-paystack-signature'
        ];

      if (
        !signature ||
        !PAYSTACK_SECRET_KEY ||
        !req.rawBody
      ) {
        return res.sendStatus(401);
      }

      const expected =
        crypto
          .createHmac(
            'sha512',
            PAYSTACK_SECRET_KEY
          )
          .update(req.rawBody)
          .digest('hex');

      const a =
        Buffer.from(
          String(signature)
        );

      const b =
        Buffer.from(expected);

      if (
        a.length !== b.length ||
        !crypto.timingSafeEqual(
          a,
          b
        )
      ) {
        return res.sendStatus(401);
      }

      const event =
        req.body;

      if (
        event?.event ===
        'charge.success'
      ) {
        const tx =
          event.data;

        if (
          tx?.reference &&
          tx?.status ===
            'success' &&
          tx?.currency ===
            'NGN'
        ) {
          try {
            await completePaidOrder(
              tx.reference,
              tx
            );
          } catch (error) {
            console.error(
              'Webhook order completion:',
              error
            );
          }
        }
      }

      res.sendStatus(200);
    } catch (error) {
      console.error(
        'Webhook error:',
        error
      );

      res.sendStatus(500);
    }
  }
);

/* =========================================================
   404 API HANDLER
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
   FRONTEND FALLBACK
========================================================= */

app.use((req, res, next) => {
  // Kada frontend fallback ya kama API routes
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    return next();
  }

  res.sendFile(
    path.join(__dirname, 'public', 'index.html'),
    error => {
      if (error) {
        next(error);
      }
    }
  );
});

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
      () => {
        console.log(
          `Face of Style Hijab Factory Version 2 running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      'Database initialization failed:',
      error
    );

    /*
      We still start the server so /api/health
      can report the problem instead of crashing.
    */

    app.listen(
      PORT,
      () => {
        console.log(
          `Face of Style server started on port ${PORT}, but database initialization needs attention.`
        );
      }
    );
  }
}

startServer();
