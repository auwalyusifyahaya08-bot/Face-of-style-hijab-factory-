import 'dotenv/config';

import express from 'express';
import pg from 'pg';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { promisify } from 'util';

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const PORT =
  Number(process.env.PORT) || 10000;

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
  process.env.WHATSAPP_NUMBER ||
  '2349065828886';

const PAYSTACK_CALLBACK_URL =
  process.env.PAYSTACK_CALLBACK_URL || '';

const BASE_URL =
  process.env.BASE_URL || '';

const BANK_NAME =
  process.env.BANK_NAME || '';

const BANK_ACCOUNT_NAME =
  process.env.BANK_ACCOUNT_NAME || '';

const BANK_ACCOUNT_NUMBER =
  process.env.BANK_ACCOUNT_NUMBER || '';

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
    limit: '10mb',

    verify: (req, res, buf) => {
      req.rawBody = Buffer.from(buf);
    }
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '10mb'
  })
);

/*
  PUBLIC FRONTEND

  public/
    index.html
    admin.html
    assets/
      logo.png
      product-1.jpg
      ...
*/

app.use(
  express.static(
    path.join(
      __dirname,
      'public'
    )
  )
);

/* =========================================================
   SESSIONS
========================================================= */

const adminSessions = new Map();

const customerSessions = new Map();

/* =========================================================
   SESSION HELPERS
========================================================= */

function createToken() {

  return crypto
    .randomBytes(32)
    .toString('hex');

}

/* =========================================================
   ADMIN SESSION
========================================================= */

function createAdminSession(
  username
) {

  const token =
    createToken();

  adminSessions.set(
    token,
    {
      username,
      createdAt: Date.now()
    }
  );

  return token;

}

function getAdminSession(req) {

  const auth =
    String(
      req.headers.authorization || ''
    );

  if (
    !auth.startsWith(
      'Bearer '
    )
  ) {

    return null;

  }

  const token =
    auth
      .slice(7)
      .trim();

  if (!token) {

    return null;

  }

  const session =
    adminSessions.get(
      token
    );

  if (!session) {

    return null;

  }

  const maxAge =
    1000 *
    60 *
    60 *
    24;

  if (
    Date.now() -
      session.createdAt >
    maxAge
  ) {

    adminSessions.delete(
      token
    );

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

    return res
      .status(401)
      .json({
        ok: false,
        message:
          'Admin authentication required.'
      });

  }

  req.admin =
    session;

  next();

}

/* =========================================================
   CUSTOMER SESSION
========================================================= */

function createCustomerSession(
  customerId
) {

  const token =
    createToken();

  customerSessions.set(
    token,
    {
      customerId:
        Number(customerId),

      createdAt:
        Date.now()
    }
  );

  return token;

}

function getCustomerSession(
  req
) {

  const auth =
    String(
      req.headers.authorization || ''
    );

  if (
    !auth.startsWith(
      'Bearer '
    )
  ) {

    return null;

  }

  const token =
    auth
      .slice(7)
      .trim();

  if (!token) {

    return null;

  }

  const session =
    customerSessions.get(
      token
    );

  if (!session) {

    return null;

  }

  const maxAge =
    1000 *
    60 *
    60 *
    24 *
    30;

  if (
    Date.now() -
      session.createdAt >
    maxAge
  ) {

    customerSessions.delete(
      token
    );

    return null;

  }

  return {
    token,
    ...session
  };

}

function requireCustomer(
  req,
  res,
  next
) {

  const session =
    getCustomerSession(req);

  if (!session) {

    return res
      .status(401)
      .json({
        ok: false,
        message:
          'Customer login required.'
      });

  }

  req.customer =
    session;

  next();

}

/* =========================================================
   PASSWORD HASHING
========================================================= */

const scryptAsync =
  promisify(
    crypto.scrypt
  );

async function hashPassword(
  password
) {

  const salt =
    crypto
      .randomBytes(16)
      .toString('hex');

  const derived =
    await scryptAsync(
      password,
      salt,
      64
    );

  return (
    'scrypt$' +
    salt +
    '$' +
    Buffer
      .from(derived)
      .toString('hex')
  );

}

async function verifyPassword(
  password,
  stored
) {

  try {

    const parts =
      String(stored)
        .split('$');

    if (
      parts.length !== 3 ||
      parts[0] !== 'scrypt'
    ) {

      return false;

    }

    const salt =
      parts[1];

    const expected =
      Buffer.from(
        parts[2],
        'hex'
      );

    const actual =
      await scryptAsync(
        password,
        salt,
        64
      );

    return (
      expected.length ===
        actual.length &&
      crypto.timingSafeEqual(
        expected,
        actual
      )
    );

  } catch {

    return false;

  }

}

/* =========================================================
   HELPERS
========================================================= */

function cleanString(
  value,
  max = 500
) {

  return String(
    value ?? ''
  )
    .trim()
    .slice(0, max);

}

function positiveInteger(
  value
) {

  const number =
    Number(value);

  if (
    !Number.isInteger(number) ||
    number < 1
  ) {

    return null;

  }

  return number;

}

function nonNegativeInteger(
  value
) {

  const number =
    Number(value);

  if (
    !Number.isInteger(number) ||
    number < 0
  ) {

    return null;

  }

  return number;

}

function positivePrice(
  value
) {

  const number =
    Number(value);

  if (
    !Number.isFinite(number) ||
    number < 0
  ) {

    return null;

  }

  return (
    Math.round(
      number * 100
    ) / 100
  );

}

function validEmail(
  email
) {

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(email);

}

function validPhone(
  phone
) {

  return /^[0-9+\-\s()]{7,25}$/
    .test(phone);

}

function normalizeCategory(
  value
) {

  return (
    cleanString(
      value,
      50
    ) ||
    'Fashion'
  );

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

function normalizeImage(
  value
) {

  return cleanString(
    value,
    2000000
  );

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

  /* =======================================================
     PRODUCTS
  ======================================================= */

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
    Extra product fields for the newer admin dashboard.
    Existing products are preserved.
  */

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS discount NUMERIC(12,2)
    NOT NULL DEFAULT 0
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS sizes TEXT
    NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS images JSONB
    NOT NULL DEFAULT '[]'::jsonb
  `);

  /* =======================================================
     ORDERS
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,

      reference TEXT UNIQUE NOT NULL,

      customer_name TEXT NOT NULL,
      customer_email TEXT NOT NULL,
      customer_phone TEXT NOT NULL,

      delivery_address TEXT NOT NULL,

      payment_method TEXT
        NOT NULL DEFAULT 'paystack',

      payment_status TEXT
        NOT NULL DEFAULT 'PENDING',

      order_status TEXT
        NOT NULL DEFAULT 'PENDING',

      total NUMERIC(12,2)
        NOT NULL DEFAULT 0,

      currency TEXT
        NOT NULL DEFAULT 'NGN',

      paystack_reference TEXT,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    )
  `);

  /*
    Add customer_id to existing orders.
  */

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS customer_id INTEGER
  `);

  /* =======================================================
     ORDER ITEMS
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS order_items (
      id BIGSERIAL PRIMARY KEY,

      order_id BIGINT NOT NULL
        REFERENCES orders(id)
        ON DELETE CASCADE,

      product_id INTEGER NOT NULL,

      product_name TEXT NOT NULL,

      price NUMERIC(12,2)
        NOT NULL,

      quantity INTEGER NOT NULL,

      subtotal NUMERIC(12,2)
        NOT NULL
    )
  `);

  /* =======================================================
     CUSTOMERS
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id SERIAL PRIMARY KEY,

      name TEXT NOT NULL,

      email TEXT UNIQUE NOT NULL,

      phone TEXT DEFAULT '',

      password_hash TEXT NOT NULL,

      store_credit NUMERIC(12,2)
        NOT NULL DEFAULT 0,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    )
  `);

  /* =======================================================
     ADDRESSES
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customer_addresses (
      id SERIAL PRIMARY KEY,

      customer_id INTEGER NOT NULL
        REFERENCES customers(id)
        ON DELETE CASCADE,

      label TEXT NOT NULL DEFAULT 'Home',

      address TEXT NOT NULL,

      city TEXT DEFAULT '',

      state TEXT DEFAULT '',

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    )
  `);

  /* =======================================================
     STORE CREDIT TRANSACTIONS
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS store_credit_transactions (
      id BIGSERIAL PRIMARY KEY,

      customer_id INTEGER NOT NULL
        REFERENCES customers(id)
        ON DELETE CASCADE,

      type TEXT NOT NULL,

      amount NUMERIC(12,2)
        NOT NULL,

      note TEXT DEFAULT '',

      order_id BIGINT,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    )
  `);

  /* =======================================================
     REFUNDS
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS refunds (
      id BIGSERIAL PRIMARY KEY,

      customer_id INTEGER,

      order_id BIGINT,

      reference TEXT UNIQUE NOT NULL,

      amount NUMERIC(12,2)
        NOT NULL DEFAULT 0,

      status TEXT
        NOT NULL DEFAULT 'PENDING',

      note TEXT DEFAULT '',

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    )
  `);

  /* =======================================================
     STORE SETTINGS
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS store_settings (
      id INTEGER PRIMARY KEY DEFAULT 1,

      store_name TEXT
        NOT NULL DEFAULT 'Face of Style Hijab Factory',

      tagline TEXT
        NOT NULL DEFAULT 'HIJAB FACTORY',

      hero_title TEXT
        NOT NULL DEFAULT 'Modesty, Elegance & Style.',

      hero_text TEXT
        NOT NULL DEFAULT 'Discover carefully crafted hijabs, abayas, gowns and modest outfits.',

      primary_color TEXT
        NOT NULL DEFAULT '#651630',

      secondary_color TEXT
        NOT NULL DEFAULT '#4d1024',

      gold_color TEXT
        NOT NULL DEFAULT '#c9a45b',

      background_color TEXT
        NOT NULL DEFAULT '#fcf8f1',

      text_color TEXT
        NOT NULL DEFAULT '#251c20',

      whatsapp TEXT
        NOT NULL DEFAULT '2349065828886',

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    INSERT INTO store_settings (id)
    VALUES (1)
    ON CONFLICT (id)
    DO NOTHING
  `);

  /* =======================================================
     INDEXES
  ======================================================= */

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
    idx_addresses_customer
    ON customer_addresses(customer_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_credit_customer
    ON store_credit_transactions(customer_id)
  `);

  console.log(
    'Database initialized successfully.'
  );

}

/* =========================================================
   HEALTH
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

      } catch (error) {

        console.error(
          'Health database error:',
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
   PUBLIC CONFIG
========================================================= */

app.get(
  '/api/config',
  async (req, res) => {

    let settings = {};

    if (pool) {

      try {

        const result =
          await pool.query(`
            SELECT
              store_name,
              tagline,
              hero_title,
              hero_text,
              primary_color,
              secondary_color,
              gold_color,
              background_color,
              text_color,
              whatsapp
            FROM store_settings
            WHERE id = 1
            LIMIT 1
          `);

        settings =
          result.rows[0] ||
          {};

      } catch (error) {

        console.error(
          'Config error:',
          error
        );

      }

    }

    res.json({

      ok: true,

      whatsapp:
        settings.whatsapp ||
        WHATSAPP_NUMBER,

      settings,

      paystackConfigured:
        Boolean(
          PAYSTACK_SECRET_KEY
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
            category AS cat,
            category,
            description,
            description AS desc,
            price,
            discount,
            color,
            image AS img,
            image,
            images,
            sizes,
            stock,
            active
          FROM products
          WHERE active = TRUE
          ORDER BY created_at DESC
        `);

      res.json({

        ok: true,

        products:
          result.rows

      });

    } catch (error) {

      console.error(
        'Products error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to load products.'
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
        req.body?.password ||
        ''
      );

    if (
      !ADMIN_USERNAME ||
      !ADMIN_PASSWORD
    ) {

      return res
        .status(503)
        .json({
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

      return res
        .status(401)
        .json({
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

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
        });

    }

    try {

      const ordersResult =
        await pool.query(`
          SELECT
            COUNT(*)::int AS orders,

            COUNT(*) FILTER (
              WHERE payment_status = 'PAID'
            )::int AS paid,

            COUNT(*) FILTER (
              WHERE payment_status = 'PENDING'
            )::int AS pending,

            COALESCE(
              SUM(total) FILTER (
                WHERE payment_status = 'PAID'
              ),
              0
            )::numeric AS revenue
          FROM orders
        `);

      const productsResult =
        await pool.query(`
          SELECT
            COUNT(*)::int AS products,

            COUNT(*) FILTER (
              WHERE active = TRUE
            )::int AS active_products,

            COALESCE(
              SUM(stock) FILTER (
                WHERE active = TRUE
              ),
              0
            )::int AS stock
          FROM products
        `);

      const stats = {

        orders:
          Number(
            ordersResult.rows[0]?.orders ||
            0
          ),

        paid:
          Number(
            ordersResult.rows[0]?.paid ||
            0
          ),

        pending:
          Number(
            ordersResult.rows[0]?.pending ||
            0
          ),

        revenue:
          Number(
            ordersResult.rows[0]?.revenue ||
            0
          ),

        products:
          Number(
            productsResult.rows[0]?.products ||
            0
          ),

        activeProducts:
          Number(
            productsResult.rows[0]?.active_products ||
            0
          ),

        stock:
          Number(
            productsResult.rows[0]?.stock ||
            0
          )

      };

      res.json({

        ok: true,

        stats

      });

    } catch (error) {

      console.error(
        'Dashboard error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
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

      return res
        .status(503)
        .json({
          ok: false,
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
            discount,
            color,
            image AS img,
            image,
            images,
            sizes,
            stock,
            active,
            created_at,
            updated_at
          FROM products
          ORDER BY created_at DESC
        `);

      res.json({

        ok: true,

        products:
          result.rows

      });

    } catch (error) {

      console.error(
        'Admin products error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to load admin products.'
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

      return res
        .status(503)
        .json({
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

    const category =
      normalizeCategory(
        req.body?.category ||
        req.body?.cat
      );

    const description =
      cleanString(
        req.body?.description ||
        req.body?.desc,
        5000
      );

    const color =
      cleanString(
        req.body?.color,
        200
      );

    const image =
      normalizeImage(
        req.body?.image ||
        req.body?.img
      );

    const price =
      positivePrice(
        req.body?.price
      );

    const discount =
      positivePrice(
        req.body?.discount ||
        0
      );

    const stock =
      nonNegativeInteger(
        req.body?.stock
      );

    const sizes =
      cleanString(
        req.body?.sizes,
        1000
      );

    let images =
      Array.isArray(
        req.body?.images
      )
        ? req.body.images
        : [];

    images =
      images
        .map(
          item =>
            normalizeImage(item)
        )
        .filter(Boolean)
        .slice(0, 10);

    if (
      image &&
      !images.includes(image)
    ) {

      images.unshift(
        image
      );

    }

    if (!name) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Product name is required.'
        });

    }

    if (price === null) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'A valid product price is required.'
        });

    }

    if (
      stock === null
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'A valid stock quantity is required.'
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
            discount,
            color,
            image,
            images,
            sizes,
            stock,
            active
          )
          VALUES
          (
            $1,$2,$3,$4,$5,
            $6,$7,$8,$9,$10,TRUE
          )
          RETURNING *
          `,
          [
            name,
            category,
            description,
            price,
            discount || 0,
            color,
            image,
            JSON.stringify(
              images
            ),
            sizes,
            stock
          ]
        );

      res
        .status(201)
        .json({
          ok: true,
          product:
            result.rows[0]
        });

    } catch (error) {

      console.error(
        'Create product error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
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

      return res
        .status(503)
        .json({
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

      return res
        .status(400)
        .json({
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
        5000
      );

    const color =
      cleanString(
        req.body?.color,
        200
      );

    const image =
      normalizeImage(
        req.body?.image ||
        req.body?.img
      );

    const price =
      positivePrice(
        req.body?.price
      );

    const discount =
      positivePrice(
        req.body?.discount ||
        0
      );

    const stock =
      nonNegativeInteger(
        req.body?.stock
      );

    const sizes =
      cleanString(
        req.body?.sizes,
        1000
      );

    const active =
      req.body?.active !== false;

    let images =
      Array.isArray(
        req.body?.images
      )
        ? req.body.images
        : [];

    images =
      images
        .map(
          item =>
            normalizeImage(item)
        )
        .filter(Boolean)
        .slice(0, 10);

    if (
      image &&
      !images.includes(image)
    ) {

      images.unshift(
        image
      );

    }

    if (
      !name ||
      price === null ||
      stock === null
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Product name, valid price and stock are required.'
        });

    }

    try {

      const result =
        await pool.query(
          `
          UPDATE products
          SET
            name = $1,
            category = $2,
            description = $3,
            price = $4,
            discount = $5,
            color = $6,
            image = $7,
            images = $8,
            sizes = $9,
            stock = $10,
            active = $11,
            updated_at = NOW()
          WHERE id = $12
          RETURNING *
          `,
          [
            name,
            category,
            description,
            price,
            discount || 0,
            color,
            image,
            JSON.stringify(
              images
            ),
            sizes,
            stock,
            active,
            id
          ]
        );

      if (
        !result.rowCount
      ) {

        return res
          .status(404)
          .json({
            ok: false,
            message:
              'Product not found.'
          });

      }

      res.json({

        ok: true,

        product:
          result.rows[0]

      });

    } catch (error) {

      console.error(
        'Update product error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
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

      return res
        .status(503)
        .json({
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

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Invalid product ID.'
        });

    }

    try {

      const result =
        await pool.query(
          `
          UPDATE products
          SET
            active = FALSE,
            updated_at = NOW()
          WHERE id = $1
          RETURNING id
          `,
          [id]
        );

      if (
        !result.rowCount
      ) {

        return res
          .status(404)
          .json({
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

      console.error(
        'Delete product error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to remove product.'
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

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
        });

    }

    try {

      const ordersResult =
        await pool.query(`
          SELECT
            o.id,
            o.reference,
            o.customer_id,
            o.customer_name,
            o.customer_email,
            o.customer_phone,
            o.delivery_address,
            o.payment_method,
            o.payment_status,
            o.order_status,
            o.total,
            o.currency,
            o.paystack_reference,
            o.created_at,
            o.updated_at,

            c.name AS registered_customer_name

          FROM orders o

          LEFT JOIN customers c
            ON c.id = o.customer_id

          ORDER BY
            o.created_at DESC
        `);

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
          order =>
            order.id
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
          .push(item);

      }

      const output =
        orders.map(
          order => ({

            id:
              order.id,

            reference:
              order.reference,

            total:
              Number(
                order.total
              ),

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

            customer: {

              id:
                order.customer_id,

              name:
                order.customer_name,

              email:
                order.customer_email,

              phone:
                order.customer_phone,

              address:
                order.delivery_address

            },

            payment: {

              provider:
                order.payment_method,

              status:
                order.payment_status,

              reference:
                order.paystack_reference

            },

            payment_status:
              order.payment_status,

            order_status:
              order.order_status,

            created_at:
              order.created_at,

            updated_at:
              order.updated_at,

            items:
              itemsByOrder.get(
                order.id
              ) || []

          })
        );

      res.json({

        ok: true,

        orders:
          output

      });

    } catch (error) {

      console.error(
        'Admin orders error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to load orders.'
        });

    }

  }
);

/* =========================================================
   ADMIN UPDATE ORDER STATUS
========================================================= */

app.patch(
  '/api/admin/orders/:id',
  requireAdmin,
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
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
        req.body?.orderStatus,
        30
      ).toUpperCase();

    const allowed = [

      'PENDING',

      'PROCESSING',

      'SHIPPED',

      'DELIVERED',

      'CANCELLED'

    ];

    if (!id) {

      return res
        .status(400)
        .json({
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

      return res
        .status(400)
        .json({
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

      if (
        !result.rowCount
      ) {

        return res
          .status(404)
          .json({
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
        'Update order error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to update order.'
        });

    }

  }
);

/* =========================================================
   CUSTOMER SIGNUP
========================================================= */

app.post(
  '/api/customer/signup',
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
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
        req.body?.password ||
        ''
      );

    if (
      !name ||
      !email ||
      !password
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Name, email and password are required.'
        });

    }

    if (
      !validEmail(email)
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Please provide a valid email address.'
        });

    }

    if (
      password.length < 6
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Password must contain at least 6 characters.'
        });

    }

    if (
      phone &&
      !validPhone(phone)
    ) {

      return res
        .status(400)
        .json({
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

      if (
        existing.rowCount
      ) {

        return res
          .status(409)
          .json({
            ok: false,
            message:
              'An account with this email already exists.'
          });

      }

      const passwordHash =
        await hashPassword(
          password
        );

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
            store_credit,
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
        createCustomerSession(
          customer.id
        );

      res
        .status(201)
        .json({

          ok: true,

          token,

          customer

        });

    } catch (error) {

      console.error(
        'Customer signup error:',
        error
      );

      res
        .status(500)
        .json({
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

      return res
        .status(503)
        .json({
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
        req.body?.password ||
        ''
      );

    if (
      !email ||
      !password
    ) {

      return res
        .status(400)
        .json({
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
            password_hash,
            store_credit,
            created_at
          FROM customers
          WHERE LOWER(email) =
            LOWER($1)
          LIMIT 1
          `,
          [email]
        );

      if (
        !result.rowCount
      ) {

        return res
          .status(401)
          .json({
            ok: false,
            message:
              'Invalid email or password.'
          });

      }

      const customer =
        result.rows[0];

      const valid =
        await verifyPassword(
          password,
          customer.password_hash
        );

      if (!valid) {

        return res
          .status(401)
          .json({
            ok: false,
            message:
              'Invalid email or password.'
          });

      }

      delete customer.password_hash;

      const token =
        createCustomerSession(
          customer.id
        );

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

      res
        .status(500)
        .json({
          ok: false,
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

    customerSessions.delete(
      req.customer.token
    );

    res.json({
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

      return res
        .status(503)
        .json({
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
            store_credit,
            created_at,
            updated_at
          FROM customers
          WHERE id = $1
          LIMIT 1
          `,
          [
            req.customer.customerId
          ]
        );

      if (
        !result.rowCount
      ) {

        return res
          .status(404)
          .json({
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
        'Customer profile error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to load customer profile.'
        });

    }

  }
);

/* =========================================================
   UPDATE CUSTOMER PROFILE
========================================================= */

app.put(
  '/api/customer/me',
  requireCustomer,
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
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

    const phone =
      cleanString(
        req.body?.phone,
        40
      );

    if (!name) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Name is required.'
        });

    }

    if (
      phone &&
      !validPhone(phone)
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Invalid phone number.'
        });

    }

    try {

      const result =
        await pool.query(
          `
          UPDATE customers
          SET
            name = $1,
            phone = $2,
            updated_at = NOW()
          WHERE id = $3
          RETURNING
            id,
            name,
            email,
            phone,
            store_credit,
            updated_at
          `,
          [
            name,
            phone,
            req.customer.customerId
          ]
        );

      res.json({

        ok: true,

        customer:
          result.rows[0]

      });

    } catch (error) {

      console.error(
        'Update profile error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to update profile.'
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

    if (!pool) {

      return res
        .status(503)
        .json({
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
            label,
            address,
            city,
            state,
            created_at
          FROM customer_addresses
          WHERE customer_id = $1
          ORDER BY created_at DESC
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
        'Addresses error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
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

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
        });

    }

    const label =
      cleanString(
        req.body?.label,
        100
      ) ||
      'Home';

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

    if (!address) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Delivery address is required.'
        });

    }

    try {

      const result =
        await pool.query(
          `
          INSERT INTO customer_addresses
          (
            customer_id,
            label,
            address,
            city,
            state
          )
          VALUES
          ($1,$2,$3,$4,$5)
          RETURNING *
          `,
          [
            req.customer.customerId,
            label,
            address,
            city,
            state
          ]
        );

      res
        .status(201)
        .json({

          ok: true,

          address:
            result.rows[0]

        });

    } catch (error) {

      console.error(
        'Save address error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to save address.'
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

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
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
          order =>
            order.id
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
          .push(item);

      }

      res.json({

        ok: true,

        orders:
          orders.map(
            order => ({

              ...order,

              total:
                Number(
                  order.total
                ),

              items:
                itemsByOrder.get(
                  order.id
                ) || []

            })
          )

      });

    } catch (error) {

      console.error(
        'Customer orders error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to load customer orders.'
        });

    }

  }
);

/* =========================================================
   STORE CREDIT
========================================================= */

app.get(
  '/api/customer/store-credit',
  requireCustomer,
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
        });

    }

    try {

      const customerResult =
        await pool.query(
          `
          SELECT
            store_credit
          FROM customers
          WHERE id = $1
          `,
          [
            req.customer.customerId
          ]
        );

      if (
        !customerResult.rowCount
      ) {

        return res
          .status(404)
          .json({
            ok: false,
            message:
              'Customer not found.'
          });

      }

      const transactionsResult =
        await pool.query(
          `
          SELECT
            id,
            type,
            amount,
            note,
            order_id,
            created_at
          FROM store_credit_transactions
          WHERE customer_id = $1
          ORDER BY created_at DESC
          LIMIT 100
          `,
          [
            req.customer.customerId
          ]
        );

      res.json({

        ok: true,

        balance:
          Number(
            customerResult
              .rows[0]
              .store_credit || 0
          ),

        transactions:
          transactionsResult.rows.map(
            tx => ({
              ...tx,
              amount:
                Number(
                  tx.amount
                )
            })
          )

      });

    } catch (error) {

      console.error(
        'Store credit error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to load store credit.'
        });

    }

  }
);

/* =========================================================
   STORE CREDIT CHECKOUT
========================================================= */

app.post(
  '/api/customer/store-credit/checkout',
  requireCustomer,
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
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

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Complete customer details are required.'
        });

    }

    if (
      !validEmail(email)
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Invalid email address.'
        });

    }

    if (!rawItems.length) {

      return res
        .status(400)
        .json({
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

      const productIds =
        rawItems
          .map(
            item =>
              positiveInteger(
                item.id
              )
          )
          .filter(Boolean);

      const productResult =
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
          [productIds]
        );

      const productMap =
        new Map(
          productResult.rows.map(
            product => [
              Number(
                product.id
              ),
              product
            ]
          )
        );

      const orderItems =
        [];

      let total =
        0;

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
            rawItem.qty
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
            'One of the products is unavailable.'
          );

        }

        if (
          Number(
            product.stock
          ) < quantity
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
          price * quantity;

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

      const customerResult =
        await client.query(
          `
          SELECT
            id,
            store_credit
          FROM customers
          WHERE id = $1
          FOR UPDATE
          `,
          [
            req.customer.customerId
          ]
        );

      if (
        !customerResult.rowCount
      ) {

        throw new Error(
          'Customer account not found.'
        );

      }

      const balance =
        Number(
          customerResult
            .rows[0]
            .store_credit || 0
        );

      if (
        balance < total
      ) {

        throw new Error(
          `Insufficient store credit. Available: ₦${balance.toLocaleString('en-NG')}`
        );

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
            $1,$2,$3,$4,$5,$6,
            'store_credit',
            'PAID',
            'PROCESSING',
            $7,
            'NGN'
          )
          RETURNING id, reference, total
          `,
          [
            reference,
            req.customer.customerId,
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

        await client.query(
          `
          UPDATE products
          SET
            stock = stock - $1,
            updated_at = NOW()
          WHERE id = $2
            AND stock >= $1
          `,
          [
            item.quantity,
            item.productId
          ]
        );

      }

      await client.query(
        `
        UPDATE customers
        SET
          store_credit =
            store_credit - $1,
          updated_at = NOW()
        WHERE id = $2
        `,
        [
          total,
          req.customer.customerId
        ]
      );

      await client.query(
        `
        INSERT INTO store_credit_transactions
        (
          customer_id,
          type,
          amount,
          note,
          order_id
        )
        VALUES
        (
          $1,
          'DEBIT',
          $2,
          $3,
          $4
        )
        `,
        [
          req.customer.customerId,
          total,
          'Store Credit payment',
          order.id
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({

        ok: true,

        reference,

        amount:
          total,

        payment_status:
          'PAID',

        order_status:
          'PROCESSING'

      });

    } catch (error) {

      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'Store credit checkout error:',
        error
      );

      res
        .status(400)
        .json({
          ok: false,
          message:
            error.message ||
            'Store credit checkout failed.'
        });

    } finally {

      client.release();

    }

  }
);

/* =========================================================
   REFUND HISTORY
========================================================= */

app.get(
  '/api/customer/refunds',
  requireCustomer,
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
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
            reference,
            amount,
            status,
            note,
            order_id,
            created_at,
            updated_at
          FROM refunds
          WHERE customer_id = $1
          ORDER BY created_at DESC
          `,
          [
            req.customer.customerId
          ]
        );

      res.json({

        ok: true,

        refunds:
          result.rows.map(
            refund => ({
              ...refund,
              amount:
                Number(
                  refund.amount
                )
            })
          )

      });

    } catch (error) {

      console.error(
        'Refund history error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to load refund history.'
        });

    }

  }
);

/* =========================================================
   CREATE MANUAL / BANK TRANSFER ORDER
========================================================= */

app.post(
  '/api/orders/manual',
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
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

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Complete customer details are required.'
        });

    }

    if (
      !validEmail(email)
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Invalid email address.'
        });

    }

    if (!rawItems.length) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Your cart is empty.'
        });

    }

    const customerSession =
      getCustomerSession(
        req
      );

    const customerId =
      customerSession
        ? customerSession.customerId
        : null;

    const client =
      await pool.connect();

    try {

      await client.query(
        'BEGIN'
      );

      const productIds =
        rawItems
          .map(
            item =>
              positiveInteger(
                item.id
              )
          )
          .filter(Boolean);

      const result =
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
          [productIds]
        );

      const productMap =
        new Map(
          result.rows.map(
            product => [
              Number(
                product.id
              ),
              product
            ]
          )
        );

      const orderItems =
        [];

      let total =
        0;

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
            rawItem.qty
          );

        if (
          !productId ||
          !quantity ||
          quantity > 99
        ) {

          throw new Error(
            'Invalid cart item.'
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
          Number(
            product.stock
          ) < quantity
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
          price * quantity;

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
            'bank_transfer',
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

      res.status(201).json({

        ok: true,

        reference,

        total,

        payment_method:
          'bank_transfer',

        payment_status:
          'PENDING',

        order_status:
          'PENDING',

        bank: {

          name:
            BANK_NAME,

          account_name:
            BANK_ACCOUNT_NAME,

          account_number:
            BANK_ACCOUNT_NUMBER

        },

        whatsapp:
          WHATSAPP_NUMBER

      });

    } catch (error) {

      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'Manual order error:',
        error
      );

      res
        .status(400)
        .json({
          ok: false,
          message:
            error.message ||
            'Unable to create order.'
        });

    } finally {

      client.release();

    }

  }
);

/* =========================================================
   ORDER TRACKING
========================================================= */

app.get(
  '/api/order-tracking/:reference',
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
        });

    }

    const reference =
      cleanString(
        req.params.reference,
        200
      );

    if (!reference) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Order reference is required.'
        });

    }

    try {

      const result =
        await pool.query(
          `
          SELECT
            reference,
            payment_method,
            payment_status,
            order_status,
            total,
            currency,
            created_at,
            updated_at
          FROM orders
          WHERE reference = $1
          LIMIT 1
          `,
          [reference]
        );

      if (
        !result.rowCount
      ) {

        return res
          .status(404)
          .json({
            ok: false,
            message:
              'Order not found.'
          });

      }

      const order =
        result.rows[0];

      res.json({

        ok: true,

        order: {

          ...order,

          total:
            Number(
              order.total
            )

        }

      });

    } catch (error) {

      console.error(
        'Tracking error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to track order.'
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

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
        });

    }

    if (!PAYSTACK_SECRET_KEY) {

      return res
        .status(503)
        .json({
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

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Complete customer details are required.'
        });

    }

    if (
      !validEmail(email)
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Please provide a valid email address.'
        });

    }

    if (
      !validPhone(phone)
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Please provide a valid phone number.'
        });

    }

    if (!rawItems.length) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Your cart is empty.'
        });

    }

    const customerSession =
      getCustomerSession(
        req
      );

    const customerId =
      customerSession
        ? customerSession.customerId
        : null;

    const client =
      await pool.connect();

    try {

      await client.query(
        'BEGIN'
      );

      const productIds =
        rawItems
          .map(
            item =>
              positiveInteger(
                item.id
              )
          )
          .filter(Boolean);

      if (
        !productIds.length
      ) {

        throw new Error(
          'Invalid cart items.'
        );

      }

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
          [productIds]
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

      const orderItems =
        [];

      let total =
        0;

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
            rawItem.qty
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
          Number(
            product.stock
          ) < quantity
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
          price * quantity;

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

      const amountInKobo =
        Math.round(
          total * 100
        );

      const callbackUrl =
        PAYSTACK_CALLBACK_URL ||
        (
          BASE_URL
            ? `${BASE_URL.replace(/\/$/, '')}/payment-success.html`
            : undefined
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

      if (callbackUrl) {

        paystackPayload.callback_url =
          callbackUrl;

      }

      const paystackResponse =
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

      const paystackData =
        await paystackResponse.json();

      if (
        !paystackResponse.ok ||
        !paystackData.status ||
        !paystackData.data?.authorization_url
      ) {

        console.error(
          'Paystack initialize error:',
          paystackData
        );

        return res
          .status(502)
          .json({
            ok: false,
            message:
              paystackData.message ||
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
          paystackData.data.reference ||
            reference,

          reference
        ]
      );

      res.json({

        ok: true,

        reference,

        authorization_url:
          paystackData
            .data
            .authorization_url

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

      res
        .status(400)
        .json({
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
   PAYSTACK VERIFY
========================================================= */

app.get(
  '/api/paystack/verify/:reference',
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
        });

    }

    if (!PAYSTACK_SECRET_KEY) {

      return res
        .status(503)
        .json({
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

      return res
        .status(400)
        .json({
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

        return res
          .status(502)
          .json({
            ok: false,
            message:
              data.message ||
              'Unable to verify payment.'
          });

      }

      const transaction =
        data.data;

      const orderResult =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE reference = $1
          LIMIT 1
          `,
          [reference]
        );

      if (
        !orderResult.rowCount
      ) {

        return res
          .status(404)
          .json({
            ok: false,
            message:
              'Order not found.'
          });

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

      const success =
        transaction.status ===
          'success' &&
        transaction.currency ===
          'NGN' &&
        expectedAmount ===
          paidAmount;

      if (!success) {

        await pool.query(
          `
          UPDATE orders
          SET
            payment_status = 'FAILED',
            updated_at = NOW()
          WHERE id = $1
            AND payment_status <> 'PAID'
          `,
          [order.id]
        );

        return res
          .status(400)
          .json({
            ok: false,
            paid: false,
            message:
              'Payment verification failed.'
          });

      }

      const client =
        await pool.connect();

      try {

        await client.query(
          'BEGIN'
        );

        const lockedResult =
          await client.query(
            `
            SELECT *
            FROM orders
            WHERE id = $1
            FOR UPDATE
            `,
            [order.id]
          );

        const lockedOrder =
          lockedResult.rows[0];

        if (!lockedOrder) {

          throw new Error(
            'Order not found.'
          );

        }

        /*
          IMPORTANT:
          Only deduct stock once.
        */

        if (
          lockedOrder.payment_status !==
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
              [order.id]
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
                  updated_at =
                    NOW()
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
            order_status = 'PROCESSING',
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

      res.json({

        ok: true,

        paid: true,

        reference,

        order_reference:
          order.reference,

        amount:
          Number(
            order.total
          ),

        customer_name:
          order.customer_name

      });

    } catch (error) {

      console.error(
        'Paystack verify error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            error.message ||
            'Payment verification error.'
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

    if (
      !PAYSTACK_SECRET_KEY ||
      !pool
    ) {

      return res.sendStatus(
        200
      );

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

      return res.sendStatus(
        401
      );

    }

    const hash =
      crypto
        .createHmac(
          'sha512',
          PAYSTACK_SECRET_KEY
        )
        .update(
          req.rawBody
        )
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

        return res.sendStatus(
          401
        );

      }

    } catch {

      return res.sendStatus(
        401
      );

    }

    try {

      const event =
        req.body;

      if (
        event?.event !==
        'charge.success'
      ) {

        return res.sendStatus(
          200
        );

      }

      const transaction =
        event.data ||
        {};

      const reference =
        cleanString(
          transaction.reference,
          200
        );

      if (!reference) {

        return res.sendStatus(
          200
        );

      }

      const orderResult =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE reference = $1
          LIMIT 1
          `,
          [reference]
        );

      if (
        !orderResult.rowCount
      ) {

        return res.sendStatus(
          200
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

      if (
        transaction.status !==
          'success' ||
        transaction.currency !==
          'NGN' ||
        Number(
          transaction.amount
        ) !== expectedAmount
      ) {

        return res.sendStatus(
          200
        );

      }

      const client =
        await pool.connect();

      try {

        await client.query(
          'BEGIN'
        );

        const locked =
          await client.query(
            `
            SELECT *
            FROM orders
            WHERE id = $1
            FOR UPDATE
            `,
            [order.id]
          );

        const lockedOrder =
          locked.rows[0];

        if (!lockedOrder) {

          throw new Error(
            'Order not found.'
          );

        }

        /*
          Do not deduct stock twice.
        */

        if (
          lockedOrder.payment_status !==
          'PAID'
        ) {

          const items =
            await client.query(
              `
              SELECT *
              FROM order_items
              WHERE order_id = $1
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
                  stock =
                    stock - $1,
                  updated_at =
                    NOW()
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
              !stock.rowCount
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
            order_status = 'PROCESSING',
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

      } catch (error) {

        try {

          await client.query(
            'ROLLBACK'
          );

        } catch {}

        console.error(
          'Webhook transaction error:',
          error
        );

      } finally {

        client.release();

      }

      return res.sendStatus(
        200
      );

    } catch (error) {

      console.error(
        'Webhook error:',
        error
      );

      return res.sendStatus(
        200
      );

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

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
        });

    }

    try {

      const result =
        await pool.query(`
          SELECT *
          FROM store_settings
          WHERE id = 1
        `);

      res.json({

        ok: true,

        settings:
          result.rows[0] ||
          {}

      });

    } catch (error) {

      console.error(
        'Admin settings error:',
        error
      );

      res
        .status(500)
        .json({
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

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
        });

    }

    const storeName =
      cleanString(
        req.body?.store_name,
        200
      );

    const tagline =
      cleanString(
        req.body?.tagline,
        200
      );

    const heroTitle =
      cleanString(
        req.body?.hero_title,
        300
      );

    const heroText =
      cleanString(
        req.body?.hero_text,
        1000
      );

    const primaryColor =
      cleanString(
        req.body?.primary_color,
        30
      );

    const secondaryColor =
      cleanString(
        req.body?.secondary_color,
        30
      );

    const goldColor =
      cleanString(
        req.body?.gold_color,
        30
      );

    const backgroundColor =
      cleanString(
        req.body?.background_color,
        30
      );

    const textColor =
      cleanString(
        req.body?.text_color,
        30
      );

    const whatsapp =
      cleanString(
        req.body?.whatsapp,
        30
      );

    try {

      const result =
        await pool.query(
          `
          UPDATE store_settings
          SET
            store_name =
              COALESCE(
                NULLIF($1,''),
                store_name
              ),

            tagline =
              COALESCE(
                NULLIF($2,''),
                tagline
              ),

            hero_title =
              COALESCE(
                NULLIF($3,''),
                hero_title
              ),

            hero_text =
              COALESCE(
                NULLIF($4,''),
                hero_text
              ),

            primary_color =
              COALESCE(
                NULLIF($5,''),
                primary_color
              ),

            secondary_color =
              COALESCE(
                NULLIF($6,''),
                secondary_color
              ),

            gold_color =
              COALESCE(
                NULLIF($7,''),
                gold_color
              ),

            background_color =
              COALESCE(
                NULLIF($8,''),
                background_color
              ),

            text_color =
              COALESCE(
                NULLIF($9,''),
                text_color
              ),

            whatsapp =
              COALESCE(
                NULLIF($10,''),
                whatsapp
              ),

            updated_at =
              NOW()

          WHERE id = 1

          RETURNING *
          `,
          [
            storeName,
            tagline,
            heroTitle,
            heroText,
            primaryColor,
            secondaryColor,
            goldColor,
            backgroundColor,
            textColor,
            whatsapp
          ]
        );

      res.json({

        ok: true,

        settings:
          result.rows[0]

      });

    } catch (error) {

      console.error(
        'Update settings error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to update settings.'
        });

    }

  }
);

/* =========================================================
   ADMIN CUSTOMERS
========================================================= */

app.get(
  '/api/admin/customers',
  requireAdmin,
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
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
            email,
            phone,
            store_credit,
            created_at,
            updated_at
          FROM customers
          ORDER BY created_at DESC
        `);

      res.json({

        ok: true,

        customers:
          result.rows.map(
            customer => ({

              ...customer,

              store_credit:
                Number(
                  customer.store_credit ||
                  0
                )

            })
          )

      });

    } catch (error) {

      console.error(
        'Admin customers error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to load customers.'
        });

    }

  }
);

/* =========================================================
   ADMIN ADD STORE CREDIT
========================================================= */

app.post(
  '/api/admin/customers/:id/store-credit',
  requireAdmin,
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
        });

    }

    const customerId =
      positiveInteger(
        req.params.id
      );

    const amount =
      positivePrice(
        req.body?.amount
      );

    const note =
      cleanString(
        req.body?.note,
        500
      ) ||
      'Admin store credit';

    if (
      !customerId ||
      amount === null ||
      amount <= 0
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Valid customer and credit amount are required.'
        });

    }

    const client =
      await pool.connect();

    try {

      await client.query(
        'BEGIN'
      );

      const result =
        await client.query(
          `
          UPDATE customers
          SET
            store_credit =
              store_credit + $1,
            updated_at =
              NOW()
          WHERE id = $2
          RETURNING
            id,
            name,
            email,
            store_credit
          `,
          [
            amount,
            customerId
          ]
        );

      if (
        !result.rowCount
      ) {

        throw new Error(
          'Customer not found.'
        );

      }

      await client.query(
        `
        INSERT INTO store_credit_transactions
        (
          customer_id,
          type,
          amount,
          note
        )
        VALUES
        (
          $1,
          'CREDIT',
          $2,
          $3
        )
        `,
        [
          customerId,
          amount,
          note
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({

        ok: true,

        customer:
          result.rows[0]

      });

    } catch (error) {

      try {

        await client.query(
          'ROLLBACK'
        );

      } catch {}

      console.error(
        'Add credit error:',
        error
      );

      res
        .status(400)
        .json({
          ok: false,
          message:
            error.message ||
            'Unable to add store credit.'
        });

    } finally {

      client.release();

    }

  }
);

/* =========================================================
   ADMIN REFUNDS
========================================================= */

app.post(
  '/api/admin/refunds',
  requireAdmin,
  async (req, res) => {

    if (!pool) {

      return res
        .status(503)
        .json({
          ok: false,
          message:
            'Database is not configured.'
        });

    }

    const orderId =
      positiveInteger(
        req.body?.order_id
      );

    const amount =
      positivePrice(
        req.body?.amount
      );

    const note =
      cleanString(
        req.body?.note,
        500
      );

    if (
      !orderId ||
      amount === null ||
      amount <= 0
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          message:
            'Valid order and refund amount are required.'
        });

    }

    try {

      const orderResult =
        await pool.query(
          `
          SELECT
            id,
            customer_id,
            reference,
            total
          FROM orders
          WHERE id = $1
          LIMIT 1
          `,
          [orderId]
        );

      if (
        !orderResult.rowCount
      ) {

        return res
          .status(404)
          .json({
            ok: false,
            message:
              'Order not found.'
          });

      }

      const order =
        orderResult.rows[0];

      if (
        amount >
        Number(
          order.total
        )
      ) {

        return res
          .status(400)
          .json({
            ok: false,
            message:
              'Refund amount cannot exceed order total.'
          });

      }

      const reference =
        'RF-' +
        Date.now()
          .toString(36)
          .toUpperCase() +
        '-' +
        crypto
          .randomBytes(3)
          .toString('hex')
          .toUpperCase();

      const result =
        await pool.query(
          `
          INSERT INTO refunds
          (
            customer_id,
            order_id,
            reference,
            amount,
            status,
            note
          )
          VALUES
          (
            $1,$2,$3,$4,
            'PENDING',
            $5
          )
          RETURNING *
          `,
          [
            order.customer_id,
            order.id,
            reference,
            amount,
            note
          ]
        );

      res
        .status(201)
        .json({

          ok: true,

          refund:
            result.rows[0]

        });

    } catch (error) {

      console.error(
        'Refund creation error:',
        error
      );

      res
        .status(500)
        .json({
          ok: false,
          message:
            'Unable to create refund.'
        });

    }

  }
);

/* =========================================================
   WHATSAPP
========================================================= */

app.get(
  '/api/whatsapp',
  (req, res) => {

    res.json({

      ok: true,

      whatsapp:
        WHATSAPP_NUMBER,

      url:
        `https://wa.me/${String(
          WHATSAPP_NUMBER
        ).replace(
          /[^0-9]/g,
          ''
        )}`

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
  '/admin.html',
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

    const file =
      path.join(
        __dirname,
        'public',
        'payment-success.html'
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

    res
      .status(404)
      .json({

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

      return next(
        error
      );

    }

    res
      .status(500)
      .json({

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
          '======================================'
        );

        console.log(
          'FACE OF STYLE HIJAB FACTORY'
        );

        console.log(
          `Server running on port ${PORT}`
        );

        console.log(
          `Database configured: ${Boolean(
            pool
          )}`
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
          `WhatsApp: ${WHATSAPP_NUMBER}`
        );

        console.log(
          '======================================'
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
