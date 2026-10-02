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
  process.env.ADMIN_USERNAME ||
  process.env.ADMIN_USER ||
  '';

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
    limit: '12mb',
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
   SESSION STORAGE
========================================================= */

const adminSessions = new Map();
const customerSessions = new Map();

const SESSION_MAX_AGE =
  1000 * 60 * 60 * 24 * 30;

/* =========================================================
   GENERAL HELPERS
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
   DATABASE INITIALIZATION
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

  console.log(
    'Face of Style Version 2 database ready.'
  );
}
    if (price === null) {
      return res.status(400).json({
        ok: false,
        message:
          'Valid product price is required.'
      });
    }

    if (stock === null) {
      return res.status(400).json({
        ok: false,
        message:
          'Valid product stock is required.'
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
            stock
          ]
        );

      const p = result.rows[0];

      const product = {
        ...p,
        id: Number(p.id),
        price: Number(p.price),
        stock: Number(p.stock),
        img: normalizeImage(p.image),
        image: normalizeImage(p.image)
      };

      res.status(201).json({
        ok: true,
        message:
          'Product added successfully.',
        product
      });
    } catch (error) {
      console.error(
        'Admin add product error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to add product.'
      });
    }
  }
);

/* =========================================================
   ADMIN UPDATE PRODUCT
========================================================= */

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
        req.body?.stock ?? 0
      );

    const imageProvided =
      Object.prototype.hasOwnProperty.call(
        req.body || {},
        'image'
      ) ||
      Object.prototype.hasOwnProperty.call(
        req.body || {},
        'img'
      );

    const incomingImage =
      cleanString(
        req.body?.image ||
        req.body?.img,
        2500000
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

    if (stock === null) {
      return res.status(400).json({
        ok: false,
        message:
          'Valid product stock is required.'
      });
    }

    try {
      let result;

      /*
        IMPORTANT:
        If admin updates product details without
        selecting a new image, the old image is preserved.
      */

      if (
        imageProvided &&
        incomingImage
      ) {
        result =
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
              incomingImage,
              stock,
              id
            ]
          );
      } else {
        result =
          await pool.query(
            `
            UPDATE products
            SET
              name=$1,
              category=$2,
              description=$3,
              price=$4,
              color=$5,
              stock=$6,
              updated_at=NOW()
            WHERE id=$7
            RETURNING *
            `,
            [
              name,
              category,
              description,
              price,
              color,
              stock,
              id
            ]
          );
      }

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Product not found.'
        });
      }

      const p = result.rows[0];

      const product = {
        ...p,
        id: Number(p.id),
        price: Number(p.price),
        stock: Number(p.stock),
        img: normalizeImage(p.image),
        image: normalizeImage(p.image)
      };

      res.json({
        ok: true,
        message:
          'Product updated successfully.',
        product
      });
    } catch (error) {
      console.error(
        'Admin update product error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to update product.'
      });
    }
  }
);

/* =========================================================
   ADMIN DELETE PRODUCT
========================================================= */

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
          'Product removed successfully.'
      });
    } catch (error) {
      console.error(
        'Delete product error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to delete product.'
      });
    }
  }
);

/* =========================================================
   ADMIN RESTORE PRODUCT
========================================================= */

app.post(
  '/api/admin/products/:id/restore',
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
      const result =
        await pool.query(
          `
          UPDATE products
          SET
            active=TRUE,
            updated_at=NOW()
          WHERE id=$1
          RETURNING *
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

      const p = result.rows[0];

      res.json({
        ok: true,
        product: {
          ...p,
          id: Number(p.id),
          price: Number(p.price),
          stock: Number(p.stock),
          img: normalizeImage(p.image),
          image: normalizeImage(p.image)
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to restore product.'
      });
    }
  }
);

/* =========================================================
   ADMIN SETTINGS GET
========================================================= */

app.get(
  '/api/admin/settings',
  requireAdmin,
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
          FROM store_settings
          WHERE id=1
          LIMIT 1
          `
        );

      let settings =
        result.rows[0] || {};

      settings = {
        ...settings,
        delivery_fee:
          Number(
            settings.delivery_fee || 0
          ),
        free_delivery_from:
          Number(
            settings.free_delivery_from || 0
          ),
        low_stock_limit:
          Number(
            settings.low_stock_limit || 5
          ),
        enable_cart:
          settings.enable_cart !== false,
        enable_whatsapp:
          settings.enable_whatsapp !== false,
        show_stock:
          settings.show_stock !== false,
        logo:
          normalizeImage(
            settings.logo
          ),
        hero_image:
          normalizeImage(
            settings.hero_image
          )
      };

      res.json({
        ok: true,
        settings,
        paystackConfigured:
          Boolean(
            PAYSTACK_SECRET_KEY
          )
      });
    } catch (error) {
      console.error(
        'Admin settings GET error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to load store settings.'
      });
    }
  }
);

/* =========================================================
   PUBLIC SETTINGS
========================================================= */

app.get(
  '/api/settings',
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        settings: {},
        message:
          'Database is not configured.'
      });
    }

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

      const settings =
        result.rows[0] || {};

      res.json({
        ok: true,
        settings: {
          ...settings,
          delivery_fee:
            Number(
              settings.delivery_fee || 0
            ),
          free_delivery_from:
            Number(
              settings.free_delivery_from || 0
            ),
          low_stock_limit:
            Number(
              settings.low_stock_limit || 5
            ),
          logo:
            normalizeImage(
              settings.logo
            ),
          hero_image:
            normalizeImage(
              settings.hero_image
            )
        }
      });
    } catch (error) {
      console.error(
        'Public settings error:',
        error
      );

      res.status(500).json({
        ok: false,
        settings: {},
        message:
          'Unable to load store settings.'
      });
    }
  }
);

/* =========================================================
   ADMIN SETTINGS UPDATE
========================================================= */

app.put(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {
    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
      });
    }

    const allowedFields = [
      'store_name',
      'tagline',
      'whatsapp',
      'phone',
      'email',
      'address',
      'hero_title',
      'hero_text',
      'about_text',
      'delivery_text',
      'delivery_fee',
      'free_delivery_from',
      'bank_name',
      'account_name',
      'account_number',
      'bank_instructions',
      'logo',
      'hero_image',
      'primary_color',
      'secondary_color',
      'gold_color',
      'background_color',
      'text_color',
      'low_stock_limit',
      'enable_cart',
      'enable_whatsapp',
      'show_stock'
    ];

    const body =
      req.body || {};

    const values = {};

    for (
      const field of allowedFields
    ) {
      if (
        Object.prototype.hasOwnProperty.call(
          body,
          field
        )
      ) {
        values[field] =
          body[field];
      }
    }

    if (
      values.store_name !== undefined
    ) {
      values.store_name =
        cleanString(
          values.store_name,
          200
        );
    }

    if (
      values.tagline !== undefined
    ) {
      values.tagline =
        cleanString(
          values.tagline,
          200
        );
    }

    if (
      values.whatsapp !== undefined
    ) {
      values.whatsapp =
        cleanString(
          values.whatsapp,
          50
        );
    }

    if (
      values.phone !== undefined
    ) {
      values.phone =
        cleanString(
          values.phone,
          50
        );
    }

    if (
      values.email !== undefined
    ) {
      values.email =
        cleanString(
          values.email,
          200
        );
    }

    if (
      values.address !== undefined
    ) {
      values.address =
        cleanString(
          values.address,
          1000
        );
    }

    if (
      values.hero_title !== undefined
    ) {
      values.hero_title =
        cleanString(
          values.hero_title,
          500
        );
    }

    if (
      values.hero_text !== undefined
    ) {
      values.hero_text =
        cleanString(
          values.hero_text,
          5000
        );
    }

    if (
      values.about_text !== undefined
    ) {
      values.about_text =
        cleanString(
          values.about_text,
          10000
        );
    }

    if (
      values.delivery_text !== undefined
    ) {
      values.delivery_text =
        cleanString(
          values.delivery_text,
          5000
        );
    }

    if (
      values.bank_name !== undefined
    ) {
      values.bank_name =
        cleanString(
          values.bank_name,
          200
        );
    }

    if (
      values.account_name !== undefined
    ) {
      values.account_name =
        cleanString(
          values.account_name,
          200
        );
    }

    if (
      values.account_number !== undefined
    ) {
      values.account_number =
        cleanString(
          values.account_number,
          100
        );
    }

    if (
      values.bank_instructions !== undefined
    ) {
      values.bank_instructions =
        cleanString(
          values.bank_instructions,
          5000
        );
    }

    if (
      values.logo !== undefined
    ) {
      values.logo =
        cleanString(
          values.logo,
          2500000
        );
    }

    if (
      values.hero_image !== undefined
    ) {
      values.hero_image =
        cleanString(
          values.hero_image,
          2500000
        );
    }

    if (
      values.primary_color !== undefined
    ) {
      values.primary_color =
        cleanString(
          values.primary_color,
          30
        );
    }

    if (
      values.secondary_color !== undefined
    ) {
      values.secondary_color =
        cleanString(
          values.secondary_color,
          30
        );
    }

    if (
      values.gold_color !== undefined
    ) {
      values.gold_color =
        cleanString(
          values.gold_color,
          30
        );
    }

    if (
      values.background_color !== undefined
    ) {
      values.background_color =
        cleanString(
          values.background_color,
          30
        );
    }

    if (
      values.text_color !== undefined
    ) {
      values.text_color =
        cleanString(
          values.text_color,
          30
        );
    }

    if (
      values.delivery_fee !== undefined
    ) {
      const n =
        positivePrice(
          values.delivery_fee
        );

      if (n === null) {
        return res.status(400).json({
          ok: false,
          message:
            'Invalid delivery fee.'
        });
      }

      values.delivery_fee = n;
    }

    if (
      values.free_delivery_from !== undefined
    ) {
      const n =
        positivePrice(
          values.free_delivery_from
        );

      if (n === null) {
        return res.status(400).json({
          ok: false,
          message:
            'Invalid free delivery amount.'
        });
      }

      values.free_delivery_from = n;
    }

    if (
      values.low_stock_limit !== undefined
    ) {
      const n =
        nonNegativeInteger(
          values.low_stock_limit
        );

      if (n === null) {
        return res.status(400).json({
          ok: false,
          message:
            'Invalid low stock limit.'
        });
      }

      values.low_stock_limit = n;
    }

    if (
      values.enable_cart !== undefined
    ) {
      values.enable_cart =
        Boolean(
          values.enable_cart
        );
    }

    if (
      values.enable_whatsapp !== undefined
    ) {
      values.enable_whatsapp =
        Boolean(
          values.enable_whatsapp
        );
    }

    if (
      values.show_stock !== undefined
    ) {
      values.show_stock =
        Boolean(
          values.show_stock
        );
    }

    const fields =
      Object.keys(values);

    if (!fields.length) {
      return res.status(400).json({
        ok: false,
        message:
          'No settings were supplied.'
      });
    }

    try {
      const setParts = [];
      const params = [];

      let index = 1;

      for (
        const field of fields
      ) {
        setParts.push(
          `${field}=$${index}`
        );

        params.push(
          values[field]
        );

        index++;
      }

      setParts.push(
        `updated_at=NOW()`
      );

      params.push(1);

      const result =
        await pool.query(
          `
          UPDATE store_settings
          SET
            ${setParts.join(', ')}
          WHERE id=$${index}
          RETURNING *
          `,
          params
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Store settings record not found.'
        });
      }

      res.json({
        ok: true,
        message:
          'Store settings updated successfully.',
        settings:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Admin settings update error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to save store settings.'
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
   CREATE ORDER
========================================================= */

app.post(
  '/api/orders',
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

    const items =
      Array.isArray(body.items)
        ? body.items
        : [];

    if (!items.length) {
      return res.status(400).json({
        ok: false,
        message:
          'Your cart is empty.'
      });
    }

    const customerName =
      cleanString(
        body.customerName ||
        body.name,
        150
      );

    const customerEmail =
      cleanString(
        body.customerEmail ||
        body.email,
        200
      ).toLowerCase();

    const customerPhone =
      cleanString(
        body.customerPhone ||
        body.phone,
        50
      );

    const deliveryAddress =
      cleanString(
        body.deliveryAddress ||
        body.address,
        1500
      );

    if (
      !customerName ||
      !validEmail(customerEmail) ||
      !validPhone(customerPhone) ||
      !deliveryAddress
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Complete customer and delivery information is required.'
      });
    }

    const productIds = [];

    for (
      const item of items
    ) {
      const id =
        positiveInteger(
          item.productId ||
          item.id
        );

      const quantity =
        positiveInteger(
          item.quantity ||
          item.qty
        );

      if (!id || !quantity) {
        return res.status(400).json({
          ok: false,
          message:
            'Invalid cart item.'
        });
      }

      productIds.push(id);
    }

    const uniqueIds =
      [...new Set(productIds)];

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const result =
        await client.query(
          `
          SELECT
            id,
            name,
            price,
            stock,
            active,
            image
          FROM products
          WHERE id = ANY($1::int[])
          FOR UPDATE
          `,
          [uniqueIds]
        );

      const productMap =
        new Map(
          result.rows.map(
            p => [
              Number(p.id),
              p
            ]
          )
        );

      let total = 0;
      const orderItems = [];

      for (
        const item of items
      ) {
        const id =
          positiveInteger(
            item.productId ||
            item.id
          );

        const quantity =
          positiveInteger(
            item.quantity ||
            item.qty
          );

        const product =
          productMap.get(id);

        if (
          !product ||
          !product.active
        ) {
          throw new Error(
            `Product ${id} is unavailable.`
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
          price * quantity;

        total += subtotal;

        orderItems.push({
          product,
          quantity,
          price,
          subtotal
        });
      }

      total =
        Math.round(
          total * 100
        ) / 100;

      const reference =
        createOrderReference();

      let customerId = null;

      const session =
        await getCustomerSession(req);

      if (session) {
        customerId =
          session.customerId;
      }

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
          RETURNING *
          `,
          [
            reference,
            customerId,
            customerName,
            customerEmail,
            customerPhone,
            deliveryAddress,
            total
          ]
        );

      const order =
        orderResult.rows[0];

      for (
        const item of orderItems
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
            item.product.id,
            item.product.name,
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
        order: {
          id:
            Number(order.id),
          reference:
            order.reference,
          total:
            Number(order.total),
          currency:
            order.currency,
          paymentStatus:
            order.payment_status,
          orderStatus:
            order.order_status
        }
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Create order error:',
        error
      );

      res.status(400).json({
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
          'Paystack is not configured.'
      });
    }

    const reference =
      cleanString(
        req.body?.reference,
        150
      );

    if (!reference) {
      return res.status(400).json({
        ok: false,
        message:
          'Order reference is required.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE reference=$1
          LIMIT 1
          `,
          [reference]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Order not found.'
        });
      }

      const order =
        result.rows[0];

      if (
        String(
          order.payment_status
        ).toUpperCase() ===
        'PAID'
      ) {
        return res.status(400).json({
          ok: false,
          message:
            'This order has already been paid.'
        });
      }

      const amount =
        Math.round(
          Number(order.total) * 100
        );

      const callback =
        PAYSTACK_CALLBACK_URL ||
        `${req.protocol}://${req.get('host')}/api/paystack/callback`;

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
                  order.customer_email,
                amount,
                currency: 'NGN',
                reference:
                  order.reference,
                callback_url:
                  callback,
                metadata: {
                  order_reference:
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
        WHERE id=$2
        `,
        [
          data.data.reference,
          order.id
        ]
      );

      res.json({
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

      res.status(500).json({
        ok: false,
        message:
          'Unable to initialize payment.'
      });
    }
  }
);

/* =========================================================
   PAYSTACK VERIFY
========================================================= */

async function verifyPaystackReference(
  reference
) {
  if (!PAYSTACK_SECRET_KEY) {
    return {
      ok: false,
      message:
        'Paystack is not configured.'
    };
  }

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
    !data.status
  ) {
    return {
      ok: false,
      message:
        data.message ||
        'Paystack verification failed.',
      data
    };
  }

  const tx =
    data.data;

  return {
    ok: true,
    transaction: tx
  };
}

async function completePaidOrder(
  reference,
  transaction
) {
  if (!pool) {
    return {
      ok: false,
      message:
        'Database is not configured.'
    };
  }

  const result =
    await pool.query(
      `
      SELECT *
      FROM orders
      WHERE reference=$1
         OR paystack_reference=$1
      LIMIT 1
      `,
      [reference]
    );

  if (!result.rowCount) {
    return {
      ok: false,
      message:
        'Order not found.'
    };
  }

  const order =
    result.rows[0];

  const expectedAmount =
    Math.round(
      Number(order.total) * 100
    );

  const paidAmount =
    Number(
      transaction?.amount || 0
    );

  const currency =
    String(
      transaction?.currency || ''
    ).toUpperCase();

  const status =
    String(
      transaction?.status || ''
    ).toLowerCase();

  if (
    status !== 'success' ||
    paidAmount !== expectedAmount ||
    currency !== 'NGN'
  ) {
    await pool.query(
      `
      UPDATE orders
      SET
        payment_status=
          CASE
            WHEN $1='failed'
            THEN 'FAILED'
            ELSE payment_status
          END,
        updated_at=NOW()
      WHERE id=$2
      `,
      [
        status,
        order.id
      ]
    );

    return {
      ok: false,
      message:
        'Payment has not been verified as successful.'
    };
  }

  /*
    If already paid, do not reduce stock again.
  */
  if (
    String(
      order.payment_status
    ).toUpperCase() ===
    'PAID'
  ) {
    return {
      ok: true,
      alreadyPaid: true,
      orderId:
        Number(order.id),
      reference:
        order.reference
    };
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
        WHERE id=$1
        FOR UPDATE
        `,
        [order.id]
      );

    if (!locked.rowCount) {
      throw new Error(
        'Order disappeared during payment completion.'
      );
    }

    const current =
      locked.rows[0];

    if (
      String(
        current.payment_status
      ).toUpperCase() ===
      'PAID'
    ) {
      await client.query(
        'COMMIT'
      );

      return {
        ok: true,
        alreadyPaid: true,
        orderId:
          Number(current.id),
        reference:
          current.reference
      };
    }

    const items =
      await client.query(
        `
        SELECT
          product_id,
          quantity
        FROM order_items
        WHERE order_id=$1
        `,
        [current.id]
      );

    /*
      Check all stock before reducing anything.
    */
    for (
      const item of items.rows
    ) {
      const stockResult =
        await client.query(
          `
          SELECT
            id,
            stock,
            name
          FROM products
          WHERE id=$1
          FOR UPDATE
          `,
          [item.product_id]
        );

      if (!stockResult.rowCount) {
        throw new Error(
          `Product ${item.product_id} no longer exists.`
        );
      }

      const product =
        stockResult.rows[0];

      if (
        Number(product.stock) <
        Number(item.quantity)
      ) {
        throw new Error(
          `${product.name} no longer has enough stock.`
        );
      }
    }

    /*
      Reduce stock exactly once.
    */
    for (
      const item of items.rows
    ) {
      await client.query(
        `
        UPDATE products
        SET
          stock=stock-$1,
          updated_at=NOW()
        WHERE id=$2
        `,
        [
          Number(item.quantity),
          item.product_id
        ]
      );
    }

    await client.query(
      `
      UPDATE orders
      SET
        payment_status='PAID',
        order_status='PROCESSING',
        paystack_reference=$1,
        updated_at=NOW()
      WHERE id=$2
      `,
      [
        transaction.reference ||
          reference,
        current.id
      ]
    );

    await client.query(
      'COMMIT'
    );

    return {
      ok: true,
      alreadyPaid: false,
      orderId:
        Number(current.id),
      reference:
        current.reference
    };
  } catch (error) {
    await client.query(
      'ROLLBACK'
    );

    console.error(
      'Complete paid order error:',
      error
    );

    return {
      ok: false,
      message:
        error.message ||
        'Unable to complete paid order.'
    };
  } finally {
    client.release();
  }
}

/* =========================================================
   PAYSTACK VERIFY ENDPOINT
========================================================= */

app.get(
  '/api/paystack/verify/:reference',
  async (req, res) => {
    const reference =
      cleanString(
        req.params.reference,
        150
      );

    if (!reference) {
      return res.status(400).json({
        ok: false,
        message:
          'Payment reference is required.'
      });
    }

    try {
      const verification =
        await verifyPaystackReference(
          reference
        );

      if (!verification.ok) {
        return res.status(502).json(
          verification
        );
      }

      const completed =
        await completePaidOrder(
          reference,
          verification.transaction
        );

      res.json({
        ok:
          completed.ok,
        paid:
          completed.ok,
        reference,
        transaction:
          verification.transaction,
        order:
          completed
      });
    } catch (error) {
      console.error(
        'Paystack verify endpoint error:',
        error
      );

      res.status(500).json({
        ok: false,
        paid: false,
        message:
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
        150
      );

    if (!reference) {
      return res.redirect(
        '/?payment=missing'
      );
    }

    try {
      const verification =
        await verifyPaystackReference(
          reference
        );

      if (
        !verification.ok
      ) {
        return res.redirect(
          `/?payment=failed&reference=${encodeURIComponent(reference)}`
        );
      }

      const completed =
        await completePaidOrder(
          reference,
          verification.transaction
        );

      if (completed.ok) {
        return res.redirect(
          `/?payment=success&reference=${encodeURIComponent(reference)}`
        );
      }

      return res.redirect(
        `/?payment=pending&reference=${encodeURIComponent(reference)}`
      );
    } catch (error) {
      console.error(
        'Paystack callback error:',
        error
      );

      return res.redirect(
        `/?payment=error&reference=${encodeURIComponent(reference)}`
      );
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
        return res.sendStatus(
          401
        );
      }

      const expected =
        crypto
          .createHmac(
            'sha512',
            PAYSTACK_SECRET_KEY
          )
          .update(
            req.rawBody
          )
          .digest('hex');

      const a =
        Buffer.from(
          String(signature)
        );

      const b =
        Buffer.from(
          expected
        );

      if (
        a.length !== b.length ||
        !crypto.timingSafeEqual(
          a,
          b
        )
      ) {
        return res.sendStatus(
          401
        );
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
          tx?.reference
        ) {
          await completePaidOrder(
            tx.reference,
            tx
          );
        }
      }

      return res.sendStatus(
        200
      );
    } catch (error) {
      console.error(
        'Paystack webhook error:',
        error
      );

      return res.sendStatus(
        500
      );
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
      return res.status(503).json({
        ok: false,
        orders: [],
        message:
          'Database is not configured.'
      });
    }

    try {
      const result =
        await pool.query(`
          SELECT
            o.*,
            COALESCE(
              json_agg(
                json_build_object(
                  'id', oi.id,
                  'productId', oi.product_id,
                  'productName', oi.product_name,
                  'price', oi.price,
                  'quantity', oi.quantity,
                  'qty', oi.quantity,
                  'subtotal', oi.subtotal
                )
                ORDER BY oi.id
              )
              FILTER (
                WHERE oi.id IS NOT NULL
              ),
              '[]'
            ) AS items
          FROM orders o
          LEFT JOIN order_items oi
            ON oi.order_id=o.id
          GROUP BY o.id
          ORDER BY o.created_at DESC
        `);

      const orders =
        result.rows.map(
          order => ({
            ...order,
            id:
              Number(order.id),
            total:
              Number(order.total),
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
              Array.isArray(
                order.items
              )
                ? order.items.map(
                    item => ({
                      ...item,
                      price:
                        Number(
                          item.price
                        ),
                      quantity:
                        Number(
                          item.quantity
                        ),
                      qty:
                        Number(
                          item.qty
                        ),
                      subtotal:
                        Number(
                          item.subtotal
                        )
                    })
                  )
                : []
          })
        );

      res.json({
        ok: true,
        orders,
        data: orders,
        count:
          orders.length
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
      const result =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE id=$1
          LIMIT 1
          `,
          [id]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Order not found.'
        });
      }

      const items =
        await pool.query(
          `
          SELECT *
          FROM order_items
          WHERE order_id=$1
          ORDER BY id ASC
          `,
          [id]
        );

      const order =
        result.rows[0];

      res.json({
        ok: true,
        order: {
          ...order,
          id:
            Number(order.id),
          total:
            Number(order.total),
          items:
            items.rows.map(
              item => ({
                ...item,
                price:
                  Number(
                    item.price
                  ),
                quantity:
                  Number(
                    item.quantity
                  ),
                qty:
                  Number(
                    item.quantity
                  ),
                subtotal:
                  Number(
                    item.subtotal
                  )
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
   ADMIN UPDATE ORDER STATUS
========================================================= */

app.put(
  '/api/admin/orders/:id/status',
  requireAdmin,
  async (req, res) => {
    const id =
      positiveInteger(
        req.params.id
      );

    const status =
      cleanString(
        req.body?.status,
        50
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

    if (
      !allowed.includes(
        status
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
            order_status=$1,
            updated_at=NOW()
          WHERE id=$2
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
        message:
          'Order status updated.',
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
   ADMIN CUSTOMERS
========================================================= */

app.get(
  '/api/admin/customers',
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            c.id,
            c.name,
            c.email,
            c.phone,
            c.created_at,
            COUNT(o.id)::int
              AS orders_count,
            COALESCE(
              SUM(
                CASE
                  WHEN o.payment_status='PAID'
                  THEN o.total
                  ELSE 0
                END
              ),
              0
            )::numeric
              AS total_spent
          FROM customers c
          LEFT JOIN orders o
            ON o.customer_id=c.id
          GROUP BY c.id
          ORDER BY c.created_at DESC
        `);

      const customers =
        result.rows.map(
          customer => ({
            ...customer,
            id:
              Number(customer.id),
            orders_count:
              Number(
                customer.orders_count
              ),
            total_spent:
              Number(
                customer.total_spent
              )
          })
        );

      res.json({
        ok: true,
        customers
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        customers: [],
        message:
          'Unable to load customers.'
      });
    }
  }
);

/* =========================================================
   STATIC FRONTEND
========================================================= */

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
  '*',
  (req, res, next) => {
    if (
      req.path.startsWith(
        '/api/'
      )
    ) {
      return next();
    }

    res.sendFile(
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
      'Server startup failed:',
      error
    );

    process.exit(1);
  }
}

startServer();
