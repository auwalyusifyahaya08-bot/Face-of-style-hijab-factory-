import 'dotenv/config';
import express from 'express';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';
import pg from 'pg';

const { Pool } = pg;

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* =========================================================
   BASIC CONFIGURATION
========================================================= */

const PORT = Number(process.env.PORT || 3000);

const BASE_URL = (
  process.env.BASE_URL ||
  `http://localhost:${PORT}`
).replace(/\/+$/, '');

const DATA = path.join(__dirname, 'data');

const ORDERS_FILE = path.join(DATA, 'orders.json');
const PRODUCTS_BACKUP_FILE = path.join(DATA, 'products.json');
const SETTINGS_FILE = path.join(DATA, 'settings.json');

fs.mkdirSync(DATA, { recursive: true });

if (!fs.existsSync(ORDERS_FILE)) {
  fs.writeFileSync(ORDERS_FILE, '[]');
}

if (!fs.existsSync(PRODUCTS_BACKUP_FILE)) {
  fs.writeFileSync(
    PRODUCTS_BACKUP_FILE,
    JSON.stringify([], null, 2)
  );
}

if (!fs.existsSync(SETTINGS_FILE)) {
  fs.writeFileSync(
    SETTINGS_FILE,
    JSON.stringify(
      {
        primaryColor: '#651630',
        accentColor: '#c9a45b',
        backgroundColor: '#f7f2eb',
        textColor: '#292025'
      },
      null,
      2
    )
  );
}

/* =========================================================
   DATABASE
========================================================= */

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not configured.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : undefined,

  max: 10,

  idleTimeoutMillis: 30000,

  connectionTimeoutMillis: 10000
});

/* =========================================================
   EXPRESS
========================================================= */

app.disable('x-powered-by');

app.use((req, res, next) => {
  res.setHeader(
    'X-Content-Type-Options',
    'nosniff'
  );

  res.setHeader(
    'X-Frame-Options',
    'SAMEORIGIN'
  );

  res.setHeader(
    'Referrer-Policy',
    'strict-origin-when-cross-origin'
  );

  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()'
  );

  next();
});

app.use(
  express.json({
    limit: '12mb',

    verify: (req, res, buf) => {
      req.rawBody = buf;
    }
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '12mb'
  })
);

app.use(express.static(__dirname));

/* =========================================================
   ADMIN SESSION SYSTEM
========================================================= */

const adminSessions = new Map();

const SESSION_DURATION =
  Number(process.env.ADMIN_SESSION_MINUTES || 240) *
  60 *
  1000;

function createAdminSession() {
  const token = crypto
    .randomBytes(48)
    .toString('hex');

  adminSessions.set(token, {
    createdAt: Date.now(),
    expiresAt:
      Date.now() + SESSION_DURATION
  });

  return token;
}

function cleanupSessions() {
  const now = Date.now();

  for (const [token, session] of adminSessions) {
    if (
      !session ||
      session.expiresAt <= now
    ) {
      adminSessions.delete(token);
    }
  }
}

setInterval(
  cleanupSessions,
  10 * 60 * 1000
).unref();

function getAdminToken(req) {
  const header =
    req.headers.authorization || '';

  if (!header.startsWith('Bearer ')) {
    return '';
  }

  return header.slice(7).trim();
}

function adminAuth(req, res, next) {
  cleanupSessions();

  const token = getAdminToken(req);

  if (!token) {
    return res.status(401).json({
      ok: false,
      message: 'Unauthorized.'
    });
  }

  const session =
    adminSessions.get(token);

  if (!session) {
    return res.status(401).json({
      ok: false,
      message: 'Session expired. Please login again.'
    });
  }

  if (
    session.expiresAt <= Date.now()
  ) {
    adminSessions.delete(token);

    return res.status(401).json({
      ok: false,
      message: 'Session expired. Please login again.'
    });
  }

  req.adminSession = session;

  next();
}

/* =========================================================
   LOGIN RATE LIMIT
========================================================= */

const loginAttempts = new Map();

const LOGIN_WINDOW = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 8;

function getClientKey(req) {
  return (
    req.ip ||
    req.headers['x-forwarded-for'] ||
    'unknown'
  );
}

function loginRateLimited(req) {
  const key = getClientKey(req);

  const current =
    loginAttempts.get(key);

  if (!current) {
    return false;
  }

  if (
    Date.now() - current.firstAttempt >
    LOGIN_WINDOW
  ) {
    loginAttempts.delete(key);
    return false;
  }

  return (
    current.count >=
    MAX_LOGIN_ATTEMPTS
  );
}

function recordFailedLogin(req) {
  const key = getClientKey(req);

  const current =
    loginAttempts.get(key);

  if (
    !current ||
    Date.now() - current.firstAttempt >
      LOGIN_WINDOW
  ) {
    loginAttempts.set(key, {
      count: 1,
      firstAttempt: Date.now()
    });

    return;
  }

  current.count += 1;
}

/* =========================================================
   JSON FILE HELPERS
========================================================= */

function readOrders() {
  try {
    return JSON.parse(
      fs.readFileSync(
        ORDERS_FILE,
        'utf8'
      ) || '[]'
    );
  } catch {
    return [];
  }
}

function writeOrders(orders) {
  const temp =
    `${ORDERS_FILE}.tmp`;

  fs.writeFileSync(
    temp,
    JSON.stringify(
      orders,
      null,
      2
    )
  );

  fs.renameSync(
    temp,
    ORDERS_FILE
  );
}

function readSettings() {
  try {
    return JSON.parse(
      fs.readFileSync(
        SETTINGS_FILE,
        'utf8'
      ) || '{}'
    );
  } catch {
    return {
      primaryColor: '#651630',
      accentColor: '#c9a45b',
      backgroundColor: '#f7f2eb',
      textColor: '#292025'
    };
  }
}

function writeSettings(settings) {
  const temp =
    `${SETTINGS_FILE}.tmp`;

  fs.writeFileSync(
    temp,
    JSON.stringify(
      settings,
      null,
      2
    )
  );

  fs.renameSync(
    temp,
    SETTINGS_FILE
  );
}

/* =========================================================
   SECURITY HELPERS
========================================================= */

function safeString(
  value,
  maxLength = 500
) {
  return String(value ?? '')
    .trim()
    .slice(0, maxLength);
}

function createReference() {
  return (
    `FS-${Date.now()}-${crypto
      .randomBytes(4)
      .toString('hex')}`
  ).toUpperCase();
}

function timingSafeEqualText(a, b) {
  const aBuffer =
    Buffer.from(String(a));

  const bBuffer =
    Buffer.from(String(b));

  if (
    aBuffer.length !==
    bBuffer.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    aBuffer,
    bBuffer
  );
}

function isValidHexColor(value) {
  return /^#[0-9A-Fa-f]{6}$/.test(
    String(value || '')
  );
}

/* =========================================================
   PRODUCTS
========================================================= */

async function getProducts() {
  const result =
    await pool.query(`
      SELECT
        id,
        name,
        cat,
        price,
        color,
        img,
        description
      FROM products
      ORDER BY id ASC
    `);

  return result.rows;
}

/* =========================================================
   PUBLIC PRODUCTS
========================================================= */

app.get(
  '/api/products',
  async (req, res) => {
    try {
      const products =
        await getProducts();

      res.json({
        ok: true,
        products
      });
    } catch (error) {
      console.error(
        'PUBLIC PRODUCTS ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to load products.'
      });
    }
  }
);

/* =========================================================
   SINGLE PUBLIC PRODUCT
========================================================= */

app.get(
  '/api/products/:id',
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          ok: false,
          message:
            'Invalid product ID.'
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            name,
            cat,
            price,
            color,
            img,
            description
          FROM products
          WHERE id = $1
          `,
          [id]
        );

      if (!result.rows.length) {
        return res.status(404).json({
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
        'SINGLE PRODUCT ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to load product.'
      });
    }
  }
);

/* =========================================================
   CALCULATE ORDER
========================================================= */

async function calculateOrder(items) {
  if (
    !Array.isArray(items) ||
    !items.length
  ) {
    return null;
  }

  const products =
    await getProducts();

  let total = 0;

  const clean = [];

  for (const item of items) {
    const product =
      products.find(
        p =>
          Number(p.id) ===
          Number(item.id)
      );

    const qty =
      Math.floor(
        Number(item.qty)
      );

    if (
      !product ||
      !Number.isInteger(qty) ||
      qty < 1 ||
      qty > 99
    ) {
      return null;
    }

    total +=
      Number(product.price) * qty;

    clean.push({
      id: product.id,
      name: product.name,
      price: Number(product.price),
      qty
    });
  }

  return {
    items: clean,
    total
  };
}

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
  '/api/admin/login',
  (req, res) => {
    if (loginRateLimited(req)) {
      return res.status(429).json({
        ok: false,
        message:
          'Too many login attempts. Please wait and try again.'
      });
    }

    const username =
      safeString(
        req.body?.username,
        120
      );

    const password =
      String(
        req.body?.password || ''
      );

    const expectedUser =
      process.env.ADMIN_USER;

    const expectedPassword =
      process.env.ADMIN_PASSWORD;

    if (
      !expectedUser ||
      !expectedPassword
    ) {
      return res.status(503).json({
        ok: false,
        message:
          'Admin credentials are not configured on the server.'
      });
    }

    const validUser =
      timingSafeEqualText(
        username,
        expectedUser
      );

    const validPassword =
      timingSafeEqualText(
        password,
        expectedPassword
      );

    if (
      !validUser ||
      !validPassword
    ) {
      recordFailedLogin(req);

      return res.status(401).json({
        ok: false,
        message:
          'Invalid username or password.'
      });
    }

    loginAttempts.delete(
      getClientKey(req)
    );

    const token =
      createAdminSession();

    res.json({
      ok: true,
      token,
      expiresAt:
        Date.now() +
        SESSION_DURATION
    });
  }
);

/* =========================================================
   ADMIN LOGOUT
========================================================= */

app.post(
  '/api/admin/logout',
  adminAuth,
  (req, res) => {
    const token =
      getAdminToken(req);

    adminSessions.delete(token);

    res.json({
      ok: true,
      message:
        'Logged out successfully.'
    });
  }
);

/* =========================================================
   ADMIN DASHBOARD
========================================================= */

app.get(
  '/api/admin/dashboard',
  adminAuth,
  (req, res) => {
    try {
      const orders =
        readOrders();

      const paid =
        orders.filter(
          x =>
            x.status === 'paid'
        );

      const pending =
        orders.filter(
          x =>
            x.status === 'pending'
        );

      const failed =
        orders.filter(
          x =>
            x.status === 'failed'
        );

      const revenue =
        paid.reduce(
          (total, order) =>
            total +
            Number(
              order.total || 0
            ),
          0
        );

      res.json({
        ok: true,

        stats: {
          orders:
            orders.length,

          paid:
            paid.length,

          pending:
            pending.length,

          failed:
            failed.length,

          revenue
        }
      });
    } catch (error) {
      console.error(
        'DASHBOARD ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to load dashboard.'
      });
    }
  }
);

/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
  '/api/admin/orders',
  adminAuth,
  (req, res) => {
    try {
      const orders =
        readOrders()
          .sort(
            (a, b) =>
              new Date(
                b.createdAt
              ) -
              new Date(
                a.createdAt
              )
          );

      res.json({
        ok: true,
        orders
      });
    } catch (error) {
      console.error(
        'ADMIN ORDERS ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to load orders.'
      });
    }
  }
);

/* =========================================================
   ADMIN SINGLE ORDER
========================================================= */

app.get(
  '/api/admin/orders/:id',
  adminAuth,
  (req, res) => {
    try {
      const order =
        readOrders().find(
          x =>
            x.id ===
            req.params.id
        );

      if (!order) {
        return res.status(404).json({
          ok: false,
          message:
            'Order not found.'
        });
      }

      res.json({
        ok: true,
        order
      });
    } catch (error) {
      console.error(
        'SINGLE ORDER ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to load order.'
      });
    }
  }
);

/* =========================================================
   ADMIN PRODUCTS - GET
========================================================= */

app.get(
  '/api/admin/products',
  adminAuth,
  async (req, res) => {
    try {
      const products =
        await getProducts();

      res.json({
        ok: true,
        products
      });
    } catch (error) {
      console.error(
        'GET PRODUCTS ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to load products.'
      });
    }
  }
);

/* =========================================================
   ADMIN PRODUCTS - ADD
========================================================= */

app.post(
  '/api/admin/products',
  adminAuth,
  async (req, res) => {
    try {
      const {
        name,
        cat,
        price,
        color,
        img,
        description,
        desc
      } = req.body || {};

      const cleanName =
        safeString(name, 150);

      const cleanCat =
        safeString(cat, 80);

      const cleanColor =
        safeString(color, 100);

      const cleanImg =
        safeString(img, 12000000);

      const cleanDescription =
        safeString(
          description ??
          desc ??
          '',
          2000
        );

      const cleanPrice =
        Number(price);

      if (!cleanName) {
        return res.status(400).json({
          ok: false,
          message:
            'Product name is required.'
        });
      }

      if (!cleanCat) {
        return res.status(400).json({
          ok: false,
          message:
            'Category is required.'
        });
      }

      if (
        !Number.isFinite(
          cleanPrice
        ) ||
        cleanPrice <= 0
      ) {
        return res.status(400).json({
          ok: false,
          message:
            'Enter a valid product price.'
        });
      }

      if (!cleanColor) {
        return res.status(400).json({
          ok: false,
          message:
            'Product color is required.'
        });
      }

      if (!cleanImg) {
        return res.status(400).json({
          ok: false,
          message:
            'Product photo is required.'
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO products
          (
            name,
            cat,
            price,
            color,
            img,
            description
          )
          VALUES
          ($1,$2,$3,$4,$5,$6)
          RETURNING
            id,
            name,
            cat,
            price,
            color,
            img,
            description
          `,
          [
            cleanName,
            cleanCat,
            cleanPrice,
            cleanColor,
            cleanImg,
            cleanDescription
          ]
        );

      res.json({
        ok: true,
        product:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'ADD PRODUCT ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to add product. Please try again.'
      });
    }
  }
);

/* =========================================================
   ADMIN PRODUCTS - EDIT
========================================================= */

app.put(
  '/api/admin/products/:id',
  adminAuth,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          ok: false,
          message:
            'Invalid product ID.'
        });
      }

      const {
        name,
        cat,
        price,
        color,
        img,
        description,
        desc
      } = req.body || {};

      const cleanName =
        safeString(name, 150);

      const cleanCat =
        safeString(cat, 80);

      const cleanColor =
        safeString(color, 100);

      const cleanImg =
        safeString(img, 12000000);

      const cleanDescription =
        safeString(
          description ??
          desc ??
          '',
          2000
        );

      const cleanPrice =
        Number(price);

      if (!cleanName) {
        return res.status(400).json({
          ok: false,
          message:
            'Product name is required.'
        });
      }

      if (!cleanCat) {
        return res.status(400).json({
          ok: false,
          message:
            'Category is required.'
        });
      }

      if (
        !Number.isFinite(
          cleanPrice
        ) ||
        cleanPrice <= 0
      ) {
        return res.status(400).json({
          ok: false,
          message:
            'Enter a valid product price.'
        });
      }

      if (!cleanColor) {
        return res.status(400).json({
          ok: false,
          message:
            'Product color is required.'
        });
      }

      if (!cleanImg) {
        return res.status(400).json({
          ok: false,
          message:
            'Product photo is required.'
        });
      }

      const result =
        await pool.query(
          `
          UPDATE products
          SET
            name = $1,
            cat = $2,
            price = $3,
            color = $4,
            img = $5,
            description = $6
          WHERE id = $7
          RETURNING
            id,
            name,
            cat,
            price,
            color,
            img,
            description
          `,
          [
            cleanName,
            cleanCat,
            cleanPrice,
            cleanColor,
            cleanImg,
            cleanDescription,
            id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
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
        'EDIT PRODUCT ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to update product.'
      });
    }
  }
);

/* =========================================================
   ADMIN PRODUCTS - DELETE
========================================================= */

app.delete(
  '/api/admin/products/:id',
  adminAuth,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          ok: false,
          message:
            'Invalid product ID.'
        });
      }

      const result =
        await pool.query(
          `
          DELETE FROM products
          WHERE id = $1
          RETURNING
            id,
            name
          `,
          [id]
        );

      if (!result.rows.length) {
        return res.status(404).json({
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
        'DELETE PRODUCT ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to delete product.'
      });
    }
  }
);

/* =========================================================
   ADMIN SETTINGS - GET
========================================================= */

app.get(
  '/api/admin/settings',
  adminAuth,
  (req, res) => {
    try {
      const settings =
        readSettings();

      res.json({
        ok: true,

        paystackConfigured:
          Boolean(
            process.env
              .PAYSTACK_SECRET_KEY
          ),

        whatsapp:
          '09065828886',

        theme: settings,

        biometric:
          Boolean(
            process.env
              .WEBAUTHN_RP_ID
          )
      });
    } catch (error) {
      console.error(
        'SETTINGS ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to load settings.'
      });
    }
  }
);

/* =========================================================
   ADMIN SETTINGS - SAVE THEME
========================================================= */

app.put(
  '/api/admin/settings/theme',
  adminAuth,
  (req, res) => {
    try {
      const current =
        readSettings();

      const primaryColor =
        safeString(
          req.body?.primaryColor,
          20
        );

      const accentColor =
        safeString(
          req.body?.accentColor,
          20
        );

      const backgroundColor =
        safeString(
          req.body?.backgroundColor,
          20
        );

      const textColor =
        safeString(
          req.body?.textColor,
          20
        );

      const values = {
        primaryColor,
        accentColor,
        backgroundColor,
        textColor
      };

      for (const [key, value] of Object.entries(values)) {
        if (
          value &&
          !isValidHexColor(value)
        ) {
          return res.status(400).json({
            ok: false,
            message:
              `${key} must be a valid HEX colour.`
          });
        }
      }

      const updated = {
        ...current,

        primaryColor:
          primaryColor ||
          current.primaryColor,

        accentColor:
          accentColor ||
          current.accentColor,

        backgroundColor:
          backgroundColor ||
          current.backgroundColor,

        textColor:
          textColor ||
          current.textColor
      };

      writeSettings(updated);

      res.json({
        ok: true,
        theme: updated
      });
    } catch (error) {
      console.error(
        'SAVE THEME ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to save website colours.'
      });
    }
  }
);

/* =========================================================
   PUBLIC THEME
========================================================= */

app.get(
  '/api/theme',
  (req, res) => {
    try {
      res.json({
        ok: true,
        theme:
          readSettings()
      });
    } catch {
      res.status(500).json({
        ok: false,
        message:
          'Failed to load website theme.'
      });
    }
  }
);

/* =========================================================
   CHANGE ADMIN PASSWORD
========================================================= */

app.put(
  '/api/admin/change-password',
  adminAuth,
  (req, res) => {
    try {
      const currentPassword =
        String(
          req.body?.currentPassword ||
          ''
        );

      const newPassword =
        String(
          req.body?.newPassword ||
          ''
        );

      const configuredPassword =
        process.env.ADMIN_PASSWORD;

      if (!configuredPassword) {
        return res.status(503).json({
          ok: false,
          message:
            'Admin password is not configured.'
        });
      }

      if (
        !timingSafeEqualText(
          currentPassword,
          configuredPassword
        )
      ) {
        return res.status(401).json({
          ok: false,
          message:
            'Current password is incorrect.'
        });
      }

      if (
        newPassword.length < 10
      ) {
        return res.status(400).json({
          ok: false,
          message:
            'New password must contain at least 10 characters.'
        });
      }

      /*
        IMPORTANT:
        Render environment variables are normally
        changed from the Render dashboard.

        Therefore this endpoint does not pretend
        to permanently change process.env.ADMIN_PASSWORD.

        It invalidates all sessions and tells the
        admin to update ADMIN_PASSWORD in Render.

        Full database-backed admin credentials can
        be added in the next security stage.
      */

      for (const token of adminSessions.keys()) {
        adminSessions.delete(token);
      }

      res.json({
        ok: true,

        requiresEnvironmentUpdate:
          true,

        message:
          'Password validation completed. Update ADMIN_PASSWORD in your Render environment variables, then login again.'
      });
    } catch (error) {
      console.error(
        'CHANGE PASSWORD ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Failed to change password.'
      });
    }
  }
);

/* =========================================================
   FORGOT PASSWORD / RECOVERY
========================================================= */

app.post(
  '/api/admin/forgot-password',
  (req, res) => {
    const recoveryCode =
      String(
        req.body?.recoveryCode ||
        ''
      );

    const configuredRecoveryCode =
      process.env
        .ADMIN_RECOVERY_CODE;

    if (
      !configuredRecoveryCode
    ) {
      return res.status(503).json({
        ok: false,
        message:
          'Admin recovery is not configured. Add ADMIN_RECOVERY_CODE on Render.'
      });
    }

    if (
      !timingSafeEqualText(
        recoveryCode,
        configuredRecoveryCode
      )
    ) {
      return res.status(401).json({
        ok: false,
        message:
          'Invalid recovery code.'
      });
    }

    const resetToken =
      crypto
        .randomBytes(32)
        .toString('hex');

    const resetHash =
      crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');

    const resetExpires =
      Date.now() +
      10 * 60 * 1000;

    /*
      Store temporary reset information
      in memory only.
    */

    globalThis.__adminReset = {
      hash: resetHash,
      expiresAt: resetExpires
    };

    res.json({
      ok: true,

      resetToken,

      expiresAt:
        resetExpires,

      message:
        'Recovery verified. Use the reset token within 10 minutes.'
    });
  }
);

/* =========================================================
   RESET PASSWORD
========================================================= */

app.post(
  '/api/admin/reset-password',
  (req, res) => {
    const resetToken =
      String(
        req.body?.resetToken ||
        ''
      );

    const newPassword =
      String(
        req.body?.newPassword ||
        ''
      );

    const reset =
      globalThis.__adminReset;

    if (
      !reset ||
      reset.expiresAt <= Date.now()
    ) {
      globalThis.__adminReset =
        null;

      return res.status(400).json({
        ok: false,
        message:
          'Reset token has expired. Start again.'
      });
    }

    const resetHash =
      crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');

    if (
      !timingSafeEqualText(
        resetHash,
        reset.hash
      )
    ) {
      return res.status(401).json({
        ok: false,
        message:
          'Invalid reset token.'
      });
    }

    if (
      newPassword.length < 10
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'New password must contain at least 10 characters.'
      });
    }

    globalThis.__adminReset =
      null;

    for (const token of adminSessions.keys()) {
      adminSessions.delete(token);
    }

    res.json({
      ok: true,

      requiresEnvironmentUpdate:
        true,

      message:
        'Reset verified. Now update ADMIN_PASSWORD in Render with the new password, then login again.'
    });
  }
);

/* =========================================================
   PAYSTACK INITIALIZE
========================================================= */

app.post(
  '/api/paystack/initialize',
  async (req, res) => {
    try {
      if (
        !process.env
          .PAYSTACK_SECRET_KEY
      ) {
        return res.status(500).json({
          ok: false,
          message:
            'Paystack is not configured. Add PAYSTACK_SECRET_KEY on the server.'
        });
      }

      const customer =
        req.body?.customer;

      const calculated =
        await calculateOrder(
          req.body?.items
        );

      if (
        !customer?.name ||
        !customer?.email ||
        !customer?.phone ||
        !customer?.address ||
        !calculated
      ) {
        return res.status(400).json({
          ok: false,
          message:
            'Incomplete order details.'
        });
      }

      const id =
        crypto.randomUUID();

      const reference =
        createReference();

      const order = {
        id,

        reference,

        status:
          'pending',

        customer: {
          name:
            safeString(
              customer.name,
              120
            ),

          email:
            safeString(
              customer.email,
              200
            ),

          phone:
            safeString(
              customer.phone,
              40
            ),

          address:
            safeString(
              customer.address,
              500
            )
        },

        items:
          calculated.items,

        total:
          calculated.total,

        payment: {
          provider:
            'paystack',

          reference
        },

        createdAt:
          new Date().toISOString()
      };

      const orders =
        readOrders();

      orders.push(order);

      writeOrders(orders);

      const response =
        await fetch(
          'https://api.paystack.co/transaction/initialize',
          {
            method: 'POST',

            headers: {
              Authorization:
                `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,

              'Content-Type':
                'application/json'
            },

            body:
              JSON.stringify({
                email:
                  order.customer.email,

                amount:
                  Math.round(
                    calculated.total * 100
                  ),

                currency:
                  'NGN',

                reference,

                callback_url:
                  `${BASE_URL}/payment-success.html`,

                metadata: {
                  order_id:
                    id,

                  custom_fields: [
                    {
                      display_name:
                        'Customer Name',

                      variable_name:
                        'customer_name',

                      value:
                        order.customer.name
                    },

                    {
                      display_name:
                        'Customer Phone',

                      variable_name:
                        'customer_phone',

                      value:
                        order.customer.phone
                    }
                  ]
                }
              })
          }
        );

      const data =
        await response.json();

      if (
        !response.ok ||
        !data.status ||
        !data.data?.authorization_url
      ) {
        order.status =
          'failed';

        order.payment.error =
          data.message ||
          'Paystack initialization failed';

        writeOrders(orders);

        return res.status(400).json({
          ok: false,
          message:
            data.message ||
            'Paystack initialization failed.'
        });
      }

      res.json({
        ok: true,

        authorization_url:
          data.data
            .authorization_url,

        reference
      });
    } catch (error) {
      console.error(
        'PAYSTACK INIT ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Payment service error.'
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
    try {
      if (
        !process.env
          .PAYSTACK_SECRET_KEY
      ) {
        return res.status(500).json({
          ok: false,
          message:
            'Paystack is not configured.'
        });
      }

      const reference =
        safeString(
          req.params.reference,
          200
        );

      const orders =
        readOrders();

      const order =
        orders.find(
          x =>
            x.reference ===
            reference
        );

      if (!order) {
        return res.status(404).json({
          ok: false,
          message:
            'Order not found.'
        });
      }

      const response =
        await fetch(
          `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
          {
            method: 'GET',

            headers: {
              Authorization:
                `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
            }
          }
        );

      const data =
        await response.json();

      const transaction =
        data.data;

      const expectedAmount =
        Math.round(
          Number(order.total) * 100
        );

      if (
        data.status === true &&
        transaction?.status ===
          'success' &&
        Number(
          transaction.amount
        ) === expectedAmount &&
        transaction.currency ===
          'NGN'
      ) {
        order.status =
          'paid';

        order.payment.verifiedAt =
          new Date()
            .toISOString();

        order.payment.channel =
          transaction.channel;

        order.payment.paidAt =
          transaction.paid_at;

        writeOrders(orders);

        return res.json({
          ok: true,
          success: true,
          reference
        });
      }

      if (
        transaction?.status ===
        'failed'
      ) {
        order.status =
          'failed';
      } else {
        order.status =
          'pending';
      }

      writeOrders(orders);

      res.json({
        ok: true,

        success: false,

        message:
          'Payment has not been verified as successful.'
      });
    } catch (error) {
      console.error(
        'PAYSTACK VERIFY ERROR:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Verification error.'
      });
    }
  }
);

/* =========================================================
   PAYSTACK WEBHOOK
========================================================= */

app.post(
  '/api/paystack/webhook',
  (req, res) => {
    try {
      const signature =
        req.headers[
          'x-paystack-signature'
        ];

      if (
        !signature ||
        !process.env
          .PAYSTACK_SECRET_KEY ||
        !req.rawBody
      ) {
        return res.sendStatus(401);
      }

      const expected =
        crypto
          .createHmac(
            'sha512',
            process.env
              .PAYSTACK_SECRET_KEY
          )
          .update(req.rawBody)
          .digest('hex');

      const receivedBuffer =
        Buffer.from(
          String(signature),
          'utf8'
        );

      const expectedBuffer =
        Buffer.from(
          expected,
          'utf8'
        );

      if (
        receivedBuffer.length !==
          expectedBuffer.length ||
        !crypto.timingSafeEqual(
          receivedBuffer,
          expectedBuffer
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
        const transaction =
          event.data;

        const orders =
          readOrders();

        const order =
          orders.find(
            x =>
              x.reference ===
              transaction.reference
          );

        if (
          order &&
          Number(
            transaction.amount
          ) ===
            Math.round(
              Number(order.total) * 100
            ) &&
          transaction.currency ===
            'NGN'
        ) {
          order.status =
            'paid';

          order.payment.verifiedAt =
            new Date()
              .toISOString();

          order.payment.channel =
            transaction.channel;

          order.payment.paidAt =
            transaction.paid_at;

          writeOrders(orders);
        }
      }

      res.sendStatus(200);
    } catch (error) {
      console.error(
        'WEBHOOK ERROR:',
        error
      );

      res.sendStatus(500);
    }
  }
);

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  '/api/health',
  async (req, res) => {
    try {
      await pool.query(
        'SELECT 1'
      );

      res.json({
        ok: true,

        database:
          'connected',

        paystackConfigured:
          Boolean(
            process.env
              .PAYSTACK_SECRET_KEY
          )
      });
    } catch (error) {
      console.error(
        'HEALTH DATABASE ERROR:',
        error
      );

      res.status(500).json({
        ok: false,

        database:
          'disconnected',

        paystackConfigured:
          Boolean(
            process.env
              .PAYSTACK_SECRET_KEY
          )
      });
    }
  }
);

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initDatabase() {
  if (!process.env.DATABASE_URL) {
    throw new Error(
      'DATABASE_URL is missing.'
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      cat TEXT NOT NULL,
      price NUMERIC NOT NULL,
      color TEXT NOT NULL,
      img TEXT NOT NULL,
      description TEXT DEFAULT ''
    )
  `);

  const oldDesc =
    await pool.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
      AND table_name = 'products'
      AND column_name = 'desc'
    `);

  const newDescription =
    await pool.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
      AND table_name = 'products'
      AND column_name = 'description'
    `);

  if (
    oldDesc.rows.length &&
    !newDescription.rows.length
  ) {
    await pool.query(`
      ALTER TABLE products
      ADD COLUMN description TEXT DEFAULT ''
    `);
  }

  if (oldDesc.rows.length) {
    await pool.query(`
      UPDATE products
      SET description =
        COALESCE("desc", '')
      WHERE description IS NULL
      OR description = ''
    `);

    await pool.query(`
      ALTER TABLE products
      DROP COLUMN IF EXISTS "desc"
    `);
  }

  const verifyDescription =
    await pool.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
      AND table_name = 'products'
      AND column_name = 'description'
    `);

  if (
    !verifyDescription.rows.length
  ) {
    await pool.query(`
      ALTER TABLE products
      ADD COLUMN description TEXT DEFAULT ''
    `);
  }

  const countResult =
    await pool.query(`
      SELECT COUNT(*)::int AS count
      FROM products
    `);

  const count =
    Number(
      countResult.rows[0].count
    );

  if (count === 0) {
    await pool.query(`
      INSERT INTO products
      (
        name,
        cat,
        price,
        color,
        img,
        description
      )
      VALUES

      (
        'Elegant Zip Abaya',
        'Abaya',
        25000,
        'Black',
        'product-1.jpg',
        'Flowing full-length abaya with refined finishing.'
      ),

      (
        'Two-Tone Signature Gown',
        'Gown',
        22000,
        'Two-Tone',
        'product-2.jpg',
        'Elegant two-tone modest gown design.'
      ),

      (
        'Teal Classic Hijab Dress',
        'Gown',
        20000,
        'Teal',
        'product-3.jpg',
        'Comfortable modest dress with clean detailing.'
      ),

      (
        'Premium Black & White',
        'Abaya',
        28000,
        'Black & White',
        'product-4.jpg',
        'Statement modest outfit with premium contrast.'
      ),

      (
        'Ruffle Hijab Collection',
        'Hijab',
        12000,
        'Multiple Colors',
        'product-5.jpg',
        'Soft, colourful hijab styles with beautiful ruffles.'
      ),

      (
        'Rose Signature Gown',
        'Custom',
        24000,
        'Rose',
        'product-6.jpg',
        'Elegant flowing gown; custom colours available.'
      )
    `);
  }

  console.log(
    `Database ready. Products in database: ${count}`
  );
}

/* =========================================================
   404 API HANDLER
========================================================= */

app.use(
  '/api',
  (req, res) => {
    res.status(404).json({
      ok: false,
      message:
        'API endpoint not found.'
    });
  }
);

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      'GLOBAL SERVER ERROR:',
      error
    );

    if (res.headersSent) {
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

initDatabase()
  .then(() => {
    app.listen(
      PORT,
      () => {
        console.log(
          `Face of Style Hijab Factory running at ${BASE_URL}`
        );
      }
    );
  })
  .catch(error => {
    console.error(
      'Database initialization failed:',
      error
    );

    process.exit(1);
  });
