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

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');

const DATA = path.join(__dirname, 'data');
const ORDERS = path.join(DATA, 'orders.json');
const PRODUCTS_FILE = path.join(DATA, 'products.json');

fs.mkdirSync(DATA, { recursive: true });

if (!fs.existsSync(ORDERS)) {
  fs.writeFileSync(ORDERS, '[]');
}

if (!fs.existsSync(PRODUCTS_FILE)) {
  fs.writeFileSync(
    PRODUCTS_FILE,
    JSON.stringify([], null, 2)
  );
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json({
  limit: '12mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.use(express.static(__dirname));

/* =========================================================
   ADMIN SESSIONS
   ========================================================= */

const adminSessions = new Set();

function adminAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';

  if (!adminSessions.has(token)) {
    return res.status(401).json({
      message: 'Unauthorized'
    });
  }

  next();
}

/* =========================================================
   ORDERS FILE
   ========================================================= */

function readOrders() {
  try {
    return JSON.parse(
      fs.readFileSync(ORDERS, 'utf8') || '[]'
    );
  } catch {
    return [];
  }
}

function writeOrders(orders) {
  const tmp = `${ORDERS}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(orders, null, 2)
  );

  fs.renameSync(tmp, ORDERS);
}

/* =========================================================
   OLD PRODUCTS FILE
   ========================================================= */

function readProductsFile() {
  try {
    return JSON.parse(
      fs.readFileSync(PRODUCTS_FILE, 'utf8') || '[]'
    );
  } catch {
    return [];
  }
}

function writeProductsFile(products) {
  fs.writeFileSync(
    PRODUCTS_FILE,
    JSON.stringify(products, null, 2)
  );
}

/* =========================================================
   REFERENCE
   ========================================================= */

function ref() {
  return `FS-${Date.now()}-${crypto
    .randomBytes(3)
    .toString('hex')}`
    .toUpperCase();
}

/* =========================================================
   GET PRODUCTS FROM DATABASE
   ========================================================= */

async function getProducts() {
  const result = await pool.query(
    `SELECT id, name, cat, price, color, img, desc
     FROM products
     ORDER BY id ASC`
  );

  return result.rows;
}

/* =========================================================
   CALCULATE ORDER
   ========================================================= */

async function calculateOrder(items) {
  if (!Array.isArray(items) || !items.length) {
    return null;
  }

  const products = await getProducts();

  let total = 0;
  const clean = [];

  for (const item of items) {
    const p = products.find(
      x => x.id === Number(item.id)
    );

    const qty = Math.floor(Number(item.qty));

    if (
      !p ||
      !Number.isInteger(qty) ||
      qty < 1 ||
      qty > 99
    ) {
      return null;
    }

    total += Number(p.price) * qty;

    clean.push({
      id: p.id,
      name: p.name,
      price: Number(p.price),
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

app.post('/api/admin/login', (req, res) => {
  const user = String(req.body?.username || '');
  const pass = String(req.body?.password || '');

  const expectedUser = process.env.ADMIN_USER;
  const expectedPass = process.env.ADMIN_PASSWORD;

  if (!expectedUser || !expectedPass) {
    return res.status(503).json({
      message:
        'Admin credentials are not configured on the server.'
    });
  }

  if (
    user !== expectedUser ||
    pass !== expectedPass
  ) {
    return res.status(401).json({
      message: 'Invalid username or password'
    });
  }

  const token = crypto
    .randomBytes(32)
    .toString('hex');

  adminSessions.add(token);

  res.json({
    token
  });
});

/* =========================================================
   ADMIN DASHBOARD
   ========================================================= */

app.get(
  '/api/admin/dashboard',
  adminAuth,
  (req, res) => {
    const orders = readOrders();

    res.json({
      stats: {
        orders: orders.length,

        paid: orders.filter(
          x => x.status === 'paid'
        ).length,

        pending: orders.filter(
          x => x.status === 'pending'
        ).length,

        revenue: orders
          .filter(x => x.status === 'paid')
          .reduce(
            (a, x) => a + Number(x.total || 0),
            0
          )
      }
    });
  }
);

/* =========================================================
   ADMIN ORDERS
   ========================================================= */

app.get(
  '/api/admin/orders',
  adminAuth,
  (req, res) => {
    const orders = readOrders().sort(
      (a, b) =>
        new Date(b.createdAt) -
        new Date(a.createdAt)
    );

    res.json({
      orders
    });
  }
);

app.get(
  '/api/admin/orders/:id',
  adminAuth,
  (req, res) => {
    const order = readOrders().find(
      x => x.id === req.params.id
    );

    if (!order) {
      return res.status(404).json({
        message: 'Order not found.'
      });
    }

    res.json({
      order
    });
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
      const products = await getProducts();

      res.json({
        products
      });

    } catch (error) {
      console.error(
        'GET PRODUCTS ERROR:',
        error
      );

      res.status(500).json({
        message: 'Failed to load products.'
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
        desc
      } = req.body || {};

      if (
        !name ||
        !cat ||
        !price ||
        !color ||
        !img
      ) {
        return res.status(400).json({
          message:
            'Name, category, price, color and photo are required.'
        });
      }

      const cleanName = String(name).trim();
      const cleanCat = String(cat).trim();
      const cleanColor = String(color).trim();
      const cleanDesc = String(desc || '').trim();
      const cleanImg = String(img).trim();
      const cleanPrice = Number(price);

      if (!cleanName) {
        return res.status(400).json({
          message: 'Product name is required.'
        });
      }

      if (!cleanCat) {
        return res.status(400).json({
          message: 'Category is required.'
        });
      }

      if (
        !Number.isFinite(cleanPrice) ||
        cleanPrice <= 0
      ) {
        return res.status(400).json({
          message: 'Enter a valid product price.'
        });
      }

      if (!cleanImg) {
        return res.status(400).json({
          message: 'Product photo is required.'
        });
      }

      /*
       * IMPORTANT:
       * The photo selected from the phone is saved
       * directly in the database as an image data URL.
       * This avoids the /assets/ problem.
       */

      const result = await pool.query(
        `INSERT INTO products
        (name, cat, price, color, img, desc)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *`,
        [
          cleanName,
          cleanCat,
          cleanPrice,
          cleanColor,
          cleanImg,
          cleanDesc
        ]
      );

      res.json({
        ok: true,
        product: result.rows[0]
      });

    } catch (error) {
      console.error(
        'ADD PRODUCT ERROR:',
        error
      );

      res.status(500).json({
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
      const id = Number(req.params.id);

      const {
        name,
        cat,
        price,
        color,
        img,
        desc
      } = req.body || {};

      if (
        !name ||
        !cat ||
        !price ||
        !color ||
        !img
      ) {
        return res.status(400).json({
          message:
            'Name, category, price, color and photo are required.'
        });
      }

      const result = await pool.query(
        `UPDATE products
         SET name = $1,
             cat = $2,
             price = $3,
             color = $4,
             img = $5,
             desc = $6
         WHERE id = $7
         RETURNING *`,
        [
          String(name).trim(),
          String(cat).trim(),
          Number(price),
          String(color).trim(),
          String(img).trim(),
          String(desc || '').trim(),
          id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          message: 'Product not found.'
        });
      }

      res.json({
        ok: true,
        product: result.rows[0]
      });

    } catch (error) {
      console.error(
        'EDIT PRODUCT ERROR:',
        error
      );

      res.status(500).json({
        message: 'Failed to update product.'
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
      const id = Number(req.params.id);

      const result = await pool.query(
        `DELETE FROM products
         WHERE id = $1
         RETURNING *`,
        [id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          message: 'Product not found.'
        });
      }

      res.json({
        ok: true,
        product: result.rows[0]
      });

    } catch (error) {
      console.error(
        'DELETE PRODUCT ERROR:',
        error
      );

      res.status(500).json({
        message: 'Failed to delete product.'
      });
    }
  }
);

/* =========================================================
   SETTINGS
   ========================================================= */

app.get(
  '/api/admin/settings',
  adminAuth,
  (req, res) => {
    res.json({
      paystackConfigured:
        Boolean(
          process.env.PAYSTACK_SECRET_KEY
        ),

      whatsapp:
        '09065828886'
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
        !process.env.PAYSTACK_SECRET_KEY
      ) {
        return res.status(500).json({
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
          message:
            'Incomplete order details.'
        });
      }

      const id =
        crypto.randomUUID();

      const reference = ref();

      const order = {
        id,

        reference,

        status: 'pending',

        customer: {
          name: String(
            customer.name
          ).slice(0, 120),

          email: String(
            customer.email
          ).slice(0, 200),

          phone: String(
            customer.phone
          ).slice(0, 40),

          address: String(
            customer.address
          ).slice(0, 500)
        },

        items: calculated.items,

        total: calculated.total,

        payment: {
          provider: 'paystack',
          reference
        },

        createdAt:
          new Date().toISOString()
      };

      const orders =
        readOrders();

      orders.push(order);

      writeOrders(orders);

      const r = await fetch(
        'https://api.paystack.co/transaction/initialize',
        {
          method: 'POST',

          headers: {
            Authorization:
              `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,

            'Content-Type':
              'application/json'
          },

          body: JSON.stringify({
            email:
              order.customer.email,

            amount:
              calculated.total * 100,

            currency:
              'NGN',

            reference,

            callback_url:
              `${BASE_URL}/payment-success.html`,

            metadata: {
              order_id: id
            }
          })
        }
      );

      const data =
        await r.json();

      if (
        !r.ok ||
        !data.status
      ) {
        order.status = 'failed';

        order.payment.error =
          data.message ||
          'Paystack initialization failed';

        writeOrders(orders);

        return res.status(400).json({
          message:
            data.message ||
            'Paystack initialization failed.'
        });
      }

      res.json({
        authorization_url:
          data.data.authorization_url,

        reference
      });

    } catch (error) {
      console.error(
        'PAYSTACK INIT ERROR:',
        error
      );

      res.status(500).json({
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
        !process.env.PAYSTACK_SECRET_KEY
      ) {
        return res.status(500).json({
          message:
            'Paystack is not configured.'
        });
      }

      const reference =
        req.params.reference;

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
          message:
            'Order not found.'
        });
      }

      const r = await fetch(
        `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
        {
          headers: {
            Authorization:
              `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
          }
        }
      );

      const data =
        await r.json();

      const tx =
        data.data;

      const expected =
        Number(order.total) * 100;

      if (
        data.status &&
        tx?.status === 'success' &&
        Number(tx.amount) === expected &&
        tx.currency === 'NGN'
      ) {
        order.status = 'paid';

        order.payment.verifiedAt =
          new Date().toISOString();

        order.payment.channel =
          tx.channel;

        order.payment.paidAt =
          tx.paid_at;

        writeOrders(orders);

        return res.json({
          success: true,
          reference
        });
      }

      order.status =
        tx?.status === 'failed'
          ? 'failed'
          : 'pending';

      writeOrders(orders);

      res.json({
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
        !process.env.PAYSTACK_SECRET_KEY ||
        !req.rawBody
      ) {
        return res.sendStatus(401);
      }

      const expected =
        crypto
          .createHmac(
            'sha512',
            process.env.PAYSTACK_SECRET_KEY
          )
          .update(req.rawBody)
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

        const orders =
          readOrders();

        const order =
          orders.find(
            x =>
              x.reference ===
              tx.reference
          );

        if (
          order &&
          Number(tx.amount) ===
            Number(order.total) * 100 &&
          tx.currency === 'NGN'
        ) {
          order.status =
            'paid';

          order.payment.verifiedAt =
            new Date().toISOString();

          order.payment.channel =
            tx.channel;

          order.payment.paidAt =
            tx.paid_at;

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
   HEALTH
   ========================================================= */

app.get(
  '/api/health',
  (req, res) => {
    res.json({
      ok: true,

      paystackConfigured:
        Boolean(
          process.env.PAYSTACK_SECRET_KEY
        )
    });
  }
);

/* =========================================================
   DATABASE INITIALIZATION
   ========================================================= */

async function initDatabase() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      cat TEXT NOT NULL,
      price NUMERIC NOT NULL,
      color TEXT NOT NULL,
      img TEXT NOT NULL,
      desc TEXT DEFAULT ''
    )
  `);

  const count =
    await pool.query(
      'SELECT COUNT(*)::int AS count FROM products'
    );

  if (
    count.rows[0].count === 0
  ) {

    await pool.query(`
      INSERT INTO products
      (name, cat, price, color, img, desc)
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
}

/* =========================================================
   START SERVER
   ========================================================= */

initDatabase()
  .then(() => {

    app.listen(
      PORT,
      () => {
        console.log(
          `Face of Style store running at ${BASE_URL}`
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
