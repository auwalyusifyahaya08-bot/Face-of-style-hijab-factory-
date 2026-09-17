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
const PORT = Number(process.env.PORT) || 10000;

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
    limit: '1mb',
    verify: (req, res, buf) => {
      req.rawBody = Buffer.from(buf);
    }
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '1mb'
  })
);

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

/* =========================================================
   SIMPLE AUTH TOKENS
========================================================= */

const sessions = new Map();

function createSession(username) {
  const token =
    crypto.randomBytes(32).toString('hex');

  sessions.set(token, {
    username,
    createdAt: Date.now()
  });

  return token;
}

function getSession(req) {
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
    sessions.get(token);

  if (!session) {
    return null;
  }

  const maxAge =
    1000 * 60 * 60 * 24;

  if (
    Date.now() -
      session.createdAt >
    maxAge
  ) {
    sessions.delete(token);
    return null;
  }

  return {
    token,
    ...session
  };
}

function requireAdmin(req, res, next) {
  const session =
    getSession(req);

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
   DATABASE INITIALIZATION
========================================================= */

async function initDatabase() {
  if (!pool) {
    console.warn(
      'DATABASE_URL is not configured. Database features are disabled.'
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
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE
  `);
await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS stock INTEGER NOT NULL DEFAULT 0
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_products_active
    ON products(active)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_orders_created
    ON orders(created_at DESC)
  `);

  console.log(
    'Database initialized successfully.'
  );
}

/* =========================================================
   HELPERS
========================================================= */

function cleanString(value, max = 500) {
  return String(value ?? '')
    .trim()
    .slice(0, max);
}

function positiveInteger(value) {
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

function positivePrice(value) {
  const number =
    Number(value);

  if (
    !Number.isFinite(number) ||
    number < 0
  ) {
    return null;
  }

  return Math.round(
    number * 100
  ) / 100;
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

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(email);
}

function validPhone(phone) {
  return /^[0-9+\-\s()]{7,25}$/
    .test(phone);
}

function normalizeCategory(value) {
  const category =
    cleanString(value, 50);

  return category || 'Fashion';
}

function verifyPaystackSignature(
  rawBody,
  signature
) {
  if (
    !rawBody ||
    !signature ||
    !PAYSTACK_SECRET_KEY
  ) {
    return false;
  }

  const hash =
    crypto
      .createHmac(
        'sha512',
        PAYSTACK_SECRET_KEY
      )
      .update(rawBody)
      .digest('hex');

  try {
    const expected =
      Buffer.from(
        hash,
        'utf8'
      );

    const received =
      Buffer.from(
        String(signature),
        'utf8'
      );

    if (
      expected.length !==
      received.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      expected,
      received
    );
  } catch {
    return false;
  }
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
      } catch {
        database = false;
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
            description,
            price,
            color,
            image AS img,
            stock
          FROM products
          WHERE active = TRUE
          ORDER BY created_at DESC
        `);

      res.json({
        products:
          result.rows
      });
    } catch (error) {
      console.error(
        'Products error:',
        error
      );

      res.status(500).json({
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
      createSession(username);

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
    sessions.delete(
      req.admin.token
    );

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   ADMIN SESSION
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
   ADMIN PRODUCTS
========================================================= */

app.get(
  '/api/admin/products',
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
        await pool.query(`
          SELECT
            id,
            name,
            category AS cat,
            description,
            price,
            color,
            image AS img,
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
      console.error(error);

      res.status(500).json({
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

    const category =
      normalizeCategory(
        req.body?.category ||
        req.body?.cat
      );

    const description =
      cleanString(
        req.body?.description ||
        req.body?.desc,
        1000
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
        1000
      );

    const price =
      positivePrice(
        req.body?.price
      );

    const stock =
      Number(
        req.body?.stock
      );

    const safeStock =
      Number.isInteger(stock)
        ? stock
        : 0;

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
          'A valid product price is required.'
      });
    }

    if (
      safeStock < 0 ||
      safeStock > 1000000
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid stock quantity.'
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
            stock
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,$7)
          RETURNING *
          `,
          [
            name,
            category,
            description,
            price,
            color,
            image,
            safeStock
          ]
        );

      res.status(201).json({
        ok: true,
        product:
          result.rows[0]
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

/* =========================================================
   UPDATE PRODUCT
========================================================= */

app.put(
  '/api/admin/products/:id',
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
        1000
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
        1000
      );

    const price =
      positivePrice(
        req.body?.price
      );

    const stock =
      Number(
        req.body?.stock
      );

    const active =
      req.body?.active !== false;

    if (
      !name ||
      price === null
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Product name and valid price are required.'
      });
    }

    if (
      !Number.isInteger(stock) ||
      stock < 0 ||
      stock > 1000000
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid stock quantity.'
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
            color = $5,
            image = $6,
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

      if (!result.rowCount) {
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
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to update product.'
      });
    }
  }
);

/* =========================================================
   DELETE / DEACTIVATE PRODUCT
========================================================= */

app.delete(
  '/api/admin/products/:id',
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
            active = FALSE,
            updated_at = NOW()
          WHERE id = $1
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
      return res.status(503).json({
        ok: false,
        message:
          'Database is not configured.'
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
            created_at,
            updated_at
          FROM orders
          ORDER BY created_at DESC
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
          .push(item);
      }

      const output =
        orders.map(order => ({
          ...order,
          items:
            itemsByOrder.get(
              order.id
            ) || []
        }));

      res.json({
        ok: true,
        orders: output
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to load orders.'
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
        req.body?.order_status,
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
      console.error(error);

      res.status(500).json({
        ok: false,
        message:
          'Unable to update order.'
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
      );

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
              Number(product.id),
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
          price * quantity;

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

      if (
        !Number.isFinite(total) ||
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
            $1,$2,$3,$4,$5,
            'paystack',
            'PENDING',
            'PENDING',
            $6,
            'NGN'
          )
          RETURNING id,
                    reference,
                    total
          `,
          [
            reference,
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

      const paystackPayload = {
        email,
        amount:
          amountInKobo,
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
        process.env
          .PAYSTACK_CALLBACK_URL
      ) {
        paystackPayload.callback_url =
          process.env
            .PAYSTACK_CALLBACK_URL;
      }

      const paystackResponse =
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
                paystackPayload
              )
          }
        );

      const paystackData =
        await paystackResponse.json();

      if (
        !paystackResponse.ok ||
        !paystackData.status ||
        !paystackData.data
          ?.authorization_url
      ) {
        console.error(
          'Paystack initialize error:',
          paystackData
        );

        return res.status(502).json({
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
          reference,
          reference
        ]
      );

      res.json({
        ok: true,
        reference,
        authorization_url:
          paystackData.data
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
        return res.status(404).json({
          ok: false,
          message:
            'Order not found.'
        });
      }

      const order =
        orderResult.rows[0];

      const expectedAmount =
        Math.round(
          Number(order.total) *
          100
        );

      const paidAmount =
        Number(
          transaction.amount
        );

      const amountMatches =
        expectedAmount ===
        paidAmount;

      const success =
        transaction.status ===
          'success' &&
        transaction.currency ===
          'NGN' &&
        amountMatches;

      if (!success) {
        await pool.query(
          `
          UPDATE orders
          SET
            payment_status =
              'FAILED',
            updated_at =
              NOW()
          WHERE id = $1
          `,
          [order.id]
        );

        return res.status(400).json({
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

        const lockedOrderResult =
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
          lockedOrderResult
            .rows[0];

        if (!lockedOrder) {
          throw new Error(
            'Order not found.'
          );
        }

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
            payment_status =
              'PAID',
            order_status =
              'PROCESSING',
            paystack_reference =
              $1,
            updated_at =
              NOW()
          WHERE id = $2
          `,
          [
            transaction.reference,
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
          Number(order.total),
        customer_name:
          order.customer_name
      });
    } catch (error) {
      console.error(
        'Verify error:',
        error
      );

      res.status(500).json({
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
      return res.sendStatus(200);
    }

    const signature =
      String(
        req.headers[
          'x-paystack-signature'
        ] || ''
      );

    if (
      !verifyPaystackSignature(
        req.rawBody,
        signature
      )
    ) {
      return res.sendStatus(401);
    }

    try {
      const event =
        typeof req.body === 'object'
          ? req.body
          : JSON.parse(
              req.rawBody.toString(
                'utf8'
              )
            );

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
        return res.sendStatus(200);
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
        Number(
          transaction.amount
        ) !== expectedAmount
      ) {
        return res.sendStatus(200);
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
            payment_status =
              'PAID',
            order_status =
              'PROCESSING',
            paystack_reference =
              $1,
            updated_at =
              NOW()
          WHERE id = $2
          `,
          [
            transaction.reference,
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
    } catch (error) {
      console.error(
        'Webhook error:',
        error
      );
    }

    return res.sendStatus(200);
  }
);

/* =========================================================
   PUBLIC CONFIG
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
        )
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
   404 API
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
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {
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
