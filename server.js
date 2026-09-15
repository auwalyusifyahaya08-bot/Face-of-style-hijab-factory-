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
).replace(/\/$/, '');

const DATA = path.join(__dirname, 'data');

const ORDERS = path.join(
  DATA,
  'orders.json'
);

const PRODUCTS_FILE = path.join(
  DATA,
  'products.json'
);

fs.mkdirSync(DATA, {
  recursive: true
});

if (!fs.existsSync(ORDERS)) {
  fs.writeFileSync(
    ORDERS,
    '[]'
  );
}

if (!fs.existsSync(PRODUCTS_FILE)) {
  fs.writeFileSync(
    PRODUCTS_FILE,
    JSON.stringify([], null, 2)
  );
}

/* =========================================================
   DATABASE
   ========================================================= */

if (!process.env.DATABASE_URL) {
  console.error(
    'DATABASE_URL is not configured.'
  );
}

const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL,

  ssl: process.env.DATABASE_URL
    ? {
        rejectUnauthorized: false
      }
    : undefined
});

/* =========================================================
   EXPRESS
   ========================================================= */

app.use(
  express.json({
    limit: '12mb',

    verify: (
      req,
      res,
      buf
    ) => {
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

app.use(
  express.static(__dirname)
);

/* =========================================================
   ADMIN SESSIONS
   ========================================================= */

const adminSessions = new Set();

function adminAuth(
  req,
  res,
  next
) {
  const header =
    req.headers.authorization || '';

  const token =
    header.startsWith('Bearer ')
      ? header.slice(7)
      : '';

  if (
    !token ||
    !adminSessions.has(token)
  ) {
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
      fs.readFileSync(
        ORDERS,
        'utf8'
      ) || '[]'
    );
  } catch {
    return [];
  }
}

function writeOrders(orders) {
  const tmp =
    `${ORDERS}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(
      orders,
      null,
      2
    )
  );

  fs.renameSync(
    tmp,
    ORDERS
  );
}

/* =========================================================
   OLD PRODUCTS FILE
   ========================================================= */

function readProductsFile() {
  try {
    return JSON.parse(
      fs.readFileSync(
        PRODUCTS_FILE,
        'utf8'
      ) || '[]'
    );
  } catch {
    return [];
  }
}

function writeProductsFile(
  products
) {
  fs.writeFileSync(
    PRODUCTS_FILE,
    JSON.stringify(
      products,
      null,
      2
    )
  );
}

/* =========================================================
   REFERENCE
   ========================================================= */

function createReference() {
  return (
    `FS-${Date.now()}-${crypto
      .randomBytes(3)
      .toString('hex')}`
  ).toUpperCase();
}

/* =========================================================
   PRODUCT DATABASE HELPERS
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
  async (
    req,
    res
  ) => {
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
  async (
    req,
    res
  ) => {
    try {
      const id =
        Number(req.params.id);

      if (
        !Number.isInteger(id)
      ) {
        return res.status(400).json({
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

      if (
        !result.rows.length
      ) {
        return res.status(404).json({
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
        message:
          'Failed to load product.'
      });
    }
  }
);

/* =========================================================
   CALCULATE ORDER
   ========================================================= */

async function calculateOrder(
  items
) {
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

  for (
    const item of items
  ) {
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
      Number(product.price) *
      qty;

    clean.push({
      id: product.id,

      name: product.name,

      price:
        Number(product.price),

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
  (
    req,
    res
  ) => {
    const username =
      String(
        req.body?.username || ''
      ).trim();

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
        message:
          'Admin credentials are not configured on the server.'
      });
    }

    if (
      username !== expectedUser ||
      password !== expectedPassword
    ) {
      return res.status(401).json({
        message:
          'Invalid username or password'
      });
    }

    const token =
      crypto.randomBytes(32)
        .toString('hex');

    adminSessions.add(token);

    res.json({
      ok: true,
      token
    });
  }
);

/* =========================================================
   ADMIN LOGOUT
   ========================================================= */

app.post(
  '/api/admin/logout',
  adminAuth,
  (
    req,
    res
  ) => {
    const header =
      req.headers.authorization || '';

    const token =
      header.startsWith('Bearer ')
        ? header.slice(7)
        : '';

    adminSessions.delete(
      token
    );

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   ADMIN DASHBOARD
   ========================================================= */

app.get(
  '/api/admin/dashboard',
  adminAuth,
  (
    req,
    res
  ) => {
    try {
      const orders =
        readOrders();

      res.json({
        ok: true,

        stats: {
          orders:
            orders.length,

          paid:
            orders.filter(
              x =>
                x.status ===
                'paid'
            ).length,

          pending:
            orders.filter(
              x =>
                x.status ===
                'pending'
            ).length,

          failed:
            orders.filter(
              x =>
                x.status ===
                'failed'
            ).length,

          revenue:
            orders
              .filter(
                x =>
                  x.status ===
                  'paid'
              )
              .reduce(
                (
                  total,
                  order
                ) =>
                  total +
                  Number(
                    order.total ||
                    0
                  ),
                0
              )
        }
      });

    } catch (error) {
      console.error(
        'DASHBOARD ERROR:',
        error
      );

      res.status(500).json({
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
  (
    req,
    res
  ) => {
    try {
      const orders =
        readOrders()
          .sort(
            (
              a,
              b
            ) =>
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
  (
    req,
    res
  ) => {
    try {
      const order =
        readOrders().find(
          x =>
            x.id ===
            req.params.id
        );

      if (!order) {
        return res.status(404).json({
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
        message:
          'Failed to load order.'
      });
    }
  }
);
/* =========================================================
   PUBLIC PRODUCTS
   Customer website uses this endpoint to load products
   directly from PostgreSQL.
   ========================================================= */

app.get(
  '/api/products',
  async (req, res) => {
    try {
      const products = await getProducts();

      res.json({
        products
      });

    } catch (error) {
      console.error(
        'PUBLIC PRODUCTS ERROR:',
        error
      );

      res.status(500).json({
        message:
          'Failed to load products.'
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
  async (
    req,
    res
  ) => {
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
  async (
    req,
    res
  ) => {
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
        String(
          name || ''
        ).trim();

      const cleanCat =
        String(
          cat || ''
        ).trim();

      const cleanColor =
        String(
          color || ''
        ).trim();

      const cleanImg =
        String(
          img || ''
        ).trim();

      const cleanDescription =
        String(
          description ??
          desc ??
          ''
        ).trim();

      const cleanPrice =
        Number(price);

      if (!cleanName) {
        return res.status(400).json({
          message:
            'Product name is required.'
        });
      }

      if (!cleanCat) {
        return res.status(400).json({
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
          message:
            'Enter a valid product price.'
        });
      }

      if (!cleanColor) {
        return res.status(400).json({
          message:
            'Product color is required.'
        });
      }

      if (!cleanImg) {
        return res.status(400).json({
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
  async (
    req,
    res
  ) => {
    try {
      const id =
        Number(req.params.id);

      if (
        !Number.isInteger(id)
      ) {
        return res.status(400).json({
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
        String(
          name || ''
        ).trim();

      const cleanCat =
        String(
          cat || ''
        ).trim();

      const cleanColor =
        String(
          color || ''
        ).trim();

      const cleanImg =
        String(
          img || ''
        ).trim();

      const cleanDescription =
        String(
          description ??
          desc ??
          ''
        ).trim();

      const cleanPrice =
        Number(price);

      if (!cleanName) {
        return res.status(400).json({
          message:
            'Product name is required.'
        });
      }

      if (!cleanCat) {
        return res.status(400).json({
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
          message:
            'Enter a valid product price.'
        });
      }

      if (!cleanColor) {
        return res.status(400).json({
          message:
            'Product color is required.'
        });
      }

      if (!cleanImg) {
        return res.status(400).json({
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

      if (
        !result.rows.length
      ) {
        return res.status(404).json({
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
  async (
    req,
    res
  ) => {
    try {
      const id =
        Number(req.params.id);

      if (
        !Number.isInteger(id)
      ) {
        return res.status(400).json({
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

      if (
        !result.rows.length
      ) {
        return res.status(404).json({
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
        message:
          'Failed to delete product.'
      });
    }
  }
);

/* =========================================================
   ADMIN SETTINGS
   ========================================================= */

app.get(
  '/api/admin/settings',
  adminAuth,
  (
    req,
    res
  ) => {
    res.json({
      ok: true,

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
  async (
    req,
    res
  ) => {
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

      const reference =
        createReference();

      const order = {
        id,

        reference,

        status:
          'pending',

        customer: {
          name:
            String(
              customer.name
            ).slice(
              0,
              120
            ),

          email:
            String(
              customer.email
            ).slice(
              0,
              200
            ),

          phone:
            String(
              customer.phone
            ).slice(
              0,
              40
            ),

          address:
            String(
              customer.address
            ).slice(
              0,
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
          new Date()
            .toISOString()
      };

      const orders =
        readOrders();

      orders.push(
        order
      );

      writeOrders(
        orders
      );

      const response =
        await fetch(
          'https://api.paystack.co/transaction/initialize',
          {
            method:
              'POST',

            headers: {
              Authorization:
                `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,

              'Content-Type':
                'application/json'
            },

            body:
              JSON.stringify({
                email:
                  order
                    .customer
                    .email,

                amount:
                  Math.round(
                    calculated.total *
                    100
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
                        order
                          .customer
                          .name
                    },

                    {
                      display_name:
                        'Customer Phone',

                      variable_name:
                        'customer_phone',

                      value:
                        order
                          .customer
                          .phone
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

        writeOrders(
          orders
        );

        return res.status(400).json({
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
  async (
    req,
    res
  ) => {
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
        String(
          req.params.reference
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
          message:
            'Order not found.'
        });
      }

      const response =
        await fetch(
          `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
          {
            method:
              'GET',

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
          Number(order.total) *
          100
        );

      if (
        data.status === true &&
        transaction?.status ===
          'success' &&
        Number(
          transaction.amount
        ) ===
          expectedAmount &&
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

        writeOrders(
          orders
        );

        return res.json({
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

      writeOrders(
        orders
      );

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
  (
    req,
    res
  ) => {
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
        return res.sendStatus(
          401
        );
      }

      const expected =
        crypto
          .createHmac(
            'sha512',
            process.env.PAYSTACK_SECRET_KEY
          )
          .update(
            req.rawBody
          )
          .digest('hex');

      const receivedBuffer =
        Buffer.from(
          String(
            signature
          ),
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
              Number(
                order.total
              ) * 100
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

          writeOrders(
            orders
          );
        }
      }

      res.sendStatus(
        200
      );

    } catch (error) {
      console.error(
        'WEBHOOK ERROR:',
        error
      );

      res.sendStatus(
        500
      );
    }
  }
);

/* =========================================================
   HEALTH CHECK
   ========================================================= */

app.get(
  '/api/health',
  async (
    req,
    res
  ) => {
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
            process.env.PAYSTACK_SECRET_KEY
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
            process.env.PAYSTACK_SECRET_KEY
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

  /*
   * STEP 1
   * Create products table using the safe column name
   * "description".
   */

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

  /*
   * STEP 2
   * If an older version of the table already exists with
   * the SQL-sensitive column "desc", migrate it safely.
   */

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

  if (
    oldDesc.rows.length
  ) {
    await pool.query(`
      UPDATE products
      SET description = COALESCE("desc", '')
      WHERE description IS NULL
         OR description = ''
    `);

    await pool.query(`
      ALTER TABLE products
      DROP COLUMN IF EXISTS "desc"
    `);
  }

  /*
   * STEP 3
   * Make sure description exists.
   */

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

  /*
   * STEP 4
   * Count existing products.
   */

  const countResult =
    await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM products
      `
    );

  const count =
    Number(
      countResult.rows[0].count
    );

  /*
   * STEP 5
   * Only create demo products if database is empty.
   */

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

  /*
   * STEP 6
   * Keep the old JSON products file only as a backup.
   * We do NOT automatically duplicate it into PostgreSQL.
   */

  console.log(
    `Database ready. Products in database: ${count}`
  );
}

/* =========================================================
   404 API HANDLER
   ========================================================= */

app.use(
  '/api',
  (
    req,
    res
  ) => {
    res.status(404).json({
      message:
        'API endpoint not found.'
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
      'GLOBAL SERVER ERROR:',
      error
    );

    if (
      res.headersSent
    ) {
      return next(
        error
      );
    }

    res.status(500).json({
      message:
        'Internal server error.'
    });
  }
);

/* =========================================================
   START SERVER
   ========================================================= */

initDatabase()
  .then(
    () => {
      app.listen(
        PORT,
        () => {
          console.log(
            `Face of Style store running at ${BASE_URL}`
          );
        }
      );
    }
  )
  .catch(
    error => {
      console.error(
        'Database initialization failed:',
        error
      );

      process.exit(
        1
      );
    }
  );
