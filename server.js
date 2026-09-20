// server.js
import 'dotenv/config';
import express from 'express';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (
  process.env.BASE_URL ||
  `http://localhost:${PORT}`
).replace(/\/$/, '');

const DATA = path.join(__dirname, 'data');
const ORDERS = path.join(DATA, 'orders.json');
const PRODUCTS_FILE = path.join(DATA, 'products.json');

fs.mkdirSync(DATA, { recursive: true });

if (!fs.existsSync(ORDERS)) {
  fs.writeFileSync(ORDERS, '[]', 'utf8');
}

const DEFAULT_PRODUCTS = [
  {
    id: 1,
    name: 'Elegant Zip Abaya',
    cat: 'Abaya',
    price: 25000,
    color: 'Black',
    image: 'assets/product-1.jpg',
    desc: 'Flowing full-length abaya with refined finishing.',
    stock: 99
  },
  {
    id: 2,
    name: 'Two-Tone Signature Gown',
    cat: 'Gown',
    price: 22000,
    color: 'Two Tone',
    image: 'assets/product-2.jpg',
    desc: 'Elegant two-tone modest gown design.',
    stock: 99
  },
  {
    id: 3,
    name: 'Teal Classic Hijab Dress',
    cat: 'Gown',
    price: 20000,
    color: 'Teal',
    image: 'assets/product-3.jpg',
    desc: 'Comfortable modest dress with clean detailing.',
    stock: 99
  },
  {
    id: 4,
    name: 'Premium Black & White',
    cat: 'Abaya',
    price: 28000,
    color: 'Black & White',
    image: 'assets/product-4.jpg',
    desc: 'Statement modest outfit with premium contrast.',
    stock: 99
  },
  {
    id: 5,
    name: 'Ruffle Hijab Collection',
    cat: 'Hijab',
    price: 12000,
    color: 'Various',
    image: 'assets/product-5.jpg',
    desc: 'Soft, colourful hijab styles with beautiful ruffles.',
    stock: 99
  },
  {
    id: 6,
    name: 'Rose Signature Gown',
    cat: 'Custom',
    price: 24000,
    color: 'Rose',
    image: 'assets/product-6.jpg',
    desc: 'Elegant flowing gown; custom colours available.',
    stock: 99
  }
];

if (!fs.existsSync(PRODUCTS_FILE)) {
  fs.writeFileSync(
    PRODUCTS_FILE,
    JSON.stringify(DEFAULT_PRODUCTS, null, 2),
    'utf8'
  );
}

function readProducts() {
  try {
    const raw = fs.readFileSync(PRODUCTS_FILE, 'utf8');
    const products = JSON.parse(raw || '[]');

    if (!Array.isArray(products)) {
      return [];
    }

    return products.map(normalizeProduct);
  } catch (error) {
    console.error('Products read error:', error);
    return [];
  }
}

function writeProducts(products) {
  const tmp = `${PRODUCTS_FILE}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(products, null, 2),
    'utf8'
  );

  fs.renameSync(tmp, PRODUCTS_FILE);
}

function normalizeProduct(product) {
  return {
    id: Number(product.id),
    name: String(product.name || 'Product'),
    cat: String(
      product.cat ||
      product.category ||
      'Custom'
    ),
    price: Number(product.price) || 0,
    color: String(product.color || ''),
    image: String(
      product.image ||
      product.img ||
      'assets/product-1.jpg'
    ),
    desc: String(
      product.desc ||
      product.description ||
      ''
    ),
    stock:
      product.stock === undefined
        ? 99
        : Math.max(
            0,
            Number(product.stock) || 0
          )
  };
}

function readOrders() {
  try {
    const raw = fs.readFileSync(
      ORDERS,
      'utf8'
    );

    const orders = JSON.parse(raw || '[]');

    if (!Array.isArray(orders)) {
      return [];
    }

    return orders;
  } catch (error) {
    console.error('Orders read error:', error);
    return [];
  }
}

function writeOrders(orders) {
  const tmp = `${ORDERS}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(orders, null, 2),
    'utf8'
  );

  fs.renameSync(tmp, ORDERS);
}

function createReference() {
  return (
    `FS-${Date.now()}-` +
    crypto
      .randomBytes(4)
      .toString('hex')
  ).toUpperCase();
}

function adminAuth(req, res, next) {
  const header =
    req.headers.authorization || '';

  const token =
    header.startsWith('Bearer ')
      ? header.slice(7)
      : '';

  if (!adminSessions.has(token)) {
    return res.status(401).json({
      message: 'Unauthorized'
    });
  }

  next();
}

function calculateOrder(items) {
  if (
    !Array.isArray(items) ||
    !items.length
  ) {
    return null;
  }

  const products = readProducts();

  let total = 0;
  const cleanItems = [];

  for (const item of items) {
    const product = products.find(
      p =>
        Number(p.id) ===
        Number(item.id)
    );

    const qty = Math.floor(
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

    const stock = Number(
      product.stock ?? 99
    );

    if (stock < qty) {
      return {
        error:
          `${product.name} has only ` +
          `${stock} item(s) available.`
      };
    }

    const price =
      Number(product.price) || 0;

    total += price * qty;

    cleanItems.push({
      id: product.id,
      name: product.name,
      price,
      qty,
      color: product.color || ''
    });
  }

  return {
    items: cleanItems,
    total
  };
}

function reduceStock(items) {
  const products = readProducts();

  for (const item of items) {
    const product = products.find(
      p =>
        Number(p.id) ===
        Number(item.id)
    );

    if (product) {
      product.stock =
        Math.max(
          0,
          Number(product.stock || 0) -
            Number(item.qty || 0)
        );
    }
  }

  writeProducts(products);
}

function markOrderPaid(order, tx) {
  order.status = 'paid';

  order.payment = {
    ...(order.payment || {}),
    provider: 'paystack',
    reference:
      order.reference,
    verifiedAt:
      new Date().toISOString(),
    channel:
      tx?.channel || null,
    paidAt:
      tx?.paid_at || null
  };

  if (!order.stockReduced) {
    reduceStock(order.items);
    order.stockReduced = true;
  }
}

/*
=========================================================
RAW BODY + STATIC FILES
=========================================================
*/

app.use(
  express.json({
    limit: '10mb',
    verify: (req, res, buffer) => {
      req.rawBody = buffer;
    }
  })
);

app.use(
  express.urlencoded({
    extended: true
  })
);

app.use(
  express.static(__dirname)
);

/*
=========================================================
PUBLIC CONFIG
=========================================================
*/

app.get(
  '/api/config',
  (req, res) => {
    res.json({
      whatsapp:
        process.env.WHATSAPP_NUMBER ||
        '2349065828886'
    });
  }
);

/*
=========================================================
PUBLIC PRODUCTS
=========================================================
*/

app.get(
  '/api/products',
  (req, res) => {
    res.json({
      products: readProducts()
    });
  }
);

/*
=========================================================
ADMIN LOGIN
=========================================================
*/

const adminSessions = new Set();

app.post(
  '/api/admin/login',
  (req, res) => {
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
          'Invalid username or password.'
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

/*
=========================================================
ADMIN LOGOUT
=========================================================
*/

app.post(
  '/api/admin/logout',
  adminAuth,
  (req, res) => {
    const header =
      req.headers.authorization || '';

    const token =
      header.startsWith('Bearer ')
        ? header.slice(7)
        : '';

    adminSessions.delete(token);

    res.json({
      ok: true
    });
  }
);

/*
=========================================================
ADMIN DASHBOARD
=========================================================
*/

app.get(
  '/api/admin/dashboard',
  adminAuth,
  (req, res) => {
    const orders =
      readOrders();

    const paid =
      orders.filter(
        order =>
          order.status === 'paid'
      );

    const pending =
      orders.filter(
        order =>
          order.status === 'pending'
      );

    const failed =
      orders.filter(
        order =>
          order.status === 'failed'
      );

    const revenue =
      paid.reduce(
        (sum, order) =>
          sum +
          Number(order.total || 0),
        0
      );

    res.json({
      stats: {
        orders: orders.length,
        paid: paid.length,
        pending: pending.length,
        failed: failed.length,
        revenue
      }
    });
  }
);

/*
=========================================================
ADMIN ORDERS
=========================================================
*/

app.get(
  '/api/admin/orders',
  adminAuth,
  (req, res) => {
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
      orders
    });
  }
);

app.get(
  '/api/admin/orders/:id',
  adminAuth,
  (req, res) => {
    const orders =
      readOrders();

    const order =
      orders.find(
        x =>
          String(x.id) ===
          String(req.params.id)
      );

    if (!order) {
      return res.status(404).json({
        message:
          'Order not found.'
      });
    }

    res.json({
      order
    });
  }
);

/*
=========================================================
ADMIN ORDER STATUS
=========================================================
Supports both:
PUT  /api/admin/orders/:id/status
PATCH /api/admin/orders/:id
=========================================================
*/

function updateOrderStatus(
  req,
  res
) {
  const allowed = [
    'new',
    'processing',
    'shipped',
    'delivered',
    'cancelled'
  ];

  const body =
    req.body || {};

  const requested =
    String(
      body.order_status ||
      body.orderStatus ||
      body.status ||
      ''
    ).toLowerCase();

  if (!allowed.includes(requested)) {
    return res.status(400).json({
      message:
        'Invalid order status.'
    });
  }

  const orders =
    readOrders();

  const order =
    orders.find(
      x =>
        String(x.id) ===
        String(req.params.id)
    );

  if (!order) {
    return res.status(404).json({
      message:
        'Order not found.'
    });
  }

  order.orderStatus =
    requested;

  order.order_status =
    requested;

  order.orderStatusUpdatedAt =
    new Date().toISOString();

  writeOrders(orders);

  res.json({
    ok: true,
    order
  });
}

app.put(
  '/api/admin/orders/:id/status',
  adminAuth,
  updateOrderStatus
);

app.patch(
  '/api/admin/orders/:id',
  adminAuth,
  updateOrderStatus
);

/*
=========================================================
ADMIN PRODUCTS
=========================================================
*/

app.get(
  '/api/admin/products',
  adminAuth,
  (req, res) => {
    res.json({
      products:
        readProducts()
    });
  }
);

app.post(
  '/api/admin/products',
  adminAuth,
  (req, res) => {
    const body =
      req.body || {};

    const name =
      String(
        body.name || ''
      ).trim();

    const cat =
      String(
        body.cat ||
        body.category ||
        ''
      ).trim();

    const price =
      Number(body.price);

    if (
      !name ||
      !cat ||
      !Number.isFinite(price) ||
      price < 0
    ) {
      return res.status(400).json({
        message:
          'Name, category and valid price are required.'
      });
    }

    const products =
      readProducts();

    const id =
      products.length
        ? Math.max(
            ...products.map(
              x =>
                Number(x.id) || 0
            )
          ) + 1
        : 1;

    const product = {
      id,
      name:
        name.slice(0, 120),
      cat:
        cat.slice(0, 40),
      price,
      color:
        String(
          body.color || ''
        ).slice(0, 200),
      image:
        String(
          body.image ||
          body.img ||
          'assets/product-1.jpg'
        ).slice(
          0,
          2000000
        ),
      desc:
        String(
          body.desc ||
          body.description ||
          ''
        ).slice(0, 500),
      stock:
        Math.max(
          0,
          Number(
            body.stock ?? 99
          ) || 0
        )
    };

    products.push(product);

    writeProducts(products);

    res.status(201).json({
      ok: true,
      product
    });
  }
);

app.put(
  '/api/admin/products/:id',
  adminAuth,
  (req, res) => {
    const products =
      readProducts();

    const index =
      products.findIndex(
        x =>
          Number(x.id) ===
          Number(req.params.id)
      );

    if (index < 0) {
      return res.status(404).json({
        message:
          'Product not found.'
      });
    }

    const body =
      req.body || {};

    const name =
      String(
        body.name || ''
      ).trim();

    const cat =
      String(
        body.cat ||
        body.category ||
        ''
      ).trim();

    const price =
      Number(body.price);

    if (
      !name ||
      !cat ||
      !Number.isFinite(price) ||
      price < 0
    ) {
      return res.status(400).json({
        message:
          'Name, category and valid price are required.'
      });
    }

    const old =
      products[index];

    products[index] = {
      ...old,

      id:
        Number(old.id),

      name:
        name.slice(0, 120),

      cat:
        cat.slice(0, 40),

      price,

      color:
        String(
          body.color ??
          old.color ??
          ''
        ).slice(0, 200),

      image:
        String(
          body.image ??
          body.img ??
          old.image ??
          'assets/product-1.jpg'
        ).slice(
          0,
          2000000
        ),

      desc:
        String(
          body.desc ??
          body.description ??
          old.desc ??
          ''
        ).slice(0, 500),

      stock:
        Math.max(
          0,
          Number(
            body.stock ??
            old.stock ??
            99
          ) || 0
        )
    };

    writeProducts(products);

    res.json({
      ok: true,
      product:
        products[index]
    });
  }
);

app.delete(
  '/api/admin/products/:id',
  adminAuth,
  (req, res) => {
    const products =
      readProducts();

    const next =
      products.filter(
        x =>
          Number(x.id) !==
          Number(req.params.id)
      );

    if (
      next.length ===
      products.length
    ) {
      return res.status(404).json({
        message:
          'Product not found.'
      });
    }

    writeProducts(next);

    res.json({
      ok: true
    });
  }
);

/*
=========================================================
ADMIN SETTINGS
=========================================================
*/

app.get(
  '/api/admin/settings',
  adminAuth,
  (req, res) => {
    res.json({
      paystackConfigured:
        Boolean(
          process.env
            .PAYSTACK_SECRET_KEY
        ),

      whatsapp:
        process.env.WHATSAPP_NUMBER ||
        '09065828886'
    });
  }
);

/*
=========================================================
PAYSTACK INITIALIZE
=========================================================
*/

app.post(
  '/api/paystack/initialize',
  async (req, res) => {
    try {
      if (
        !process.env
          .PAYSTACK_SECRET_KEY
      ) {
        return res.status(500).json({
          message:
            'Paystack is not configured. Add PAYSTACK_SECRET_KEY on the server.'
        });
      }

      const customer =
        req.body?.customer;

      const calculated =
        calculateOrder(
          req.body?.items
        );

      if (
        calculated?.error
      ) {
        return res.status(400).json({
          message:
            calculated.error
        });
      }

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

        payment_status:
          'pending',

        orderStatus:
          'new',

        order_status:
          'new',

        customer: {
          name:
            String(
              customer.name
            ).slice(0, 120),

          email:
            String(
              customer.email
            ).slice(0, 200),

          phone:
            String(
              customer.phone
            ).slice(0, 40),

          address:
            String(
              customer.address
            ).slice(0, 500)
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

        stockReduced:
          false,

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
                  order.customer
                    .email,

                amount:
                  calculated.total *
                  100,

                currency:
                  'NGN',

                reference,

                callback_url:
                  `${BASE_URL}/payment-success.html`,

                metadata: {
                  order_id:
                    id
                }
              })
          }
        );

      const data =
        await response.json();

      if (
        !response.ok ||
        !data.status ||
        !data.data
          ?.authorization_url
      ) {
        order.status =
          'failed';

        order.payment_status =
          'failed';

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
        ok: true,

        authorization_url:
          data.data
            .authorization_url,

        reference
      });

    } catch (error) {
      console.error(
        'Paystack initialization error:',
        error
      );

      res.status(500).json({
        message:
          'Payment service error.'
      });
    }
  }
);

/*
=========================================================
PAYSTACK VERIFY
=========================================================
*/

app.get(
  '/api/paystack/verify/:reference',
  async (req, res) => {
    try {
      if (
        !process.env
          .PAYSTACK_SECRET_KEY
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
            headers: {
              Authorization:
                `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
            }
          }
        );

      const data =
        await response.json();

      const tx =
        data?.data;

      const expected =
        Number(order.total) *
        100;

      if (
        data.status &&
        tx?.status ===
          'success' &&
        Number(tx.amount) ===
          expected &&
        tx.currency ===
          'NGN'
      ) {
        markOrderPaid(
          order,
          tx
        );

        order.payment_status =
          'paid';

        writeOrders(
          orders
        );

        return res.json({
          success: true,
          reference,
          status: 'paid'
        });
      }

      if (
        tx?.status ===
        'failed'
      ) {
        order.status =
          'failed';

        order.payment_status =
          'failed';
      } else {
        order.status =
          'pending';

        order.payment_status =
          'pending';
      }

      writeOrders(
        orders
      );

      res.json({
        success: false,

        status:
          order.status,

        message:
          'Payment has not been verified as successful.'
      });

    } catch (error) {
      console.error(
        'Payment verification error:',
        error
      );

      res.status(500).json({
        message:
          'Verification error.'
      });
    }
  }
);

/*
=========================================================
PAYSTACK WEBHOOK
=========================================================
*/

app.post(
  '/api/paystack/webhook',
  (req, res) => {
    try {
      const signature =
        req.headers[
          'x-paystack-signature'
        ];

      const secret =
        process.env
          .PAYSTACK_SECRET_KEY;

      if (
        !signature ||
        !secret ||
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
            secret
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
        a.length !==
          b.length ||
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

        const orders =
          readOrders();

        const order =
          orders.find(
            x =>
              x.reference ===
              tx.reference
          );

        if (order) {
          const expectedAmount =
            Number(
              order.total
            ) * 100;

          if (
            Number(
              tx.amount
            ) ===
              expectedAmount &&
            tx.currency ===
              'NGN'
          ) {
            markOrderPaid(
              order,
              tx
            );

            order.payment_status =
              'paid';

            writeOrders(
              orders
            );
          }
        }
      }

      res.sendStatus(
        200
      );

    } catch (error) {
      console.error(
        'Webhook error:',
        error
      );

      res.sendStatus(
        500
      );
    }
  }
);

/*
=========================================================
HEALTH CHECK
=========================================================
*/

app.get(
  '/api/health',
  (req, res) => {
    res.json({
      ok: true,

      paystackConfigured:
        Boolean(
          process.env
            .PAYSTACK_SECRET_KEY
        ),

      adminConfigured:
        Boolean(
          process.env.ADMIN_USER &&
          process.env.ADMIN_PASSWORD
        )
    });
  }
);

/*
=========================================================
START SERVER
=========================================================
*/

app.listen(
  PORT,
  () => {
    console.log(
      `Face of Style Version 2 running at ${BASE_URL}`
    );
  }
);
