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
const ORDERS_FILE = path.join(DATA, 'orders.json');
const PRODUCTS_FILE = path.join(DATA, 'products.json');

fs.mkdirSync(DATA, { recursive: true });

if (!fs.existsSync(ORDERS_FILE)) {
  fs.writeFileSync(ORDERS_FILE, '[]');
}

const DEFAULT_PRODUCTS = [
  {
    id: 1,
    name: 'Elegant Zip Abaya',
    cat: 'Abaya',
    price: 25000,
    color: 'Black',
    colors: ['Black'],
    sizes: 'Free Size',
    stock: 10,
    image: 'assets/product-1.jpg',
    images: ['assets/product-1.jpg'],
    desc: 'Flowing full-length abaya with refined finishing.'
  },
  {
    id: 2,
    name: 'Two-Tone Signature Gown',
    cat: 'Gown',
    price: 22000,
    color: 'Two Tone',
    colors: ['Black', 'White'],
    sizes: 'Free Size',
    stock: 10,
    image: 'assets/product-2.jpg',
    images: ['assets/product-2.jpg'],
    desc: 'Elegant two-tone modest gown design.'
  },
  {
    id: 3,
    name: 'Teal Classic Hijab Dress',
    cat: 'Gown',
    price: 20000,
    color: 'Teal',
    colors: ['Teal'],
    sizes: 'Free Size',
    stock: 10,
    image: 'assets/product-3.jpg',
    images: ['assets/product-3.jpg'],
    desc: 'Comfortable modest dress with clean detailing.'
  },
  {
    id: 4,
    name: 'Premium Black & White',
    cat: 'Fashion',
    price: 28000,
    color: 'Black & White',
    colors: ['Black', 'White'],
    sizes: 'Free Size',
    stock: 10,
    image: 'assets/product-4.jpg',
    images: ['assets/product-4.jpg'],
    desc: 'Statement modest outfit with premium contrast.'
  },
  {
    id: 5,
    name: 'Ruffle Hijab Collection',
    cat: 'Hijab',
    price: 12000,
    color: 'Mixed',
    colors: ['Black', 'Rose', 'Navy'],
    sizes: 'Free Size',
    stock: 10,
    image: 'assets/product-5.jpg',
    images: ['assets/product-5.jpg'],
    desc: 'Soft colourful hijab styles with beautiful ruffles.'
  },
  {
    id: 6,
    name: 'Rose Signature Gown',
    cat: 'Custom',
    price: 24000,
    color: 'Rose',
    colors: ['Rose'],
    sizes: 'Custom',
    stock: 10,
    image: 'assets/product-6.jpg',
    images: ['assets/product-6.jpg'],
    desc: 'Elegant flowing gown; custom colours available.'
  }
];

if (!fs.existsSync(PRODUCTS_FILE)) {
  fs.writeFileSync(
    PRODUCTS_FILE,
    JSON.stringify(DEFAULT_PRODUCTS, null, 2)
  );
}

/* =========================================================
   FILE HELPERS
========================================================= */

function safeReadJSON(file, fallback = []) {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, JSON.stringify(fallback, null, 2));
      return fallback;
    }

    const text = fs.readFileSync(file, 'utf8').trim();

    if (!text) return fallback;

    const data = JSON.parse(text);

    return Array.isArray(data) ? data : fallback;
  } catch (error) {
    console.error(`JSON read error: ${file}`, error);
    return fallback;
  }
}

function safeWriteJSON(file, data) {
  const temp = `${file}.tmp`;

  fs.writeFileSync(
    temp,
    JSON.stringify(data, null, 2),
    'utf8'
  );

  fs.renameSync(temp, file);
}

/* =========================================================
   PRODUCT NORMALIZATION
========================================================= */

function normalizeProduct(product, index = 0) {
  const id = Number(product.id) || index + 1;

  const category =
    product.cat ||
    product.category ||
    'Fashion';

  const description =
    product.desc ||
    product.description ||
    '';

  const price = Number(product.price) || 0;

  let colors = [];

  if (Array.isArray(product.colors)) {
    colors = product.colors;
  } else if (product.color) {
    colors = String(product.color)
      .split(',')
      .map(x => x.trim())
      .filter(Boolean);
  }

  let image =
    product.image ||
    product.img ||
    '';

  let images = [];

  if (Array.isArray(product.images)) {
    images = product.images.filter(Boolean);
  }

  if (!images.length && image) {
    images = [image];
  }

  /*
   * IMPORTANT:
   * If an old V2 product has no image saved,
   * automatically connect it to the matching
   * assets/product-X.jpg image.
   */
  if (!image && id >= 1 && id <= 6) {
    image = `assets/product-${id}.jpg`;
    images = [image];
  }

  return {
    ...product,

    id,
    name: String(product.name || 'Unnamed Product'),

    cat: String(category),

    category: String(category),

    price,

    color:
      product.color ||
      colors.join(', '),

    colors,

    sizes:
      product.sizes ||
      'Free Size',

    stock:
      Number.isFinite(Number(product.stock))
        ? Number(product.stock)
        : 0,

    image,

    img: image,

    images,

    desc: String(description),

    description: String(description)
  };
}

function readProducts() {
  const raw = safeReadJSON(
    PRODUCTS_FILE,
    DEFAULT_PRODUCTS
  );

  return raw.map(normalizeProduct);
}

function writeProducts(products) {
  const normalized = products.map(normalizeProduct);

  safeWriteJSON(
    PRODUCTS_FILE,
    normalized
  );
}

function readOrders() {
  return safeReadJSON(
    ORDERS_FILE,
    []
  );
}

function writeOrders(orders) {
  safeWriteJSON(
    ORDERS_FILE,
    orders
  );
}

/* =========================================================
   ADMIN SESSIONS
========================================================= */

const adminSessions = new Set();

function adminAuth(req, res, next) {
  const header =
    req.headers.authorization || '';

  const token =
    header.startsWith('Bearer ')
      ? header.slice(7)
      : '';

  if (!token || !adminSessions.has(token)) {
    return res.status(401).json({
      message: 'Unauthorized'
    });
  }

  next();
}

/* =========================================================
   ORDER HELPERS
========================================================= */

function createReference() {
  return (
    `FS-${Date.now()}-${crypto
      .randomBytes(3)
      .toString('hex')}`
  ).toUpperCase();
}

function calculateOrder(items) {
  if (!Array.isArray(items) || !items.length) {
    return null;
  }

  const products = readProducts();

  let total = 0;

  const cleanItems = [];

  for (const item of items) {
    const product = products.find(
      p => Number(p.id) === Number(item.id)
    );

    const qty =
      Math.floor(Number(item.qty));

    if (
      !product ||
      !Number.isInteger(qty) ||
      qty < 1 ||
      qty > 99
    ) {
      return null;
    }

    if (Number(product.stock) < qty) {
      return null;
    }

    total +=
      Number(product.price) * qty;

    cleanItems.push({
      id: product.id,
      name: product.name,
      price: Number(product.price),
      qty
    });
  }

  return {
    items: cleanItems,
    total
  };
}

/* =========================================================
   EXPRESS
========================================================= */

app.use(
  express.json({
    limit: '6mb',
    verify: (req, res, buf) => {
      req.rawBody = buf;
    }
  })
);

app.use(express.urlencoded({
  extended: true,
  limit: '6mb'
}));

app.use(
  express.static(__dirname)
);

/* =========================================================
   HOME / ADMIN ALIASES
========================================================= */

app.get('/admin', (req, res) => {
  res.sendFile(
    path.join(__dirname, 'admin.html')
  );
});

/* =========================================================
   PUBLIC PRODUCTS
========================================================= */

app.get('/api/products', (req, res) => {
  res.json({
    products: readProducts()
  });
});

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post('/api/admin/login', (req, res) => {
  const username =
    String(req.body?.username || '');

  const password =
    String(req.body?.password || '');

  const expectedUsername =
    process.env.ADMIN_USERNAME ||
    process.env.ADMIN_USER;

  const expectedPassword =
    process.env.ADMIN_PASSWORD;

  if (
    !expectedUsername ||
    !expectedPassword
  ) {
    return res.status(503).json({
      message:
        'Admin credentials are not configured on the server.'
    });
  }

  if (
    username !== expectedUsername ||
    password !== expectedPassword
  ) {
    return res.status(401).json({
      message:
        'Invalid username or password.'
    });
  }

  const token =
    crypto.randomBytes(32).toString('hex');

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

        revenue:
          orders
            .filter(
              x => x.status === 'paid'
            )
            .reduce(
              (sum, x) =>
                sum + Number(x.total || 0),
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
    const orders =
      readOrders()
        .sort(
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
    const order =
      readOrders().find(
        x => String(x.id) ===
          String(req.params.id)
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

app.put(
  '/api/admin/orders/:id/status',
  adminAuth,
  (req, res) => {
    const allowed = [
      'new',
      'processing',
      'shipped',
      'delivered',
      'cancelled'
    ];

    const status =
      String(
        req.body?.status || ''
      ).toLowerCase();

    if (!allowed.includes(status)) {
      return res.status(400).json({
        message:
          'Invalid order status.'
      });
    }

    const orders = readOrders();

    const order =
      orders.find(
        x => String(x.id) ===
          String(req.params.id)
      );

    if (!order) {
      return res.status(404).json({
        message: 'Order not found.'
      });
    }

    order.orderStatus = status;

    order.orderStatusUpdatedAt =
      new Date().toISOString();

    writeOrders(orders);

    res.json({
      ok: true,
      order
    });
  }
);

/* =========================================================
   ADMIN PRODUCTS
========================================================= */

app.get(
  '/api/admin/products',
  adminAuth,
  (req, res) => {
    res.json({
      products: readProducts()
    });
  }
);

app.post(
  '/api/admin/products',
  adminAuth,
  (req, res) => {
    const body = req.body || {};

    const name =
      String(body.name || '').trim();

    const category =
      String(
        body.cat ||
        body.category ||
        'Fashion'
      ).trim();

    const price =
      Number(body.price);

    if (
      !name ||
      !Number.isFinite(price) ||
      price < 0
    ) {
      return res.status(400).json({
        message:
          'Product name and valid price are required.'
      });
    }

    const products =
      readProducts();

    const newId =
      products.length
        ? Math.max(
            ...products.map(
              p => Number(p.id) || 0
            )
          ) + 1
        : 1;

    const colors =
      Array.isArray(body.colors)
        ? body.colors
        : String(
            body.color || ''
          )
            .split(',')
            .map(x => x.trim())
            .filter(Boolean);

    const image =
      String(
        body.image || ''
      );

    const images =
      Array.isArray(body.images)
        ? body.images
        : image
          ? [image]
          : [];

    const product = {
      id: newId,

      name,

      cat: category,

      category,

      price,

      color:
        body.color ||
        colors.join(', '),

      colors,

      sizes:
        body.sizes ||
        'Free Size',

      stock:
        Number(body.stock || 0),

      image,

      img: image,

      images,

      desc:
        String(
          body.desc ||
          body.description ||
          ''
        ).slice(0, 1000),

      description:
        String(
          body.desc ||
          body.description ||
          ''
        ).slice(0, 1000)
    };

    products.push(product);

    writeProducts(products);

    res.status(201).json({
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
        p =>
          Number(p.id) ===
          Number(req.params.id)
      );

    if (index < 0) {
      return res.status(404).json({
        message:
          'Product not found.'
      });
    }

    const old =
      products[index];

    const body =
      req.body || {};

    const name =
      String(
        body.name ??
        old.name
      ).trim();

    const category =
      String(
        body.cat ??
        body.category ??
        old.cat
      ).trim();

    const price =
      Number(
        body.price ??
        old.price
      );

    if (
      !name ||
      !Number.isFinite(price) ||
      price < 0
    ) {
      return res.status(400).json({
        message:
          'Product name and valid price are required.'
      });
    }

    const colors =
      Array.isArray(body.colors)
        ? body.colors
        : String(
            body.color ??
            old.color ??
            ''
          )
            .split(',')
            .map(x => x.trim())
            .filter(Boolean);

    const image =
      body.image !== undefined
        ? String(body.image || '')
        : String(
            old.image ||
            old.img ||
            ''
          );

    const images =
      Array.isArray(body.images)
        ? body.images
        : image
          ? [image]
          : (
              Array.isArray(old.images)
                ? old.images
                : []
            );

    const description =
      String(
        body.desc ??
        body.description ??
        old.desc ??
        old.description ??
        ''
      );

    products[index] = {
      ...old,

      id: old.id,

      name,

      cat: category,

      category,

      price,

      color:
        body.color !== undefined
          ? String(body.color)
          : colors.join(', '),

      colors,

      sizes:
        body.sizes !== undefined
          ? String(body.sizes)
          : (
              old.sizes ||
              'Free Size'
            ),

      stock:
        body.stock !== undefined
          ? Number(body.stock)
          : Number(old.stock || 0),

      image,

      img: image,

      images,

      desc: description,

      description
    };

    writeProducts(products);

    res.json({
      product: products[index]
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
        p =>
          Number(p.id) !==
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

/* =========================================================
   ADMIN SETTINGS
========================================================= */

app.get(
  '/api/admin/settings',
  adminAuth,
  (req, res) => {
    res.json({
      store:
        'Face of Style Hijab Factory',

      version:
        '2.0.0',

      database:
        'JSON File Storage',

      databaseConfigured:
        fs.existsSync(PRODUCTS_FILE) &&
        fs.existsSync(ORDERS_FILE),

      paystackConfigured:
        Boolean(
          process.env.PAYSTACK_SECRET_KEY
        ),

      adminConfigured:
        Boolean(
          (
            process.env.ADMIN_USERNAME ||
            process.env.ADMIN_USER
          ) &&
          process.env.ADMIN_PASSWORD
        ),

      whatsapp:
        '0906 582 8886',

      baseUrl:
        BASE_URL
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
            'Paystack is not configured. Add PAYSTACK_SECRET_KEY on Render.'
        });
      }

      const customer =
        req.body?.customer;

      const calculated =
        calculateOrder(
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
            'Incomplete order details or unavailable product.'
        });
      }

      const id =
        crypto.randomUUID();

      const reference =
        createReference();

      const order = {
        id,

        reference,

        status: 'pending',

        orderStatus: 'new',

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
                  calculated.total * 100,

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
        !data.status
      ) {
        order.status =
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
        authorization_url:
          data.data.authorization_url,

        reference
      });

    } catch (error) {
      console.error(
        'PAYSTACK INITIALIZE ERROR:',
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

      const transaction =
        data.data;

      const expected =
        Number(order.total) * 100;

      if (
        data.status &&
        transaction?.status ===
          'success' &&
        Number(transaction.amount) ===
          expected &&
        transaction.currency ===
          'NGN'
      ) {
        order.status =
          'paid';

        order.payment.verifiedAt =
          new Date().toISOString();

        order.payment.channel =
          transaction.channel;

        order.payment.paidAt =
          transaction.paid_at;

        writeOrders(orders);

        return res.json({
          success: true,

          reference
        });
      }

      order.status =
        transaction?.status ===
        'failed'
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
          Number(transaction.amount) ===
            Number(order.total) * 100 &&
          transaction.currency ===
            'NGN'
        ) {
          order.status =
            'paid';

          order.payment.verifiedAt =
            new Date().toISOString();

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
   HEALTH
========================================================= */

app.get(
  '/api/health',
  (req, res) => {
    res.json({
      ok: true,

      version:
        '2.0.0',

      paystackConfigured:
        Boolean(
          process.env.PAYSTACK_SECRET_KEY
        ),

      adminConfigured:
        Boolean(
          (
            process.env.ADMIN_USERNAME ||
            process.env.ADMIN_USER
          ) &&
          process.env.ADMIN_PASSWORD
        ),

      databaseConfigured:
        fs.existsSync(
          PRODUCTS_FILE
        ) &&
        fs.existsSync(
          ORDERS_FILE
        )
    });
  }
);

/* =========================================================
   START
========================================================= */

app.listen(
  PORT,
  () => {
    console.log(
      `Face of Style Version 2 running at ${BASE_URL}`
    );

    console.log(
      `Database: JSON`
    );

    console.log(
      `Paystack configured: ${Boolean(
        process.env.PAYSTACK_SECRET_KEY
      )}`
    );
  }
);
