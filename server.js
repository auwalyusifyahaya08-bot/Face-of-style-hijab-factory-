import 'dotenv/config';
import express from 'express';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';

const app = express();

/* =========================================================
   PATHS
========================================================= */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);

const BASE_URL =
  (process.env.BASE_URL ||
    `http://localhost:${PORT}`).replace(/\/$/, '');

const PUBLIC_DIR = path.join(__dirname, 'public');
const ASSETS_DIR = path.join(PUBLIC_DIR, 'assets');
const DATA_DIR = path.join(__dirname, 'data');

const ORDERS_FILE =
  path.join(DATA_DIR, 'orders.json');

const PRODUCTS_FILE =
  path.join(DATA_DIR, 'products.json');

const CUSTOMERS_FILE =
  path.join(DATA_DIR, 'customers.json');

const SETTINGS_FILE =
  path.join(DATA_DIR, 'settings.json');


/* =========================================================
   DIRECTORY INITIALIZATION
========================================================= */

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });
fs.mkdirSync(ASSETS_DIR, { recursive: true });


/* =========================================================
   JSON INITIALIZER
========================================================= */

function ensureJson(file, fallback) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(
      file,
      JSON.stringify(fallback, null, 2),
      'utf8'
    );
  }
}


/* =========================================================
   DEFAULT PRODUCTS
========================================================= */

ensureJson(PRODUCTS_FILE, [
  {
    id: 1,
    name: 'Elegant Zip Abaya',
    cat: 'Abaya',
    category: 'Abaya',
    price: 25000,
    color: '',
    stock: 99,
    active: true,
    image: '/assets/product-1.jpg',
    desc: 'Flowing full-length abaya with refined finishing.'
  },
  {
    id: 2,
    name: 'Two-Tone Signature Gown',
    cat: 'Gown',
    category: 'Gown',
    price: 22000,
    color: '',
    stock: 99,
    active: true,
    image: '/assets/product-2.jpg',
    desc: 'Elegant two-tone modest gown design.'
  },
  {
    id: 3,
    name: 'Teal Classic Hijab Dress',
    cat: 'Gown',
    category: 'Gown',
    price: 20000,
    color: '',
    stock: 99,
    active: true,
    image: '/assets/product-3.jpg',
    desc: 'Comfortable modest dress with clean detailing.'
  },
  {
    id: 4,
    name: 'Premium Black & White',
    cat: 'Abaya',
    category: 'Abaya',
    price: 28000,
    color: '',
    stock: 99,
    active: true,
    image: '/assets/product-4.jpg',
    desc: 'Statement modest outfit with premium contrast.'
  },
  {
    id: 5,
    name: 'Ruffle Hijab Collection',
    cat: 'Hijab',
    category: 'Hijab',
    price: 12000,
    color: '',
    stock: 99,
    active: true,
    image: '/assets/product-5.jpg',
    desc: 'Soft, colourful hijab styles with beautiful ruffles.'
  },
  {
    id: 6,
    name: 'Rose Signature Gown',
    cat: 'Custom',
    category: 'Custom',
    price: 24000,
    color: '',
    stock: 99,
    active: true,
    image: '/assets/product-6.jpg',
    desc: 'Elegant flowing gown; custom colours available.'
  }
]);


/* =========================================================
   DEFAULT SETTINGS
========================================================= */

ensureJson(SETTINGS_FILE, {
  storeName: 'Face of Style Hijab Factory',
  tagline: 'HIJAB FACTORY',

  whatsapp: '09065828886',
  phone: '09065828886',
  email: '',
  address: 'Kano, Nigeria',

  primaryColor: '#651630',
  secondaryColor: '#4d1024',
  goldColor: '#c9a45b',
  backgroundColor: '#fcf8f1',
  textColor: '#251c20',

  logo: '/assets/logo.png',

  /*
     IMPORTANT:
     Hero image now points to /assets/
  */
  heroImage: '/assets/product-1.jpg',

  heroTitle: 'Modesty, Elegance & Style.',
  heroText:
    'Discover carefully crafted hijabs, abayas, gowns and modest outfits.',

  aboutText:
    'Elegant hijabs, abayas, gowns and custom modest wear.',

  deliveryText:
    'Delivery is available. Contact us for delivery arrangements.',

  deliveryFee: 0,
  freeDeliveryFrom: 0,

  bankName: '',
  accountName: '',
  accountNumber: '',
  bankInstructions:
    'Please contact the store for bank transfer instructions.',

  enableCart: true,
  enableWhatsapp: true,
  showStock: true,

  lowStockLimit: 5
});


/* =========================================================
   OTHER DATA FILES
========================================================= */

ensureJson(ORDERS_FILE, []);
ensureJson(CUSTOMERS_FILE, []);


/* =========================================================
   JSON HELPERS
========================================================= */

function readJson(file, fallback) {
  try {
    if (!fs.existsSync(file)) {
      return fallback;
    }

    const content =
      fs.readFileSync(file, 'utf8');

    if (!content.trim()) {
      return fallback;
    }

    return JSON.parse(content);
  } catch (error) {
    console.error(
      `Failed to read ${file}:`,
      error.message
    );

    return fallback;
  }
}


function writeJson(file, value) {
  const tempFile =
    `${file}.tmp`;

  fs.writeFileSync(
    tempFile,
    JSON.stringify(value, null, 2),
    'utf8'
  );

  fs.renameSync(
    tempFile,
    file
  );
}


function readProducts() {
  return readJson(
    PRODUCTS_FILE,
    []
  );
}


function writeProducts(products) {
  writeJson(
    PRODUCTS_FILE,
    products
  );
}


function readOrders() {
  return readJson(
    ORDERS_FILE,
    []
  );
}


function writeOrders(orders) {
  writeJson(
    ORDERS_FILE,
    orders
  );
}


function readCustomers() {
  return readJson(
    CUSTOMERS_FILE,
    []
  );
}


function writeCustomers(customers) {
  writeJson(
    CUSTOMERS_FILE,
    customers
  );
}


function readSettings() {
  return {
    ...readJson(
      SETTINGS_FILE,
      {}
    )
  };
}


function writeSettings(settings) {
  writeJson(
    SETTINGS_FILE,
    settings
  );
}


/* =========================================================
   ENVIRONMENT
========================================================= */

const ADMIN_USER =
  process.env.ADMIN_USER ||
  process.env.ADMIN_USERNAME ||
  '';

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD ||
  '';

const PAYSTACK_SECRET =
  process.env.PAYSTACK_SECRET_KEY ||
  '';

const WHATSAPP =
  process.env.WHATSAPP_NUMBER ||
  readSettings().whatsapp ||
  '09065828886';

const CALLBACK_URL =
  process.env.PAYSTACK_CALLBACK_URL ||
  `${BASE_URL}/payment-success.html`;


/* =========================================================
   SESSIONS
========================================================= */

const adminSessions =
  new Set();

const customerSessions =
  new Map();


/* =========================================================
   BODY PARSER
========================================================= */

app.use(
  express.json({
    limit: '12mb',

    verify(req, res, buffer) {
      req.rawBody = buffer;
    }
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '2mb'
  })
);


/* =========================================================
   HELPERS
========================================================= */

function clean(value, max = 500) {
  return String(
    value ?? ''
  )
    .trim()
    .slice(0, max);
}


function positiveInt(value, fallback = 0) {
  const number =
    Number(value);

  return (
    Number.isInteger(number) &&
    number >= 0
  )
    ? number
    : fallback;
}


function safePrice(value) {
  const number =
    Number(value);

  if (
    !Number.isFinite(number) ||
    number < 0
  ) {
    return NaN;
  }

  return Math.round(
    number * 100
  ) / 100;
}


function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    String(value || '').trim()
  );
}


function validPhone(value) {
  return String(
    value || ''
  )
    .trim()
    .length >= 7;
}


function passwordHash(password) {
  const salt =
    crypto
      .randomBytes(16)
      .toString('hex');

  const hash =
    crypto.scryptSync(
      String(password),
      salt,
      64
    ).toString('hex');

  return `${salt}:${hash}`;
}


function verifyPassword(password, stored) {
  try {
    const [
      salt,
      hashHex
    ] =
      String(
        stored || ''
      ).split(':');

    if (!salt || !hashHex) {
      return false;
    }

    const actual =
      crypto.scryptSync(
        String(password),
        salt,
        64
      );

    const expected =
      Buffer.from(
        hashHex,
        'hex'
      );

    return (
      actual.length ===
        expected.length &&
      crypto.timingSafeEqual(
        actual,
        expected
      )
    );
  } catch {
    return false;
  }
}


function token() {
  return crypto
    .randomBytes(32)
    .toString('hex');
}


function orderReference() {
  return (
    `FS-${Date.now()}-${crypto
      .randomBytes(3)
      .toString('hex')}`
  ).toUpperCase();
}


/* =========================================================
   IMAGE NORMALIZATION
   IMPORTANT FIX FOR /assets/ PATH
========================================================= */

function normalizeImage(
  value,
  fallback = '/assets/product-1.jpg'
) {
  let v =
    clean(
      value,
      8000000
    );

  if (!v) {
    return fallback;
  }

  /*
     Convert Windows/backslash paths.
  */
  v = v.replace(/\\/g, '/');

  /*
     Remove ./ at beginning.
  */
  v = v.replace(/^\.\/+/i, '');

  /*
     Existing assets path remains unchanged.
  */
  if (
    /^\/assets\//i.test(v)
  ) {
    return v;
  }

  /*
     Convert assets/product-x.jpg
     to /assets/product-x.jpg
  */
  if (
    /^assets\//i.test(v)
  ) {
    return `/${v}`;
  }

  /*
     Convert /product-x.jpg
     to /assets/product-x.jpg
  */
  if (
    /^\/[^/]+\.(jpg|jpeg|png|webp|gif|svg)$/i.test(v)
  ) {
    return `/assets${v}`;
  }

  /*
     Convert product-x.jpg
     to /assets/product-x.jpg
  */
  if (
    /^[^/]+\.(jpg|jpeg|png|webp|gif|svg)$/i.test(v)
  ) {
    return `/assets/${v}`;
  }

  /*
     External image.
  */
  if (
    /^https?:\/\//i.test(v)
  ) {
    return v;
  }

  /*
     Base64 image.
  */
  if (
    /^data:image\//i.test(v)
  ) {
    return v;
  }

  /*
     Other absolute paths.
  */
  if (
    v.startsWith('/')
  ) {
    return v;
  }

  return `/${v}`;
}


/* =========================================================
   PUBLIC PRODUCT FORMAT
========================================================= */

function publicProduct(product) {
  const category =
    product.cat ||
    product.category ||
    'Custom';

  const image =
    normalizeImage(
      product.image ||
      product.img,
      `/assets/product-${product.id || 1}.jpg`
    );

  return {
    id: product.id,

    name:
      product.name || '',

    cat:
      category,

    category:
      category,

    price:
      Number(product.price || 0),

    color:
      product.color || '',

    stock:
      positiveInt(
        product.stock,
        0
      ),

    active:
      product.active !== false,

    image,

    img:
      image,

    desc:
      product.desc ||
      product.description ||
      '',

    description:
      product.desc ||
      product.description ||
      '',

    createdAt:
      product.createdAt || null,

    updatedAt:
      product.updatedAt || null
  };
}


/* =========================================================
   CUSTOMER FORMAT
========================================================= */

function publicCustomer(customer) {
  return {
    id: customer.id,
    name: customer.name,
    email: customer.email,
    phone: customer.phone
  };
}


/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function getBearerToken(req) {
  const header =
    req.headers.authorization || '';

  if (
    !header.startsWith('Bearer ')
  ) {
    return '';
  }

  return header.slice(7).trim();
}


function adminAuth(req, res, next) {
  const sessionToken =
    getBearerToken(req);

  if (
    !sessionToken ||
    !adminSessions.has(sessionToken)
  ) {
    return res
      .status(401)
      .json({
        message: 'Unauthorized'
      });
  }

  next();
}


function customerAuth(req, res, next) {
  const sessionToken =
    getBearerToken(req);

  const customerId =
    customerSessions.get(
      sessionToken
    );

  if (!customerId) {
    return res
      .status(401)
      .json({
        message:
          'Please login first.'
      });
  }

  req.customerId =
    customerId;

  req.customerToken =
    sessionToken;

  next();
}


/* =========================================================
   FIND HELPERS
========================================================= */

function getCustomer(id) {
  return readCustomers()
    .find(
      customer =>
        customer.id === id
    );
}


function getOrder(id) {
  return readOrders()
    .find(
      order =>
        String(order.id) ===
        String(id)
    );
}


/* =========================================================
   ORDER CALCULATION
========================================================= */

function calculateItems(items) {
  if (
    !Array.isArray(items) ||
    items.length === 0
  ) {
    return null;
  }

  const products =
    readProducts();

  const cleanItems = [];

  let total = 0;

  for (
    const raw of items
  ) {
    const product =
      products.find(
        item =>
          String(item.id) ===
            String(raw?.id) &&
          item.active !== false
      );

    const qty =
      Number(raw?.qty);

    if (
      !product ||
      !Number.isInteger(qty) ||
      qty < 1 ||
      qty > 99
    ) {
      return null;
    }

    const stock =
      positiveInt(
        product.stock,
        0
      );

    if (stock < qty) {
      return {
        error:
          `Only ${stock} item(s) available for ${product.name}.`
      };
    }

    const productPrice =
      safePrice(product.price);

    if (
      !Number.isFinite(
        productPrice
      )
    ) {
      return {
        error:
          `Invalid price for ${product.name}.`
      };
    }

    total +=
      productPrice * qty;

    cleanItems.push({
      id:
        product.id,

      name:
        product.name,

      price:
        productPrice,

      qty,

      image:
        normalizeImage(
          product.image ||
          product.img,
          `/assets/product-${product.id}.jpg`
        )
    });
  }

  return {
    items:
      cleanItems,

    total:
      Math.round(
        total * 100
      ) / 100
  };
}


/* =========================================================
   STOCK DECREASE
========================================================= */

function decrementStock(items) {
  const products =
    readProducts();

  for (
    const item of items
  ) {
    const product =
      products.find(
        product =>
          String(product.id) ===
          String(item.id)
      );

    if (!product) {
      continue;
    }

    product.stock =
      Math.max(
        0,
        positiveInt(
          product.stock,
          0
        ) -
        positiveInt(
          item.qty,
          0
        )
      );

    product.updatedAt =
      new Date().toISOString();
  }

  writeProducts(
    products
  );
}


/* =========================================================
   CHECK STOCK AGAIN
========================================================= */

function validateStock(items) {
  const products =
    readProducts();

  for (
    const item of items
  ) {
    const product =
      products.find(
        p =>
          String(p.id) ===
          String(item.id)
      );

    if (!product) {
      return {
        ok: false,
        message:
          'One of the selected products no longer exists.'
      };
    }

    const stock =
      positiveInt(
        product.stock,
        0
      );

    const qty =
      positiveInt(
        item.qty,
        0
      );

    if (stock < qty) {
      return {
        ok: false,
        message:
          `Only ${stock} item(s) available for ${product.name}.`
      };
    }
  }

  return {
    ok: true
  };
}


/* =========================================================
   PUBLIC HOME
========================================================= */

app.get(
  '/',
  (req, res) => {
    const file =
      path.join(
        PUBLIC_DIR,
        'index.html'
      );

    if (
      fs.existsSync(file)
    ) {
      return res.sendFile(file);
    }

    res
      .status(404)
      .send('index.html not found.');
  }
);


/* =========================================================
   ADMIN PAGE
========================================================= */

app.get(
  '/admin',
  (req, res) => {
    const file =
      path.join(
        PUBLIC_DIR,
        'admin.html'
      );

    if (
      fs.existsSync(file)
    ) {
      return res.sendFile(file);
    }

    res
      .status(404)
      .send('admin.html not found.');
  }
);


app.get(
  '/admin.html',
  (req, res) => {
    const file =
      path.join(
        PUBLIC_DIR,
        'admin.html'
      );

    if (
      fs.existsSync(file)
    ) {
      return res.sendFile(file);
    }

    res
      .status(404)
      .send('admin.html not found.');
  }
);


/* =========================================================
   PUBLIC PRODUCTS
========================================================= */

app.get(
  '/api/products',
  (req, res) => {
    const products =
      readProducts()
        .filter(
          product =>
            product.active !== false
        )
        .map(
          publicProduct
        );

    res.json({
      products
    });
  }
);


/* =========================================================
   PUBLIC CONFIG
========================================================= */

app.get(
  '/api/config',
  (req, res) => {
    const settings =
      readSettings();

    /*
       Always normalize settings images.
    */
    settings.logo =
      normalizeImage(
        settings.logo,
        '/assets/logo.png'
      );

    settings.heroImage =
      normalizeImage(
        settings.heroImage,
        '/assets/product-1.jpg'
      );

    res.json({
      store:
        settings,

      settings:
        settings,

      whatsapp:
        WHATSAPP,

      paystackConfigured:
        Boolean(PAYSTACK_SECRET),

      customerAuthEnabled:
        true
    });
  }
);


/* =========================================================
   CUSTOMER SIGNUP
========================================================= */

app.post(
  '/api/customer/signup',
  (req, res) => {
    const name =
      clean(
        req.body?.name,
        120
      );

    const email =
      clean(
        req.body?.email,
        200
      ).toLowerCase();

    const phone =
      clean(
        req.body?.phone,
        40
      );

    const password =
      String(
        req.body?.password || ''
      );

    if (
      !name ||
      !validEmail(email) ||
      !validPhone(phone) ||
      password.length < 6
    ) {
      return res
        .status(400)
        .json({
          message:
            'Name, valid email, phone and a password of at least 6 characters are required.'
        });
    }

    const customers =
      readCustomers();

    if (
      customers.some(
        customer =>
          customer.email ===
          email
      )
    ) {
      return res
        .status(409)
        .json({
          message:
            'An account with this email already exists.'
        });
    }

    const customer = {
      id:
        crypto.randomUUID(),

      name,

      email,

      phone,

      passwordHash:
        passwordHash(password),

      createdAt:
        new Date().toISOString()
    };

    customers.push(
      customer
    );

    writeCustomers(
      customers
    );

    const sessionToken =
      token();

    customerSessions.set(
      sessionToken,
      customer.id
    );

    res
      .status(201)
      .json({
        token:
          sessionToken,

        customer:
          publicCustomer(
            customer
          )
      });
  }
);


/* =========================================================
   CUSTOMER LOGIN
========================================================= */

app.post(
  '/api/customer/login',
  (req, res) => {
    const email =
      clean(
        req.body?.email,
        200
      ).toLowerCase();

    const password =
      String(
        req.body?.password || ''
      );

    const customer =
      readCustomers()
        .find(
          item =>
            item.email ===
            email
        );

    if (
      !customer ||
      !verifyPassword(
        password,
        customer.passwordHash
      )
    ) {
      return res
        .status(401)
        .json({
          message:
            'Invalid email or password.'
        });
    }

    const sessionToken =
      token();

    customerSessions.set(
      sessionToken,
      customer.id
    );

    res.json({
      token:
        sessionToken,

      customer:
        publicCustomer(
          customer
        )
    });
  }
);


/* =========================================================
   CUSTOMER LOGOUT
========================================================= */

app.post(
  '/api/customer/logout',
  customerAuth,
  (req, res) => {
    customerSessions.delete(
      req.customerToken
    );

    res.json({
      ok: true
    });
  }
);


/* =========================================================
   CUSTOMER ME
========================================================= */

app.get(
  '/api/customer/me',
  customerAuth,
  (req, res) => {
    const customer =
      getCustomer(
        req.customerId
      );

    if (!customer) {
      return res
        .status(404)
        .json({
          message:
            'Customer account not found.'
        });
    }

    res.json({
      customer:
        publicCustomer(
          customer
        )
    });
  }
);


/* =========================================================
   CUSTOMER PROFILE
========================================================= */

app.put(
  '/api/customer/profile',
  customerAuth,
  (req, res) => {
    const customers =
      readCustomers();

    const index =
      customers.findIndex(
        customer =>
          customer.id ===
          req.customerId
      );

    if (index < 0) {
      return res
        .status(404)
        .json({
          message:
            'Customer account not found.'
        });
    }

    const name =
      clean(
        req.body?.name,
        120
      );

    const phone =
      clean(
        req.body?.phone,
        40
      );

    if (
      !name ||
      !validPhone(phone)
    ) {
      return res
        .status(400)
        .json({
          message:
            'Name and valid phone are required.'
        });
    }

    customers[index].name =
      name;

    customers[index].phone =
      phone;

    writeCustomers(
      customers
    );

    res.json({
      customer:
        publicCustomer(
          customers[index]
        )
    });
  }
);


/* =========================================================
   CUSTOMER ORDERS
========================================================= */

app.get(
  '/api/customer/orders',
  customerAuth,
  (req, res) => {
    const customer =
      getCustomer(
        req.customerId
      );

    if (!customer) {
      return res
        .status(404)
        .json({
          message:
            'Customer account not found.'
        });
    }

    const orders =
      readOrders()
        .filter(
          order =>
            order.customer?.customerId ===
              customer.id ||
            (
              !order.customer?.customerId &&
              order.customer?.email ===
                customer.email
            )
        )
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


/* =========================================================
   CUSTOMER SINGLE ORDER
========================================================= */

app.get(
  '/api/customer/orders/:reference',
  customerAuth,
  (req, res) => {
    const customer =
      getCustomer(
        req.customerId
      );

    const reference =
      clean(
        req.params.reference,
        100
      ).toUpperCase();

    const order =
      readOrders()
        .find(
          item =>
            String(
              item.reference
            ).toUpperCase() ===
              reference &&
            (
              item.customer?.customerId ===
                customer?.id ||
              item.customer?.email ===
                customer?.email
            )
        );

    if (!order) {
      return res
        .status(404)
        .json({
          message:
            'Order not found.'
        });
    }

    res.json({
      order
    });
  }
);


/* =========================================================
   PUBLIC ORDER TRACKING
========================================================= */

app.get(
  '/api/track-order/:reference',
  (req, res) => {
    const reference =
      clean(
        req.params.reference,
        100
      ).toUpperCase();

    const phone =
      clean(
        req.query.phone,
        40
      );

    const email =
      clean(
        req.query.email,
        200
      ).toLowerCase();

    const order =
      readOrders()
        .find(
          item =>
            String(
              item.reference
            ).toUpperCase() ===
            reference
        );

    if (!order) {
      return res
        .status(404)
        .json({
          message:
            'Order not found.'
        });
    }

    const phoneMatches =
      phone &&
      order.customer?.phone ===
        phone;

    const emailMatches =
      email &&
      order.customer?.email ===
        email;

    if (
      !phoneMatches &&
      !emailMatches
    ) {
      return res
        .status(403)
        .json({
          message:
            'Please provide the phone number or email used for this order.'
        });
    }

    res.json({
      order
    });
  }
);


/* =========================================================
   CREATE PENDING ORDER
========================================================= */

function createPendingOrder(
  customer,
  calculated,
  paymentProvider = 'paystack'
) {
  const now =
    new Date().toISOString();

  return {
    id:
      crypto.randomUUID(),

    reference:
      orderReference(),

    status:
      'pending',

    orderStatus:
      'new',

    customer,

    items:
      calculated.items,

    total:
      calculated.total,

    currency:
      'NGN',

    payment: {
      provider:
        paymentProvider
    },

    createdAt:
      now,

    updatedAt:
      now
  };
}


/* =========================================================
   WHATSAPP ORDER
========================================================= */

app.post(
  '/api/orders/whatsapp',
  customerAuth,
  (req, res) => {
    const customer =
      getCustomer(
        req.customerId
      );

    const calculated =
      calculateItems(
        req.body?.items
      );

    if (!customer) {
      return res
        .status(401)
        .json({
          message:
            'Customer account not found.'
        });
    }

    if (
      !calculated ||
      calculated.error
    ) {
      return res
        .status(400)
        .json({
          message:
            calculated?.error ||
            'Invalid order.'
        });
    }

    const address =
      clean(
        req.body?.address,
        500
      );

    if (!address) {
      return res
        .status(400)
        .json({
          message:
            'Delivery address is required.'
        });
    }

    const stockCheck =
      validateStock(
        calculated.items
      );

    if (!stockCheck.ok) {
      return res
        .status(400)
        .json({
          message:
            stockCheck.message
        });
    }

    const order =
      createPendingOrder(
        {
          customerId:
            customer.id,

          name:
            customer.name,

          email:
            customer.email,

          phone:
            customer.phone,

          address
        },

        calculated,

        'whatsapp'
      );

    const orders =
      readOrders();

    orders.push(
      order
    );

    writeOrders(
      orders
    );

    res
      .status(201)
      .json({
        order,

        whatsapp:
          WHATSAPP
      });
  }
);


/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
  '/api/admin/login',
  (req, res) => {
    const username =
      clean(
        req.body?.username,
        100
      );

    const password =
      String(
        req.body?.password || ''
      );

    if (
      !ADMIN_USER ||
      !ADMIN_PASSWORD
    ) {
      return res
        .status(503)
        .json({
          message:
            'Admin credentials are not configured on the server.'
        });
    }

    if (
      username !== ADMIN_USER ||
      password !== ADMIN_PASSWORD
    ) {
      return res
        .status(401)
        .json({
          message:
            'Invalid username or password.'
        });
    }

    const sessionToken =
      token();

    adminSessions.add(
      sessionToken
    );

    res.json({
      token:
        sessionToken
    });
  }
);


/* =========================================================
   ADMIN ME
========================================================= */

app.get(
  '/api/admin/me',
  adminAuth,
  (req, res) => {
    res.json({
      authenticated:
        true
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
    adminSessions.delete(
      getBearerToken(req)
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
  (req, res) => {
    const orders =
      readOrders();

    const products =
      readProducts();

    res.json({
      stats: {
        orders:
          orders.length,

        paid:
          orders.filter(
            order =>
              order.status ===
              'paid'
          ).length,

        pending:
          orders.filter(
            order =>
              order.status ===
              'pending'
          ).length,

        failed:
          orders.filter(
            order =>
              order.status ===
              'failed'
          ).length,

        processing:
          orders.filter(
            order =>
              order.orderStatus ===
              'processing'
          ).length,

        ready:
          orders.filter(
            order =>
              order.orderStatus ===
              'ready'
          ).length,

        shipped:
          orders.filter(
            order =>
              order.orderStatus ===
              'shipped'
          ).length,

        delivered:
          orders.filter(
            order =>
              order.orderStatus ===
              'delivered'
          ).length,

        cancelled:
          orders.filter(
            order =>
              order.orderStatus ===
              'cancelled'
          ).length,

        revenue:
          orders
            .filter(
              order =>
                order.status ===
                'paid'
            )
            .reduce(
              (
                total,
                order
              ) =>
                total +
                Number(
                  order.total || 0
                ),
              0
            ),

        products:
          products.filter(
            product =>
              product.active !== false
          ).length,

        lowStock:
          products.filter(
            product =>
              product.active !== false &&
              positiveInt(
                product.stock,
                0
              ) <=
              positiveInt(
                readSettings()
                  .lowStockLimit,
                5
              )
          ).length,

        outOfStock:
          products.filter(
            product =>
              positiveInt(
                product.stock,
                0
              ) <= 0
          ).length
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
    res.json({
      orders:
        readOrders()
          .sort(
            (a, b) =>
              new Date(
                b.createdAt
              ) -
              new Date(
                a.createdAt
              )
          )
    });
  }
);


/* =========================================================
   ADMIN SINGLE ORDER
========================================================= */

app.get(
  '/api/admin/orders/:id',
  adminAuth,
  (req, res) => {
    const order =
      getOrder(
        req.params.id
      );

    if (!order) {
      return res
        .status(404)
        .json({
          message:
            'Order not found.'
        });
    }

    res.json({
      order
    });
  }
);


/* =========================================================
   ADMIN ORDER STATUS
========================================================= */

app.put(
  '/api/admin/orders/:id/status',
  adminAuth,
  (req, res) => {
    const allowed = [
      'new',
      'processing',
      'ready',
      'shipped',
      'delivered',
      'cancelled'
    ];

    const status =
      clean(
        req.body?.status,
        30
      ).toLowerCase();

    if (
      !allowed.includes(status)
    ) {
      return res
        .status(400)
        .json({
          message:
            'Invalid order status.'
        });
    }

    const orders =
      readOrders();

    const order =
      orders.find(
        item =>
          String(item.id) ===
          String(req.params.id)
      );

    if (!order) {
      return res
        .status(404)
        .json({
          message:
            'Order not found.'
        });
    }

    order.orderStatus =
      status;

    order.updatedAt =
      new Date().toISOString();

    writeOrders(
      orders
    );

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
      products:
        readProducts()
          .map(
            publicProduct
          )
    });
  }
);


/* =========================================================
   PRODUCT PAYLOAD
========================================================= */

function productPayload(
  body,
  old = {}
) {
  const name =
    clean(
      body?.name,
      120
    );

  const category =
    clean(
      body?.cat ||
      body?.category,
      40
    ) ||
    'Custom';

  const productPrice =
    safePrice(
      body?.price
    );

  if (
    !name ||
    !Number.isFinite(
      productPrice
    )
  ) {
    return {
      error:
        'Product name and valid price are required.'
    };
  }

  const stock =
    positiveInt(
      body?.stock,
      positiveInt(
        old.stock,
        0
      )
    );

  let active;

  if (
    body?.active ===
    undefined
  ) {
    active =
      old.active !== false;
  } else {
    /*
       Support boolean and string values.
    */
    if (
      typeof body.active ===
      'string'
    ) {
      active =
        body.active !== 'false' &&
        body.active !== '0';
    } else {
      active =
        Boolean(
          body.active
        );
    }
  }

  let image;

  if (
    body?.image ===
    undefined
  ) {
    image =
      old.image ||
      old.img ||
      `/assets/product-${old.id || 1}.jpg`;
  } else {
    image =
      body.image;
  }

  image =
    normalizeImage(
      image,
      `/assets/product-${old.id || 1}.jpg`
    );

  /*
     Base64 image size protection.
  */
  if (
    image.startsWith(
      'data:image/'
    ) &&
    image.length >
      7000000
  ) {
    return {
      error:
        'Product image is too large. Please use an image under about 5MB.'
    };
  }

  return {
    name,

    cat:
      category,

    category:
      category,

    price:
      productPrice,

    color:
      clean(
        body?.color,
        200
      ),

    stock,

    active,

    image,

    img:
      image,

    desc:
      clean(
        body?.desc ||
        body?.description,
        1000
      )
  };
}


/* =========================================================
   ADD PRODUCT
========================================================= */

app.post(
  '/api/admin/products',
  adminAuth,
  (req, res) => {
    const products =
      readProducts();

    const payload =
      productPayload(
        req.body
      );

    if (
      payload.error
    ) {
      return res
        .status(400)
        .json({
          message:
            payload.error
        });
    }

    const id =
      products.length
        ? Math.max(
            ...products.map(
              item =>
                Number(
                  item.id
                ) || 0
            )
          ) + 1
        : 1;

    /*
       If admin uploads image as base64,
       keep it. If normal path, normalize it.
    */
    const product = {
      id,

      ...payload,

      createdAt:
        new Date().toISOString(),

      updatedAt:
        new Date().toISOString()
    };

    products.push(
      product
    );

    writeProducts(
      products
    );

    res
      .status(201)
      .json({
        product:
          publicProduct(
            product
          )
      });
  }
);


/* =========================================================
   EDIT PRODUCT
========================================================= */

app.put(
  '/api/admin/products/:id',
  adminAuth,
  (req, res) => {
    const products =
      readProducts();

    const index =
      products.findIndex(
        item =>
          String(item.id) ===
          String(req.params.id)
      );

    if (index < 0) {
      return res
        .status(404)
        .json({
          message:
            'Product not found.'
        });
    }

    const payload =
      productPayload(
        req.body,
        products[index]
      );

    if (
      payload.error
    ) {
      return res
        .status(400)
        .json({
          message:
            payload.error
        });
    }

    products[index] = {
      ...products[index],

      ...payload,

      updatedAt:
        new Date().toISOString()
    };

    writeProducts(
      products
    );

    res.json({
      product:
        publicProduct(
          products[index]
        )
    });
  }
);


/* =========================================================
   DELETE PRODUCT
========================================================= */

app.delete(
  '/api/admin/products/:id',
  adminAuth,
  (req, res) => {
    const products =
      readProducts();

    const next =
      products.filter(
        item =>
          String(item.id) !==
          String(req.params.id)
      );

    if (
      next.length ===
      products.length
    ) {
      return res
        .status(404)
        .json({
          message:
            'Product not found.'
        });
    }

    writeProducts(
      next
    );

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
    const settings =
      readSettings();

    settings.logo =
      normalizeImage(
        settings.logo,
        '/assets/logo.png'
      );

    settings.heroImage =
      normalizeImage(
        settings.heroImage,
        '/assets/product-1.jpg'
      );

    res.json({
      settings,

      paystackConfigured:
        Boolean(
          PAYSTACK_SECRET
        ),

      whatsapp:
        WHATSAPP
    });
  }
);


/* =========================================================
   SAVE SETTINGS
========================================================= */

app.put(
  '/api/admin/settings',
  adminAuth,
  (req, res) => {
    const old =
      readSettings();

    const body =
      req.body || {};

    const next = {
      ...old,

      storeName:
        clean(
          body.storeName,
          120
        ) ||
        old.storeName ||
        'Face of Style Hijab Factory',

      tagline:
        clean(
          body.tagline,
          120
        ),

      whatsapp:
        clean(
          body.whatsapp,
          30
        ),

      phone:
        clean(
          body.phone,
          30
        ),

      email:
        clean(
          body.email,
          200
        ),

      address:
        clean(
          body.address,
          300
        ),

      primaryColor:
        clean(
          body.primaryColor,
          20
        ),

      secondaryColor:
        clean(
          body.secondaryColor,
          20
        ),

      goldColor:
        clean(
          body.goldColor,
          20
        ),

      backgroundColor:
        clean(
          body.backgroundColor,
          20
        ),

      textColor:
        clean(
          body.textColor,
          20
        ),

      logo:
        normalizeImage(
          body.logo,
          old.logo ||
          '/assets/logo.png'
        ),

      heroImage:
        normalizeImage(
          body.heroImage,
          old.heroImage ||
          '/assets/product-1.jpg'
        ),

      heroTitle:
        clean(
          body.heroTitle,
          200
        ),

      heroText:
        clean(
          body.heroText,
          500
        ),

      aboutText:
        clean(
          body.aboutText,
          1000
        ),

      deliveryText:
        clean(
          body.deliveryText,
          1000
        ),

      deliveryFee:
        positiveInt(
          body.deliveryFee,
          old.deliveryFee || 0
        ),

      freeDeliveryFrom:
        positiveInt(
          body.freeDeliveryFrom,
          old.freeDeliveryFrom || 0
        ),

      bankName:
        clean(
          body.bankName,
          120
        ),

      accountName:
        clean(
          body.accountName,
          120
        ),

      accountNumber:
        clean(
          body.accountNumber,
          80
        ),

      bankInstructions:
        clean(
          body.bankInstructions,
          1000
        ),

      enableCart:
        body.enableCart ===
        undefined
          ? old.enableCart !== false
          : Boolean(
              body.enableCart
            ),

      enableWhatsapp:
        body.enableWhatsapp ===
        undefined
          ? old.enableWhatsapp !== false
          : Boolean(
              body.enableWhatsapp
            ),

      showStock:
        body.showStock ===
        undefined
          ? old.showStock !== false
          : Boolean(
              body.showStock
            ),

      lowStockLimit:
        positiveInt(
          body.lowStockLimit,
          old.lowStockLimit || 5
        )
    };

    writeSettings(
      next
    );

    res.json({
      settings:
        next
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
      if (!PAYSTACK_SECRET) {
        return res
          .status(500)
          .json({
            message:
              'Paystack is not configured. Add PAYSTACK_SECRET_KEY on the server.'
          });
      }

      const customer =
        req.body?.customer;

      const calculated =
        calculateItems(
          req.body?.items
        );

      if (
        !customer?.name ||
        !validEmail(
          customer?.email
        ) ||
        !validPhone(
          customer?.phone
        ) ||
        !customer?.address ||
        !calculated ||
        calculated.error
      ) {
        return res
          .status(400)
          .json({
            message:
              calculated?.error ||
              'Incomplete order details.'
          });
      }

      const stockCheck =
        validateStock(
          calculated.items
        );

      if (!stockCheck.ok) {
        return res
          .status(400)
          .json({
            message:
              stockCheck.message
          });
      }

      const customerId =
        req.body?.customerId ||
        null;

      const order =
        createPendingOrder(
          {
            customerId,

            name:
              clean(
                customer.name,
                120
              ),

            email:
              clean(
                customer.email,
                200
              ).toLowerCase(),

            phone:
              clean(
                customer.phone,
                40
              ),

            address:
              clean(
                customer.address,
                500
              )
          },

          calculated,

          'paystack'
        );

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
                `Bearer ${PAYSTACK_SECRET}`,

              'Content-Type':
                'application/json'
            },

            body:
              JSON.stringify({
                email:
                  order.customer.email,

                amount:
                  Math.round(
                    order.total * 100
                  ),

                currency:
                  'NGN',

                reference:
                  order.reference,

                callback_url:
                  CALLBACK_URL,

                metadata: {
                  order_id:
                    order.id
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

        order.updatedAt =
          new Date().toISOString();

        writeOrders(
          orders
        );

        return res
          .status(400)
          .json({
            message:
              data.message ||
              'Paystack initialization failed.'
          });
      }

      res.json({
        authorization_url:
          data.data.authorization_url,

        reference:
          order.reference
      });

    } catch (error) {
      console.error(
        'Paystack initialize error:',
        error
      );

      res
        .status(500)
        .json({
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
      if (!PAYSTACK_SECRET) {
        return res
          .status(500)
          .json({
            message:
              'Paystack is not configured.'
          });
      }

      const reference =
        clean(
          req.params.reference,
          100
        );

      const orders =
        readOrders();

      const order =
        orders.find(
          item =>
            item.reference ===
            reference
        );

      if (!order) {
        return res
          .status(404)
          .json({
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
                `Bearer ${PAYSTACK_SECRET}`
            }
          }
        );

      const data =
        await response.json();

      const transaction =
        data.data;

      if (
        data.status &&
        transaction?.status ===
          'success' &&
        Number(
          transaction.amount
        ) ===
          Math.round(
            order.total * 100
          ) &&
        transaction.currency ===
          'NGN'
      ) {
        if (
          order.status !==
          'paid'
        ) {
          order.status =
            'paid';

          order.payment =
            order.payment || {};

          order.payment.verifiedAt =
            new Date().toISOString();

          order.payment.channel =
            transaction.channel;

          order.payment.paidAt =
            transaction.paid_at;

          decrementStock(
            order.items
          );
        }

        order.updatedAt =
          new Date().toISOString();

        writeOrders(
          orders
        );

        return res.json({
          success:
            true,

          reference,

          orderStatus:
            order.orderStatus,

          order
        });
      }

      order.status =
        transaction?.status ===
        'failed'
          ? 'failed'
          : 'pending';

      order.updatedAt =
        new Date().toISOString();

      writeOrders(
        orders
      );

      res.json({
        success:
          false,

        message:
          'Payment has not been verified as successful.'
      });

    } catch (error) {
      console.error(
        'Paystack verification error:',
        error
      );

      res
        .status(500)
        .json({
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
        !PAYSTACK_SECRET ||
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
            PAYSTACK_SECRET
          )
          .update(
            req.rawBody
          )
          .digest('hex');

      const actualBuffer =
        Buffer.from(
          String(signature)
        );

      const expectedBuffer =
        Buffer.from(
          expected
        );

      if (
        actualBuffer.length !==
          expectedBuffer.length ||
        !crypto.timingSafeEqual(
          actualBuffer,
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
            item =>
              item.reference ===
              transaction.reference
          );

        if (
          order &&
          Number(
            transaction.amount
          ) ===
            Math.round(
              order.total * 100
            ) &&
          transaction.currency ===
            'NGN' &&
          order.status !==
            'paid'
        ) {
          order.status =
            'paid';

          order.payment =
            order.payment || {};

          order.payment.verifiedAt =
            new Date().toISOString();

          order.payment.channel =
            transaction.channel;

          order.payment.paidAt =
            transaction.paid_at;

          decrementStock(
            order.items
          );

          order.updatedAt =
            new Date().toISOString();

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
        'Paystack webhook error:',
        error
      );

      res.sendStatus(
        500
      );
    }
  }
);


/* =========================================================
   PAYMENT SUCCESS PAGE
========================================================= */

app.get(
  '/payment-success.html',
  (req, res) => {
    const file =
      path.join(
        PUBLIC_DIR,
        'payment-success.html'
      );

    /*
       If the custom page exists,
       serve it.
    */
    if (
      fs.existsSync(file)
    ) {
      return res.sendFile(file);
    }

    /*
       Otherwise use built-in page.
    */
    res
      .type('html')
      .send(`
<!doctype html>
<html>
<head>
<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>
<title>Payment | Face of Style</title>
<style>
body{
  font-family:Arial,sans-serif;
  background:#fcf8f1;
  text-align:center;
  padding:50px 20px;
  color:#251c20;
}
.box{
  max-width:520px;
  margin:auto;
  background:#fff;
  padding:35px;
  border-radius:20px;
  box-shadow:0 10px 40px rgba(0,0,0,.08);
}
h1{
  color:#651630;
}
a{
  display:inline-block;
  margin-top:18px;
  background:#651630;
  color:#fff;
  padding:12px 20px;
  border-radius:25px;
  text-decoration:none;
}
</style>
</head>
<body>
<div class="box">
<h1 id="title">Checking payment…</h1>
<p id="msg">
Please wait while we verify your payment.
</p>
<a href="/">Return to store</a>
</div>

<script>
(async()=>{
  const params =
    new URLSearchParams(
      location.search
    );

  const reference =
    params.get('reference') ||
    params.get('trxref');

  const title =
    document.getElementById('title');

  const msg =
    document.getElementById('msg');

  if(!reference){
    title.textContent =
      'Payment reference missing';

    msg.textContent =
      'Please contact the store.';
    return;
  }

  try{
    const response =
      await fetch(
        '/api/paystack/verify/' +
        encodeURIComponent(
          reference
        )
      );

    const data =
      await response.json();

    if(data.success){
      title.textContent =
        'Payment Successful';

      msg.textContent =
        'Your order ' +
        reference +
        ' has been received.';

    }else{
      title.textContent =
        'Payment Not Confirmed';

      msg.textContent =
        data.message ||
        'Your payment is still being verified.';
    }

  }catch(error){
    title.textContent =
      'Verification Error';

    msg.textContent =
      'Please check your order again shortly.';
  }
})();
</script>

</body>
</html>
`);
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
          PAYSTACK_SECRET
        ),

      customerAuth:
        true,

      orderTracking:
        true,

      products:
        true,

      admin:
        true
    });
  }
);


/* =========================================================
   UNKNOWN API ROUTE
========================================================= */

app.use(
  (req, res, next) => {
    if (
      req.path.startsWith(
        '/api/'
      )
    ) {
      return res
        .status(404)
        .json({
          message:
            'API route not found.'
        });
    }

    next();
  }
);


/* =========================================================
   STATIC FILES
   IMPORTANT:
   index.html/admin.html are inside public/
========================================================= */

app.use(
  express.static(
    PUBLIC_DIR,
    {
      extensions: [
        'html'
      ]
    }
  )
);


/* =========================================================
   404 FALLBACK
========================================================= */

app.use(
  (req, res) => {
    if (
      req.accepts('html')
    ) {
      const indexFile =
        path.join(
          PUBLIC_DIR,
          'index.html'
        );

      if (
        fs.existsSync(
          indexFile
        )
      ) {
        return res.sendFile(
          indexFile
        );
      }
    }

    res
      .status(404)
      .send(
        'Page not found.'
      );
  }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  () => {
    console.log(
      `Face of Style Hijab Factory running at ${BASE_URL}`
    );

    console.log(
      `Public folder: ${PUBLIC_DIR}`
    );

    console.log(
      `Assets folder: ${ASSETS_DIR}`
    );

    console.log(
      `Paystack configured: ${Boolean(
        PAYSTACK_SECRET
      )}`
    );
  }
);
