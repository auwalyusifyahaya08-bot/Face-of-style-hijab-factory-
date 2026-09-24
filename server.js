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

const BASE_URL =
  (process.env.BASE_URL ||
    `http://localhost:${PORT}`).replace(/\/$/, '');

const DATA = path.join(__dirname, 'data');

const ORDERS =
  path.join(DATA, 'orders.json');

const PRODUCTS_FILE =
  path.join(DATA, 'products.json');

const CUSTOMERS_FILE =
  path.join(DATA, 'customers.json');

const SETTINGS_FILE =
  path.join(DATA, 'settings.json');


/* =========================================================
   DATA INITIALIZATION
========================================================= */

fs.mkdirSync(DATA, { recursive: true });

function ensureJson(file, fallback) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(
      file,
      JSON.stringify(fallback, null, 2)
    );
  }
}

ensureJson(ORDERS, []);

ensureJson(CUSTOMERS_FILE, []);

ensureJson(PRODUCTS_FILE, [
  {
    id: 1,
    name: 'Elegant Zip Abaya',
    cat: 'Abaya',
    price: 25000,
    color: '',
    stock: 99,
    active: true,
    image: '/product-1.jpg',
    desc: 'Flowing full-length abaya with refined finishing.'
  },
  {
    id: 2,
    name: 'Two-Tone Signature Gown',
    cat: 'Gown',
    price: 22000,
    color: '',
    stock: 99,
    active: true,
    image: '/product-2.jpg',
    desc: 'Elegant two-tone modest gown design.'
  },
  {
    id: 3,
    name: 'Teal Classic Hijab Dress',
    cat: 'Gown',
    price: 20000,
    color: '',
    stock: 99,
    active: true,
    image: '/product-3.jpg',
    desc: 'Comfortable modest dress with clean detailing.'
  },
  {
    id: 4,
    name: 'Premium Black & White',
    cat: 'Abaya',
    price: 28000,
    color: '',
    stock: 99,
    active: true,
    image: '/product-4.jpg',
    desc: 'Statement modest outfit with premium contrast.'
  },
  {
    id: 5,
    name: 'Ruffle Hijab Collection',
    cat: 'Hijab',
    price: 12000,
    color: '',
    stock: 99,
    active: true,
    image: '/product-5.jpg',
    desc: 'Soft, colourful hijab styles with beautiful ruffles.'
  },
  {
    id: 6,
    name: 'Rose Signature Gown',
    cat: 'Custom',
    price: 24000,
    color: '',
    stock: 99,
    active: true,
    image: '/product-6.jpg',
    desc: 'Elegant flowing gown; custom colours available.'
  }
]);

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

  logo: '/logo.png',
  heroImage: '/product-1.jpg',

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
   JSON HELPERS
========================================================= */

function readJson(file, fallback) {

  try {

    return JSON.parse(
      fs.readFileSync(
        file,
        'utf8'
      ) ||
      JSON.stringify(fallback)
    );

  } catch {

    return fallback;

  }

}


function writeJson(file, value) {

  const tmp =
    `${file}.tmp`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(
      value,
      null,
      2
    )
  );

  fs.renameSync(
    tmp,
    file
  );

}


function readProducts() {
  return readJson(
    PRODUCTS_FILE,
    []
  );
}


function writeProducts(value) {
  writeJson(
    PRODUCTS_FILE,
    value
  );
}


function readOrders() {
  return readJson(
    ORDERS,
    []
  );
}


function writeOrders(value) {
  writeJson(
    ORDERS,
    value
  );
}


function readCustomers() {
  return readJson(
    CUSTOMERS_FILE,
    []
  );
}


function writeCustomers(value) {
  writeJson(
    CUSTOMERS_FILE,
    value
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


function writeSettings(value) {

  writeJson(
    SETTINGS_FILE,
    value
  );

}


/* =========================================================
   SESSIONS
========================================================= */

const adminSessions =
  new Set();

const customerSessions =
  new Map();


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

const WHATSAPP =
  process.env.WHATSAPP_NUMBER ||
  readSettings().whatsapp ||
  '09065828886';

const PAYSTACK_SECRET =
  process.env.PAYSTACK_SECRET_KEY ||
  '';

const CALLBACK_URL =
  process.env.PAYSTACK_CALLBACK_URL ||
  `${BASE_URL}/payment-success.html`;


/* =========================================================
   BODY PARSER
   IMPORTANT:
   Large limit allows product image upload.
========================================================= */

app.use(
  express.json({
    limit: '12mb',

    verify:
      (req, res, buf) => {

        req.rawBody =
          buf;

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

function clean(
  value,
  max = 500
) {

  return String(
    value ?? ''
  )
    .trim()
    .slice(
      0,
      max
    );

}


function positiveInt(
  value,
  fallback = 0
) {

  const number =
    Number(value);

  return (
    Number.isInteger(number) &&
    number >= 0
  )
    ? number
    : fallback;

}


function price(value) {

  const number =
    Number(value);

  return (
    Number.isFinite(number) &&
    number >= 0
  )
    ? Math.round(
        number * 100
      ) / 100
    : NaN;

}


function emailValid(value) {

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(
      String(
        value || ''
      ).trim()
    );

}


function passwordHash(
  password
) {

  const salt =
    crypto.randomBytes(
      16
    ).toString('hex');

  const hash =
    crypto.scryptSync(
      String(password),
      salt,
      64
    ).toString('hex');

  return `${salt}:${hash}`;

}


function verifyPassword(
  password,
  stored
) {

  try {

    const [
      salt,
      hashHex
    ] =
      String(
        stored || ''
      ).split(':');

    if (
      !salt ||
      !hashHex
    ) {

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


function normalizeImage(
  value,
  fallback = '/product-1.jpg'
) {

  let v =
    clean(
      value,
      8000000
    );

  if (!v) {

    return fallback;

  }

  v =
    v.replace(
      /^\.?\/?assets\//i,
      '/'
    );

  if (
    /^https?:\/\//i.test(v) ||
    v.startsWith(
      'data:image/'
    )
  ) {

    return v;

  }

  return v.startsWith('/')
    ? v
    : `/${v}`;

}


function publicProduct(p) {

  return {

    id: p.id,

    name:
      p.name,

    cat:
      p.cat ||
      p.category ||
      'Custom',

    category:
      p.cat ||
      p.category ||
      'Custom',

    price:
      Number(
        p.price || 0
      ),

    color:
      p.color ||
      '',

    stock:
      positiveInt(
        p.stock,
        0
      ),

    active:
      p.active !== false,

    image:
      normalizeImage(
        p.image ||
        p.img,
        '/product-1.jpg'
      ),

    img:
      normalizeImage(
        p.image ||
        p.img,
        '/product-1.jpg'
      ),

    desc:
      p.desc ||
      p.description ||
      ''

  };

}


function publicCustomer(
  customer
) {

  return {

    id:
      customer.id,

    name:
      customer.name,

    email:
      customer.email,

    phone:
      customer.phone

  };

}


/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function adminAuth(
  req,
  res,
  next
) {

  const header =
    req.headers.authorization ||
    '';

  const sessionToken =
    header.startsWith(
      'Bearer '
    )
      ? header.slice(7)
      : '';

  if (
    !adminSessions.has(
      sessionToken
    )
  ) {

    return res
      .status(401)
      .json({
        message:
          'Unauthorized'
      });

  }

  next();

}


function customerAuth(
  req,
  res,
  next
) {

  const header =
    req.headers.authorization ||
    '';

  const sessionToken =
    header.startsWith(
      'Bearer '
    )
      ? header.slice(7)
      : '';

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

  next();

}


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
        order.id === id
    );

}


/* =========================================================
   ORDER CALCULATION
========================================================= */

function calculateItems(
  items
) {

  if (
    !Array.isArray(items) ||
    !items.length
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
      Number(
        raw?.qty
      );

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

    if (
      stock < qty
    ) {

      return {

        error:
          `Only ${stock} item(s) available for ${product.name}.`

      };

    }

    total +=
      Number(
        product.price
      ) * qty;

    cleanItems.push({

      id:
        product.id,

      name:
        product.name,

      price:
        Number(
          product.price
        ),

      qty

    });

  }

  return {

    items:
      cleanItems,

    total

  };

}


/* =========================================================
   DECREASE STOCK
========================================================= */

function decrementStock(
  items
) {

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

    if (product) {

      product.stock =
        Math.max(
          0,
          positiveInt(
            product.stock,
            0
          ) -
          Number(
            item.qty
          )
        );

    }

  }

  writeProducts(
    products
  );

}


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

    res.json({

      store:
        settings,

      whatsapp:
        WHATSAPP,

      paystackConfigured:
        Boolean(
          PAYSTACK_SECRET
        ),

      customerAuthEnabled:
        true

    });

  }
);


/* =========================================================
   CUSTOMER SIGN UP
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
        req.body?.password ||
        ''
      );

    if (
      !name ||
      !emailValid(email) ||
      !phone ||
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
        passwordHash(
          password
        ),

      createdAt:
        new Date()
          .toISOString()

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
        req.body?.password ||
        ''
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

    const header =
      req.headers.authorization ||
      '';

    const sessionToken =
      header.startsWith(
        'Bearer '
      )
        ? header.slice(7)
        : '';

    customerSessions.delete(
      sessionToken
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
      !phone
    ) {

      return res
        .status(400)
        .json({
          message:
            'Name and phone are required.'
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


app.get(
  '/api/customer/orders/:reference',
  customerAuth,
  (req, res) => {

    const customer =
      getCustomer(
        req.customerId
      );

    const order =
      readOrders()
        .find(
          item =>
            item.reference ===
              req.params.reference &&
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

    const matches =
      (
        phone &&
        order.customer?.phone ===
          phone
      ) ||
      (
        email &&
        order.customer?.email ===
          email
      );

    if (!matches) {

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
   CREATE ORDER
========================================================= */

function createPendingOrder(
  customer,
  calculated,
  paymentProvider = 'paystack'
) {

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

    payment: {

      provider:
        paymentProvider

    },

    createdAt:
      new Date()
        .toISOString(),

    updatedAt:
      new Date()
        .toISOString()

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

    if (
      !customer ||
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

          address:
            clean(
              req.body?.address,
              500
            )

        },

        calculated,

        'whatsapp'

      );

    if (
      !order.customer.address
    ) {

      return res
        .status(400)
        .json({
          message:
            'Delivery address is required.'
        });

    }

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
        req.body?.password ||
        ''
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
      username !==
        ADMIN_USER ||
      password !==
        ADMIN_PASSWORD
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
   ADMIN LOGOUT
========================================================= */

app.post(
  '/api/admin/logout',
  adminAuth,
  (req, res) => {

    const header =
      req.headers.authorization ||
      '';

    const sessionToken =
      header.startsWith(
        'Bearer '
      )
        ? header.slice(7)
        : '';

    adminSessions.delete(
      sessionToken
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

        processing:
          orders.filter(
            order =>
              order.orderStatus ===
              'processing'
          ).length,

        delivered:
          orders.filter(
            order =>
              order.orderStatus ===
              'delivered'
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
                  order.total ||
                  0
                ),
              0
            ),

        products:
          readProducts()
            .filter(
              product =>
                product.active !== false
            )
            .length

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
      !allowed.includes(
        status
      )
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
          item.id ===
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

    order.orderStatus =
      status;

    order.updatedAt =
      new Date()
        .toISOString();

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

  const cat =
    clean(
      body?.cat ||
      body?.category,
      40
    ) ||
    'Custom';

  const productPrice =
    price(
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

  const active =
    body?.active ===
    undefined

      ? old.active !== false

      : Boolean(
          body.active
        );

  let image =
    body?.image ===
    undefined

      ? (
          old.image ||
          old.img ||
          ''
        )

      : body.image;

  image =
    normalizeImage(
      image,
      old.image ||
      old.img ||
      '/product-1.jpg'
    );

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

    cat,

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

    const product = {

      id,

      ...payload,

      createdAt:
        new Date()
          .toISOString(),

      updatedAt:
        new Date()
          .toISOString()

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
          String(
            item.id
          ) ===
          String(
            req.params.id
          )
      );

    if (
      index < 0
    ) {

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
        new Date()
          .toISOString()

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
          String(
            item.id
          ) !==
          String(
            req.params.id
          )
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

    res.json({

      settings:
        readSettings(),

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
   SAVE STORE SETTINGS
========================================================= */

app.put(
  '/api/admin/settings',
  adminAuth,
  (req, res) => {

    const old =
      readSettings();

    const body =
      req.body ||
      {};

    const next = {

      ...old,

      storeName:
        clean(
          body.storeName,
          120
        ) ||
        old.storeName,

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
          '/logo.png'
        ),

      heroImage:
        normalizeImage(
          body.heroImage,
          old.heroImage ||
          '/product-1.jpg'
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
          old.deliveryFee ||
          0
        ),

      freeDeliveryFrom:
        positiveInt(
          body.freeDeliveryFrom,
          old.freeDeliveryFrom ||
          0
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
          ? old.enableCart !==
            false
          : Boolean(
              body.enableCart
            ),

      enableWhatsapp:
        body.enableWhatsapp ===
        undefined
          ? old.enableWhatsapp !==
            false
          : Boolean(
              body.enableWhatsapp
            ),

      showStock:
        body.showStock ===
        undefined
          ? old.showStock !==
            false
          : Boolean(
              body.showStock
            ),

      lowStockLimit:
        positiveInt(
          body.lowStockLimit,
          5
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

      if (
        !PAYSTACK_SECRET
      ) {

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
        !emailValid(
          customer?.email
        ) ||
        !customer?.phone ||
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
          data.data
            .authorization_url,

        reference:
          order.reference

      });

    } catch (error) {

      console.error(
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

      if (
        !PAYSTACK_SECRET
      ) {

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

          order.payment
            .verifiedAt =
              new Date()
                .toISOString();

          order.payment
            .channel =
              transaction.channel;

          order.payment
            .paidAt =
              transaction.paid_at;

          decrementStock(
            order.items
          );

        }

        order.updatedAt =
          new Date()
            .toISOString();

        writeOrders(
          orders
        );

        return res.json({

          success:
            true,

          reference,

          orderStatus:
            order.orderStatus

        });

      }

      order.status =
        transaction?.status ===
        'failed'
          ? 'failed'
          : 'pending';

      order.updatedAt =
        new Date()
          .toISOString();

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

        return res
          .sendStatus(
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
          String(
            signature
          )
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

        return res
          .sendStatus(
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

          order.payment
            .verifiedAt =
              new Date()
                .toISOString();

          order.payment
            .channel =
              transaction.channel;

          order.payment
            .paidAt =
              transaction.paid_at;

          decrementStock(
            order.items
          );

          order.updatedAt =
            new Date()
              .toISOString();

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

<title>
Payment | Face of Style
</title>

<style>

body{
  font-family:Arial;
  background:#fcf8f1;
  text-align:center;
  padding:50px;
  color:#251c20;
}

.box{
  max-width:520px;
  margin:auto;
  background:#fff;
  padding:35px;
  border-radius:20px;
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

<h1 id="title">
Checking payment…
</h1>

<p id="msg">
Please wait while we verify your payment.
</p>

<a href="/">
Return to store
</a>

</div>

<script>

(async()=>{

  const reference =
    new URLSearchParams(
      location.search
    ).get(
      'reference'
    );

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
        ' has been received. You can track it from your account.';

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

      ok:
        true,

      paystackConfigured:
        Boolean(
          PAYSTACK_SECRET
        ),

      customerAuth:
        true,

      orderTracking:
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
========================================================= */

app.use(
  express.static(
    __dirname
  )
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  () => {

    console.log(
      `Face of Style store running at ${BASE_URL}`
    );

  }
);
