import "dotenv/config";
import express from "express";
import pg from "pg";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 10000);

const PAYSTACK_SECRET_KEY =
  process.env.PAYSTACK_SECRET_KEY || "";

const ADMIN_USERNAME =
  process.env.ADMIN_USERNAME || "";

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "";

const DATABASE_URL =
  process.env.DATABASE_URL || "";

const DEFAULT_WHATSAPP =
  String(
    process.env.WHATSAPP_NUMBER ||
    "2349065828886"
  ).replace(/[^0-9]/g, "");

const isProduction =
  process.env.NODE_ENV === "production";

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
    limit: "8mb",
    verify: (req, res, buf) => {
      req.rawBody = Buffer.from(buf);
    }
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "8mb"
  })
);

/*
   IMPORTANT:
   All public assets are served from:

   public/assets/...
   
   Browser URL:

   /assets/...
*/
app.use(
  express.static(
    path.join(__dirname, "public")
  )
);


/* =========================================================
   SESSIONS
========================================================= */

const adminSessions = new Map();
const customerSessions = new Map();

function createToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

function createAdminSession(username) {
  const token = createToken();

  adminSessions.set(token, {
    username,
    createdAt: Date.now()
  });

  return token;
}

function createCustomerSession(customerId) {
  const token = createToken();

  customerSessions.set(token, {
    customerId: Number(customerId),
    createdAt: Date.now()
  });

  return token;
}

function getBearerToken(req) {
  const authorization =
    String(
      req.headers.authorization || ""
    );

  if (
    !authorization.startsWith(
      "Bearer "
    )
  ) {
    return "";
  }

  return authorization
    .slice(7)
    .trim();
}

function requireAdmin(
  req,
  res,
  next
) {
  const token =
    getBearerToken(req);

  const session =
    adminSessions.get(token);

  if (!session) {
    return res.status(401).json({
      ok: false,
      message:
        "Admin authentication required."
    });
  }

  if (
    Date.now() -
      session.createdAt >
    1000 * 60 * 60 * 24
  ) {
    adminSessions.delete(token);

    return res.status(401).json({
      ok: false,
      message:
        "Admin session expired."
    });
  }

  req.admin = {
    token,
    ...session
  };

  next();
}

function optionalCustomer(req) {
  const token =
    getBearerToken(req);

  const session =
    customerSessions.get(token);

  if (!session) {
    return null;
  }

  if (
    Date.now() -
      session.createdAt >
    1000 * 60 * 60 * 24 * 30
  ) {
    customerSessions.delete(token);
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
    optionalCustomer(req);

  if (!session) {
    return res.status(401).json({
      ok: false,
      message:
        "Customer login required."
    });
  }

  req.customer = session;
  next();
}


/* =========================================================
   HELPERS
========================================================= */

function cleanString(
  value,
  max = 500
) {
  return String(
    value ?? ""
  )
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

function safePrice(value) {
  const number =
    Number(value);

  if (
    !Number.isFinite(number) ||
    number < 0
  ) {
    return null;
  }

  return (
    Math.round(number * 100) /
    100
  );
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    String(email || "")
  );
}

function validPhone(phone) {
  return /^[0-9+\-\s()]{7,25}$/.test(
    String(phone || "")
  );
}

function createOrderReference() {
  return (
    "FS-" +
    Date.now()
      .toString(36)
      .toUpperCase() +
    "-" +
    crypto
      .randomBytes(4)
      .toString("hex")
      .toUpperCase()
  );
}


/* =========================================================
   IMAGE NORMALIZATION
   VERSION 2 IMAGE FIX
========================================================= */

function normalizeImage(value) {
  let image =
    String(value || "").trim();

  if (!image) {
    return "";
  }

  /*
     Keep Base64 images exactly as they are.
  */
  if (
    image.startsWith("data:image/")
  ) {
    return image;
  }

  /*
     Keep external HTTPS/HTTP images.
  */
  if (
    image.startsWith("https://") ||
    image.startsWith("http://")
  ) {
    return image;
  }

  /*
     Remove leading ./ or /
     so we can normalize local assets.
  */
  image =
    image.replace(
      /^\.?\//,
      ""
    );

  /*
     Convert old database paths:
     
     public/assets/Product-1.jpg
     -> /assets/Product-1.jpg
     
     public/Product-1.jpg
     -> /assets/Product-1.jpg
  */
  image =
    image.replace(
      /^public\/assets\//i,
      ""
    );

  image =
    image.replace(
      /^public\//i,
      ""
    );

  /*
     Already assets/...
  */
  if (
    image.startsWith("assets/")
  ) {
    return "/" + image;
  }

  /*
     If database contains /assets after
     previous cleanup.
  */
  if (
    image.startsWith("/assets/")
  ) {
    return image;
  }

  /*
     If database contains an absolute
     public file path.
  */
  if (
    image.startsWith("uploads/")
  ) {
    return "/" + image;
  }

  /*
     Normal product filename:
     
     Product-1.jpg
     
     becomes:
     
     /assets/Product-1.jpg
  */
  return (
    "/assets/" +
    image
  );
}


/* =========================================================
   PASSWORD HASHING
========================================================= */

function hashPassword(password) {
  const salt =
    crypto.randomBytes(16).toString("hex");

  const hash =
    crypto.scryptSync(
      String(password),
      salt,
      64
    ).toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(
  password,
  stored
) {
  try {
    const [
      salt,
      originalHash
    ] = String(stored || "").split(":");

    if (
      !salt ||
      !originalHash
    ) {
      return false;
    }

    const hash =
      crypto
        .scryptSync(
          String(password),
          salt,
          64
        )
        .toString("hex");

    return crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(
        originalHash,
        "hex"
      )
    );
  } catch {
    return false;
  }
}


/* =========================================================
   DATABASE INITIALIZATION
   KEEP EXISTING PRODUCTS.IMG SCHEMA.
========================================================= */

async function initDatabase() {
  if (!pool) {
    console.warn(
      "DATABASE_URL is not configured."
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
      img TEXT DEFAULT '',
      stock INTEGER NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS category
    TEXT DEFAULT 'Fashion'
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS description
    TEXT DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS price
    NUMERIC(12,2) DEFAULT 0
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS color
    TEXT DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS img
    TEXT DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS stock
    INTEGER DEFAULT 0
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS active
    BOOLEAN DEFAULT TRUE
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS created_at
    TIMESTAMPTZ DEFAULT NOW()
  `);

  await pool.query(`
    ALTER TABLE products
    ADD COLUMN IF NOT EXISTS updated_at
    TIMESTAMPTZ DEFAULT NOW()
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
      payment_method TEXT NOT NULL DEFAULT 'paystack',
      payment_status TEXT NOT NULL DEFAULT 'PENDING',
      order_status TEXT NOT NULL DEFAULT 'PENDING',
      total NUMERIC(12,2) NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'NGN',
      paystack_reference TEXT,
      customer_id BIGINT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS customer_id BIGINT
  `);

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS payment_status
    TEXT DEFAULT 'PENDING'
  `);

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS order_status
    TEXT DEFAULT 'PENDING'
  `);

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS payment_method
    TEXT DEFAULT 'paystack'
  `);

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS total
    NUMERIC(12,2) DEFAULT 0
  `);

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS currency
    TEXT DEFAULT 'NGN'
  `);

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS paystack_reference
    TEXT
  `);

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS created_at
    TIMESTAMPTZ DEFAULT NOW()
  `);

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS updated_at
    TIMESTAMPTZ DEFAULT NOW()
  `);


  /* =======================================================
     OLD STATUS INDEX FIX
  ======================================================= */

  const oldStatusIndexes =
    await pool.query(`
      SELECT
        schemaname,
        indexname,
        indexdef
      FROM pg_indexes
      WHERE tablename = 'orders'
    `);

  for (
    const row
    of oldStatusIndexes.rows
  ) {
    const definition =
      String(
        row.indexdef || ""
      );

    if (
      /\(\s*"?status"?\s*\)/i.test(
        definition
      )
    ) {
      const schema =
        String(
          row.schemaname
        ).replace(
          /"/g,
          '""'
        );

      const indexName =
        String(
          row.indexname
        ).replace(
          /"/g,
          '""'
        );

      console.log(
        `Removing old orders.status index: ${row.indexname}`
      );

      await pool.query(
        `DROP INDEX IF EXISTS "${schema}"."${indexName}"`
      );
    }
  }


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
      price NUMERIC(12,2) NOT NULL,
      quantity INTEGER NOT NULL,
      subtotal NUMERIC(12,2) NOT NULL
    )
  `);


  /* =======================================================
     CUSTOMERS
  ======================================================= */

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
    ALTER TABLE orders
    ADD CONSTRAINT orders_customer_fk
    FOREIGN KEY (customer_id)
    REFERENCES customers(id)
    ON DELETE SET NULL
  `).catch(() => {});


  /* =======================================================
     ADDRESSES
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customer_addresses (
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT NOT NULL
        REFERENCES customers(id)
        ON DELETE CASCADE,
      label TEXT NOT NULL DEFAULT 'Home',
      address TEXT NOT NULL,
      city TEXT DEFAULT '',
      state TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      is_default BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);


  /* =======================================================
     STORE CREDIT
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS store_credit_transactions (
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT NOT NULL
        REFERENCES customers(id)
        ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL,
      type TEXT NOT NULL,
      reference TEXT,
      note TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);


  /* =======================================================
     REFUNDS
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS refunds (
      id BIGSERIAL PRIMARY KEY,
      order_id BIGINT NOT NULL
        REFERENCES orders(id)
        ON DELETE CASCADE,
      customer_id BIGINT,
      amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      reason TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'PENDING',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);


  /* =======================================================
     STORE SETTINGS
  ======================================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS store_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL DEFAULT ''
    )
  `);

  const defaultSettings = {
    store_name:
      "Face of Style Hijab Factory",

    tagline:
      "HIJAB FACTORY",

    primary_color:
      "#651630",

    secondary_color:
      "#4d1024",

    gold_color:
      "#c9a45b",

    background_color:
      "#fcf8f1",

    text_color:
      "#251c20",

    hero_title:
      "Modesty, Elegance & Style.",

    hero_text:
      "Discover carefully crafted hijabs, abayas, gowns and modest outfits.",

    whatsapp:
      DEFAULT_WHATSAPP
  };

  for (
    const [
      key,
      value
    ]
    of Object.entries(
      defaultSettings
    )
  ) {
    await pool.query(
      `
      INSERT INTO store_settings
      (key,value)
      VALUES
      ($1,$2)
      ON CONFLICT (key)
      DO NOTHING
      `,
      [
        key,
        String(value)
      ]
    );
  }


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
    idx_products_created
    ON products(created_at DESC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_orders_created
    ON orders(created_at DESC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_orders_payment_status
    ON orders(payment_status)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_orders_order_status
    ON orders(order_status)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_customers_email
    ON customers(email)
  `);

  console.log(
    "Face of Style Version 2 database initialized successfully."
  );
}


/* =========================================================
   SETTINGS HELPERS
========================================================= */

async function getSettings() {
  const settings = {};

  if (!pool) {
    return settings;
  }

  const result =
    await pool.query(`
      SELECT key,value
      FROM store_settings
    `);

  for (
    const row
    of result.rows
  ) {
    settings[row.key] =
      row.value;
  }

  return settings;
}


/* =========================================================
   PRODUCT HELPERS
========================================================= */

function mapProduct(row) {
  const image =
    normalizeImage(
      row.img
    );

  const stock =
    Math.max(
      0,
      Number(row.stock) || 0
    );

  const inStock =
    stock > 0;

  return {
    id:
      Number(row.id),

    name:
      row.name,

    category:
      row.category ||
      "Fashion",

    cat:
      row.category ||
      "Fashion",

    description:
      row.description ||
      "",

    desc:
      row.description ||
      "",

    price:
      Number(row.price) || 0,

    color:
      row.color ||
      "",

    img:
      image,

    image,

    stock,

    inStock,

    outOfStock:
      !inStock,

    stockStatus:
      inStock
        ? "IN_STOCK"
        : "OUT_OF_STOCK",

    active:
      row.active !== false,

    created_at:
      row.created_at,

    updated_at:
      row.updated_at
  };
}


/* =========================================================
   PUBLIC CONFIG
========================================================= */

app.get(
  "/api/config",
  async (req, res) => {
    try {
      const settings =
        await getSettings();

      res.json({
        ok: true,

        settings,

        whatsapp:
          settings.whatsapp ||
          DEFAULT_WHATSAPP,

        paystackConfigured:
          Boolean(
            PAYSTACK_SECRET_KEY
          )
      });
    } catch (error) {
      console.error(
        "Config error:",
        error
      );

      res.json({
        ok: true,
        settings: {
          store_name:
            "Face of Style Hijab Factory",

          tagline:
            "HIJAB FACTORY",

          primary_color:
            "#651630",

          secondary_color:
            "#4d1024",

          gold_color:
            "#c9a45b",

          background_color:
            "#fcf8f1",

          text_color:
            "#251c20",

          hero_title:
            "Modesty, Elegance & Style.",

          hero_text:
            "Discover carefully crafted hijabs, abayas, gowns and modest outfits.",

          whatsapp:
            DEFAULT_WHATSAPP
        },

        whatsapp:
          DEFAULT_WHATSAPP,

        paystackConfigured:
          Boolean(
            PAYSTACK_SECRET_KEY
          )
      });
    }
  }
);


/* =========================================================
   PUBLIC PRODUCTS
========================================================= */

app.get(
  "/api/products",
  async (req, res) => {
    if (!pool) {
      return res.json({
        ok: true,
        products: []
      });
    }

    try {
      const result =
        await pool.query(`
          SELECT
            id,
            name,
            category,
            description,
            price,
            color,
            img,
            stock,
            active,
            created_at,
            updated_at
          FROM products
          WHERE active = TRUE
          ORDER BY created_at DESC
        `);

      res.json({
        ok: true,

        products:
          result.rows.map(
            mapProduct
          )
      });

    } catch (error) {
      console.error(
        "Public products error:",
        error
      );

      res.status(500).json({
        ok: false,
        products: [],
        message:
          "Unable to load products."
      });
    }
  }
);


/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
  "/api/admin/login",
  (req, res) => {
    const username =
      cleanString(
        req.body?.username,
        100
      );

    const password =
      String(
        req.body?.password || ""
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
            "Admin credentials are not configured on the server."
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
            "Invalid admin credentials."
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
  "/api/admin/logout",
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
  "/api/admin/me",
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
  "/api/admin/dashboard",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    try {
      const [
        orders,
        paid,
        customers,
        products,
        refunds
      ] =
        await Promise.all([
          pool.query(
            `SELECT COUNT(*)::int AS count FROM orders`
          ),

          pool.query(
            `
            SELECT COUNT(*)::int AS count
            FROM orders
            WHERE payment_status = 'PAID'
            `
          ),

          pool.query(
            `SELECT COUNT(*)::int AS count FROM customers`
          ),

          pool.query(
            `
            SELECT COUNT(*)::int AS count
            FROM products
            WHERE active = TRUE
            `
          ),

          pool.query(
            `
            SELECT COUNT(*)::int AS count
            FROM refunds
            WHERE status = 'PENDING'
            `
          )
        ]);

      const revenue =
        await pool.query(`
          SELECT
            COALESCE(
              SUM(total),
              0
            ) AS revenue
          FROM orders
          WHERE payment_status = 'PAID'
        `);

      res.json({
        ok: true,

        stats: {
          orders:
            Number(
              orders.rows[0].count
            ),

          paid:
            Number(
              paid.rows[0].count
            ),

          customers:
            Number(
              customers.rows[0].count
            ),

          products:
            Number(
              products.rows[0].count
            ),

          refunds:
            Number(
              refunds.rows[0].count
            ),

          revenue:
            Number(
              revenue.rows[0].revenue
            ) || 0
        }
      });

    } catch (error) {
      console.error(
        "Dashboard error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load dashboard."
      });
    }
  }
);


/* =========================================================
   ADMIN PRODUCTS
========================================================= */

app.get(
  "/api/admin/products",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    try {

      const result =
        await pool.query(`
          SELECT
            id,
            name,
            category,
            description,
            price,
            color,
            img,
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
          result.rows.map(
            mapProduct
          )
      });

    } catch (error) {

      console.error(
        "Admin products error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load products."
      });
    }
  }
);


/* =========================================================
   CREATE PRODUCT
========================================================= */

app.post(
  "/api/admin/products",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    const name =
      cleanString(
        req.body?.name,
        150
      );

    const category =
      cleanString(
        req.body?.category ||
        req.body?.cat ||
        "Fashion",
        60
      );

    const description =
      cleanString(
        req.body?.description ||
        req.body?.desc ||
        "",
        2000
      );

    const color =
      cleanString(
        req.body?.color ||
        "",
        300
      );

    const image =
      cleanString(
        req.body?.image ||
        req.body?.img ||
        "",
        3000000
      );

    const price =
      safePrice(
        req.body?.price
      );

    const stock =
      Number(
        req.body?.stock
      );

    if (!name) {
      return res.status(400).json({
        ok: false,
        message:
          "Product name is required."
      });
    }

    if (price === null) {
      return res.status(400).json({
        ok: false,
        message:
          "Valid product price is required."
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
          "Invalid stock quantity."
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
            img,
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

      res.status(201).json({
        ok: true,

        product:
          mapProduct(
            result.rows[0]
          )
      });

    } catch (error) {

      console.error(
        "Create product error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to create product."
      });
    }
  }
);


/* =========================================================
   UPDATE PRODUCT
========================================================= */

app.put(
  "/api/admin/products/:id",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
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
          "Invalid product ID."
      });
    }

    const name =
      cleanString(
        req.body?.name,
        150
      );

    const category =
      cleanString(
        req.body?.category ||
        req.body?.cat ||
        "Fashion",
        60
      );

    const description =
      cleanString(
        req.body?.description ||
        req.body?.desc ||
        "",
        2000
      );

    const color =
      cleanString(
        req.body?.color ||
        "",
        300
      );

    const image =
      cleanString(
        req.body?.image ??
          req.body?.img ??
          "",
        3000000
      );

    const price =
      safePrice(
        req.body?.price
      );

    const stock =
      Number(
        req.body?.stock
      );

    const active =
      req.body?.active !== false;

    if (!name) {
      return res.status(400).json({
        ok: false,
        message:
          "Product name is required."
      });
    }

    if (price === null) {
      return res.status(400).json({
        ok: false,
        message:
          "Valid product price is required."
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
          "Invalid stock quantity."
      });
    }

    try {

      let finalImage =
        image;

      if (!finalImage) {

        const old =
          await pool.query(
            `
            SELECT img
            FROM products
            WHERE id = $1
            `,
            [id]
          );

        finalImage =
          old.rows[0]?.img ||
          "";
      }

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
            img = $6,
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
            finalImage,
            stock,
            active,
            id
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            "Product not found."
        });
      }

      res.json({
        ok: true,

        product:
          mapProduct(
            result.rows[0]
          )
      });

    } catch (error) {

      console.error(
        "Update product error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to update product."
      });
    }
  }
);


/* =========================================================
   DELETE PRODUCT
========================================================= */

app.delete(
  "/api/admin/products/:id",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
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
          "Invalid product ID."
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
            "Product not found."
        });
      }

      res.json({
        ok: true,
        message:
          "Product removed from the store."
      });

    } catch (error) {

      console.error(
        "Delete product error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to remove product."
      });
    }
  }
);


/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
  "/api/admin/orders",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    try {

      const orders =
        await pool.query(`
          SELECT
            id,
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
            currency,
            paystack_reference,
            created_at,
            updated_at
          FROM orders
          ORDER BY created_at DESC
        `);

      const list =
        orders.rows;

      if (!list.length) {
        return res.json({
          ok: true,
          orders: []
        });
      }

      const ids =
        list.map(
          order => order.id
        );

      const items =
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

      const grouped =
        new Map();

      for (
        const item
        of items.rows
      ) {
        if (
          !grouped.has(
            String(item.order_id)
          )
        ) {
          grouped.set(
            String(item.order_id),
            []
          );
        }

        grouped
          .get(
            String(item.order_id)
          )
          .push(item);
      }

      res.json({
        ok: true,

        orders:
          list.map(
            order => ({
              ...order,

              items:
                grouped.get(
                  String(order.id)
                ) || []
            })
          )
      });

    } catch (error) {

      console.error(
        "Admin orders error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load orders."
      });
    }
  }
);


/* =========================================================
   UPDATE ORDER STATUS
========================================================= */

app.patch(
  "/api/admin/orders/:id",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    const id =
      positiveInteger(
        req.params.id
      );

    const status =
      cleanString(
        req.body?.order_status ||
        req.body?.status ||
        "",
        30
      ).toUpperCase();

    const allowed = [
      "PENDING",
      "PROCESSING",
      "SHIPPED",
      "DELIVERED",
      "CANCELLED"
    ];

    if (
      !id ||
      !allowed.includes(status)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Invalid order status."
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
            status,
            id
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            "Order not found."
        });
      }

      res.json({
        ok: true,
        order:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "Order status error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to update order status."
      });
    }
  }
);


/* =========================================================
   ADMIN CUSTOMERS
========================================================= */

app.get(
  "/api/admin/customers",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    try {

      const result =
        await pool.query(`
          SELECT
            c.id,
            c.name,
            c.email,
            c.phone,
            c.created_at,
            COALESCE(
              COUNT(o.id),
              0
            )::int AS order_count,

            COALESCE(
              SUM(
                CASE
                  WHEN o.payment_status = 'PAID'
                  THEN o.total
                  ELSE 0
                END
              ),
              0
            ) AS spent

          FROM customers c

          LEFT JOIN orders o
            ON o.customer_id = c.id

          GROUP BY
            c.id

          ORDER BY
            c.created_at DESC
        `);

      res.json({
        ok: true,
        customers:
          result.rows
      });

    } catch (error) {

      console.error(
        "Customers error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load customers."
      });
    }
  }
);


/* =========================================================
   ADMIN STORE CREDIT
========================================================= */

app.get(
  "/api/admin/store-credit",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    try {

      const result =
        await pool.query(`
          SELECT
            c.id,
            c.name,
            c.email,

            COALESCE(
              SUM(
                CASE
                  WHEN s.type = 'CREDIT'
                  THEN s.amount

                  WHEN s.type = 'DEBIT'
                  THEN -s.amount

                  ELSE 0
                END
              ),
              0
            ) AS balance

          FROM customers c

          LEFT JOIN
            store_credit_transactions s

            ON s.customer_id =
              c.id

          GROUP BY
            c.id

          ORDER BY
            c.name ASC
        `);

      res.json({
        ok: true,
        customers:
          result.rows
      });

    } catch (error) {

      console.error(
        "Store credit error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load store credit."
      });
    }
  }
);


/* =========================================================
   ADMIN STORE CREDIT ADJUST
========================================================= */

app.post(
  "/api/admin/store-credit/:customerId",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    const customerId =
      positiveInteger(
        req.params.customerId
      );

    const amount =
      safePrice(
        req.body?.amount
      );

    const type =
      String(
        req.body?.type ||
        "CREDIT"
      ).toUpperCase();

    const note =
      cleanString(
        req.body?.note,
        500
      );

    if (
      !customerId ||
      amount === null ||
      amount <= 0 ||
      ![
        "CREDIT",
        "DEBIT"
      ].includes(type)
    ) {

      return res.status(400).json({
        ok: false,
        message:
          "Invalid store credit adjustment."
      });
    }

    try {

      await pool.query(
        `
        INSERT INTO
          store_credit_transactions
        (
          customer_id,
          amount,
          type,
          reference,
          note
        )
        VALUES
        ($1,$2,$3,$4,$5)
        `,
        [
          customerId,
          amount,
          type,
          `ADMIN-${Date.now()}`,
          note
        ]
      );

      res.json({
        ok: true,
        message:
          "Store credit updated."
      });

    } catch (error) {

      console.error(
        "Store credit adjustment error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to update store credit."
      });
    }
  }
);


/* =========================================================
   ADMIN PAYMENTS
========================================================= */

app.get(
  "/api/admin/payments",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    try {

      const result =
        await pool.query(`
          SELECT
            id,
            reference,
            customer_name,
            customer_email,
            total,
            currency,
            payment_method,
            payment_status,
            paystack_reference,
            created_at
          FROM orders
          ORDER BY created_at DESC
        `);

      res.json({
        ok: true,
        payments:
          result.rows
      });

    } catch (error) {

      console.error(
        "Payments error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load payments."
      });
    }
  }
);


/* =========================================================
   ADMIN REFUNDS
========================================================= */

app.get(
  "/api/admin/refunds",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    try {

      const result =
        await pool.query(`
          SELECT
            r.*,
            o.reference,
            o.customer_name,
            o.customer_email

          FROM refunds r

          JOIN orders o
            ON o.id = r.order_id

          ORDER BY
            r.created_at DESC
        `);

      res.json({
        ok: true,
        refunds:
          result.rows
      });

    } catch (error) {

      console.error(
        "Refunds error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load refunds."
      });
    }
  }
);


/* =========================================================
   CREATE REFUND
========================================================= */

app.post(
  "/api/admin/refunds",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    const orderId =
      positiveInteger(
        req.body?.order_id
      );

    const amount =
      safePrice(
        req.body?.amount
      );

    const reason =
      cleanString(
        req.body?.reason,
        500
      );

    if (
      !orderId ||
      amount === null ||
      amount <= 0
    ) {

      return res.status(400).json({
        ok: false,
        message:
          "Valid order and refund amount are required."
      });
    }

    try {

      const order =
        await pool.query(
          `
          SELECT
            id,
            customer_id,
            total,
            payment_status
          FROM orders
          WHERE id = $1
          `,
          [orderId]
        );

      if (!order.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            "Order not found."
        });
      }

      if (
        order.rows[0].payment_status !==
        "PAID"
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Only paid orders can be refunded."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO refunds
          (
            order_id,
            customer_id,
            amount,
            reason,
            status
          )
          VALUES
          ($1,$2,$3,$4,'PENDING')
          RETURNING *
          `,
          [
            orderId,
            order.rows[0].customer_id,
            amount,
            reason
          ]
        );

      res.status(201).json({
        ok: true,
        refund:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "Refund create error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to create refund."
      });
    }
  }
);


/* =========================================================
   UPDATE REFUND
========================================================= */

app.patch(
  "/api/admin/refunds/:id",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    const id =
      positiveInteger(
        req.params.id
      );

    const status =
      String(
        req.body?.status ||
        ""
      ).toUpperCase();

    if (
      !id ||
      ![
        "PENDING",
        "APPROVED",
        "COMPLETED",
        "REJECTED"
      ].includes(status)
    ) {

      return res.status(400).json({
        ok: false,
        message:
          "Invalid refund status."
      });
    }

    try {

      const result =
        await pool.query(
          `
          UPDATE refunds
          SET
            status = $1,
            updated_at = NOW()
          WHERE id = $2
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
            "Refund not found."
        });
      }

      res.json({
        ok: true,
        refund:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "Refund update error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to update refund."
      });
    }
  }
);


/* =========================================================
   ADMIN SETTINGS GET
========================================================= */

app.get(
  "/api/admin/settings",
  requireAdmin,
  async (req, res) => {

    try {

      const settings =
        await getSettings();

      res.json({
        ok: true,

        settings,

        system: {
          database:
            Boolean(pool),

          paystackConfigured:
            Boolean(
              PAYSTACK_SECRET_KEY
            ),

          adminConfigured:
            Boolean(
              ADMIN_USERNAME &&
              ADMIN_PASSWORD
            )
        }
      });

    } catch (error) {

      console.error(
        "Settings error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load settings."
      });
    }
  }
);


/* =========================================================
   ADMIN SETTINGS UPDATE
========================================================= */

app.put(
  "/api/admin/settings",
  requireAdmin,
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    const allowedKeys = [
      "store_name",
      "tagline",
      "primary_color",
      "secondary_color",
      "gold_color",
      "background_color",
      "text_color",
      "hero_title",
      "hero_text",
      "whatsapp"
    ];

    try {

      for (
        const key
        of allowedKeys
      ) {

        if (
          req.body?.[key] ===
          undefined
        ) {
          continue;
        }

        let value =
          String(
            req.body[key]
          ).trim();

        if (
          key ===
          "whatsapp"
        ) {
          value =
            value.replace(
              /[^0-9]/g,
              ""
            );
        }

        value =
          value.slice(
            0,
            key.includes(
              "color"
            )
              ? 20
              : 2000
          );

        await pool.query(
          `
          INSERT INTO
            store_settings
          (
            key,
            value
          )
          VALUES
          ($1,$2)

          ON CONFLICT (key)
          DO UPDATE SET
            value = EXCLUDED.value
          `,
          [
            key,
            value
          ]
        );
      }

      res.json({
        ok: true,

        settings:
          await getSettings(),

        message:
          "Store settings saved successfully."
      });

    } catch (error) {

      console.error(
        "Settings save error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to save store settings."
      });
    }
  }
);


/* =========================================================
   CUSTOMER SIGN UP
========================================================= */

app.post(
  "/api/customer/signup",
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    const name =
      cleanString(
        req.body?.name,
        120
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
        req.body?.password || ""
      );

    if (
      !name ||
      !email ||
      !password
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Name, email and password are required."
      });
    }

    if (!validEmail(email)) {
      return res.status(400).json({
        ok: false,
        message:
          "Please enter a valid email address."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        message:
          "Password must contain at least 6 characters."
      });
    }

    try {

      const exists =
        await pool.query(
          `
          SELECT id
          FROM customers
          WHERE email = $1
          `,
          [email]
        );

      if (exists.rowCount) {
        return res.status(409).json({
          ok: false,
          message:
            "An account with this email already exists."
        });
      }

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
            phone
          `,
          [
            name,
            email,
            phone,
            hashPassword(
              password
            )
          ]
        );

      const customer =
        result.rows[0];

      const token =
        createCustomerSession(
          customer.id
        );

      res.status(201).json({
        ok: true,
        token,
        customer
      });

    } catch (error) {

      console.error(
        "Signup error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to create account."
      });
    }
  }
);


/* =========================================================
   CUSTOMER LOGIN
========================================================= */

app.post(
  "/api/customer/login",
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    const email =
      cleanString(
        req.body?.email,
        200
      ).toLowerCase();

    const password =
      String(
        req.body?.password || ""
      );

    try {

      const result =
        await pool.query(
          `
          SELECT
            id,
            name,
            email,
            phone,
            password_hash
          FROM customers
          WHERE email = $1
          LIMIT 1
          `,
          [email]
        );

      if (
        !result.rowCount ||
        !verifyPassword(
          password,
          result.rows[0]
            .password_hash
        )
      ) {
        return res.status(401).json({
          ok: false,
          message:
            "Invalid email or password."
        });
      }

      const customer = {
        id:
          result.rows[0].id,
        name:
          result.rows[0].name,
        email:
          result.rows[0].email,
        phone:
          result.rows[0].phone
      };

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
        "Customer login error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to login."
      });
    }
  }
);


/* =========================================================
   CUSTOMER LOGOUT
========================================================= */

app.post(
  "/api/customer/logout",
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
  "/api/customer/me",
  requireCustomer,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            id,
            name,
            email,
            phone,
            created_at
          FROM customers
          WHERE id = $1
          `,
          [
            req.customer.customerId
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            "Customer not found."
        });
      }

      res.json({
        ok: true,
        customer:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "Customer me error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load account."
      });
    }
  }
);


/* =========================================================
   CUSTOMER PROFILE UPDATE
========================================================= */

app.put(
  "/api/customer/me",
  requireCustomer,
  async (req, res) => {

    const name =
      cleanString(
        req.body?.name,
        120
      );

    const phone =
      cleanString(
        req.body?.phone,
        40
      );

    if (!name) {
      return res.status(400).json({
        ok: false,
        message:
          "Name is required."
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
            phone
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
        "Profile update error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to update profile."
      });
    }
  }
);


/* =========================================================
   CUSTOMER ADDRESSES
========================================================= */

app.get(
  "/api/customer/addresses",
  requireCustomer,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT *
          FROM customer_addresses
          WHERE customer_id = $1
          ORDER BY is_default DESC,
                   created_at DESC
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
        "Addresses error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load addresses."
      });
    }
  }
);

app.post(
  "/api/customer/addresses",
  requireCustomer,
  async (req, res) => {

    const label =
      cleanString(
        req.body?.label ||
        "Home",
        50
      );

    const address =
      cleanString(
        req.body?.address,
        500
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

    const phone =
      cleanString(
        req.body?.phone,
        40
      );

    if (!address) {
      return res.status(400).json({
        ok: false,
        message:
          "Address is required."
      });
    }

    try {

      await pool.query(
        `
        UPDATE customer_addresses
        SET is_default = FALSE
        WHERE customer_id = $1
        `,
        [
          req.customer.customerId
        ]
      );

      const result =
        await pool.query(
          `
          INSERT INTO customer_addresses
          (
            customer_id,
            label,
            address,
            city,
            state,
            phone,
            is_default
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,TRUE)
          RETURNING *
          `,
          [
            req.customer.customerId,
            label,
            address,
            city,
            state,
            phone
          ]
        );

      res.status(201).json({
        ok: true,
        address:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "Address create error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to save address."
      });
    }
  }
);


/* =========================================================
   CUSTOMER ORDERS
========================================================= */

app.get(
  "/api/customer/orders",
  requireCustomer,
  async (req, res) => {

    try {

      const result =
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

      res.json({
        ok: true,
        orders:
          result.rows
      });

    } catch (error) {

      console.error(
        "Customer orders error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load orders."
      });
    }
  }
);


/* =========================================================
   CUSTOMER STORE CREDIT
========================================================= */

app.get(
  "/api/customer/store-credit",
  requireCustomer,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            COALESCE(
              SUM(
                CASE
                  WHEN type = 'CREDIT'
                  THEN amount

                  WHEN type = 'DEBIT'
                  THEN -amount

                  ELSE 0
                END
              ),
              0
            ) AS balance

          FROM store_credit_transactions

          WHERE customer_id = $1
          `,
          [
            req.customer.customerId
          ]
        );

      const transactions =
        await pool.query(
          `
          SELECT *
          FROM store_credit_transactions
          WHERE customer_id = $1
          ORDER BY created_at DESC
          `,
          [
            req.customer.customerId
          ]
        );

      res.json({
        ok: true,

        balance:
          Number(
            result.rows[0].balance
          ) || 0,

        transactions:
          transactions.rows
      });

    } catch (error) {

      console.error(
        "Customer credit error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load store credit."
      });
    }
  }
);


/* =========================================================
   CUSTOMER REFUND HISTORY
========================================================= */

app.get(
  "/api/customer/refunds",
  requireCustomer,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            r.*,
            o.reference
          FROM refunds r
          JOIN orders o
            ON o.id = r.order_id
          WHERE r.customer_id = $1
          ORDER BY r.created_at DESC
          `,
          [
            req.customer.customerId
          ]
        );

      res.json({
        ok: true,
        refunds:
          result.rows
      });

    } catch (error) {

      console.error(
        "Refund history error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to load refund history."
      });
    }
  }
);


/* =========================================================
   ORDER TRACKING
========================================================= */

app.get(
  "/api/order-tracking/:reference",
  async (req, res) => {

    const reference =
      cleanString(
        req.params.reference,
        200
      );

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    try {

      const result =
        await pool.query(
          `
          SELECT
            reference,
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

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            "Order not found."
        });
      }

      res.json({
        ok: true,
        order:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "Tracking error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to track order."
      });
    }
  }
);


/* =========================================================
   MANUAL ORDER
   BANK TRANSFER
========================================================= */

app.post(
  "/api/orders/manual",
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
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
      !address ||
      !rawItems.length
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Complete customer details and cart items are required."
      });
    }

    try {

      const result =
        await buildOrderFromCart(
          rawItems
        );

      if (result.error) {
        return res.status(400).json({
          ok: false,
          message:
            result.error
        });
      }

      const reference =
        createOrderReference();

      let customerId =
        null;

      const existing =
        await pool.query(
          `
          SELECT id
          FROM customers
          WHERE email = $1
          `,
          [email]
        );

      if (
        existing.rowCount
      ) {
        customerId =
          existing.rows[0].id;
      }

      const client =
        await pool.connect();

      try {

        await client.query(
          "BEGIN"
        );

        const order =
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
            RETURNING *
            `,
            [
              reference,
              customerId,
              name,
              email,
              phone,
              address,
              result.total
            ]
          );

        for (
          const item
          of result.items
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
              order.rows[0].id,
              item.productId,
              item.name,
              item.price,
              item.quantity,
              item.subtotal
            ]
          );
        }

        await client.query(
          "COMMIT"
        );

        res.json({
          ok: true,
          reference,
          order:
            order.rows[0]
        });

      } catch (error) {

        await client.query(
          "ROLLBACK"
        );

        throw error;

      } finally {

        client.release();

      }

    } catch (error) {

      console.error(
        "Manual order error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to create order."
      });
    }
  }
);


/* =========================================================
   BUILD ORDER FROM CART
========================================================= */

async function buildOrderFromCart(
  rawItems
) {

  if (
    !Array.isArray(
      rawItems
    ) ||
    !rawItems.length
  ) {
    return {
      error:
        "Cart is empty."
    };
  }

  const ids =
    rawItems
      .map(
        item =>
          positiveInteger(
            item.id
          )
      )
      .filter(Boolean);

  if (!ids.length) {
    return {
      error:
        "Invalid cart items."
    };
  }

  const result =
    await pool.query(
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
      `,
      [ids]
    );

  const productMap =
    new Map(
      result.rows.map(
        product => [
          Number(product.id),
          product
        ]
      )
    );

  const items = [];
  let total = 0;

  for (
    const raw
    of rawItems
  ) {

    const productId =
      positiveInteger(
        raw?.id
      );

    const quantity =
      positiveInteger(
        raw?.qty
      );

    if (
      !productId ||
      !quantity
    ) {
      return {
        error:
          "Invalid cart quantity."
      };
    }

    if (
      quantity > 99
    ) {
      return {
        error:
          "Maximum quantity per item is 99."
      };
    }

    const product =
      productMap.get(
        productId
      );

    if (
      !product ||
      product.active === false
    ) {
      return {
        error:
          "One of the selected products is no longer available."
      };
    }

    /*
       OUT OF STOCK PROTECTION
    */
    const availableStock =
      Math.max(
        0,
        Number(product.stock) || 0
      );

    if (
      availableStock <= 0
    ) {
      return {
        error:
          `${product.name} is out of stock.`
      };
    }

    if (
      availableStock < quantity
    ) {
      return {
        error:
          `${product.name} does not have enough stock. Only ${availableStock} item(s) available.`
      };
    }

    const price =
      Number(
        product.price
      ) || 0;

    const subtotal =
      price * quantity;

    total +=
      subtotal;

    items.push({
      productId,
      name:
        product.name,
      price,
      quantity,
      subtotal
    });
  }

  return {
    items,
    total:
      Math.round(
        total * 100
      ) / 100
  };
}


/* =========================================================
   PAYSTACK INITIALIZE
========================================================= */

app.post(
  "/api/paystack/initialize",
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    if (!PAYSTACK_SECRET_KEY) {
      return res.status(503).json({
        ok: false,
        message:
          "Paystack is not configured on the server."
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
      return res.status(400).json({
        ok: false,
        message:
          "Complete customer details are required."
      });
    }

    if (!validEmail(email)) {
      return res.status(400).json({
        ok: false,
        message:
          "Please provide a valid email address."
      });
    }

    if (!validPhone(phone)) {
      return res.status(400).json({
        ok: false,
        message:
          "Please provide a valid phone number."
      });
    }

    try {

      const calculated =
        await buildOrderFromCart(
          rawItems
        );

      if (calculated.error) {
        return res.status(400).json({
          ok: false,
          message:
            calculated.error
        });
      }

      let customerId =
        null;

      const customerResult =
        await pool.query(
          `
          SELECT id
          FROM customers
          WHERE email = $1
          `,
          [email]
        );

      if (
        customerResult.rowCount
      ) {
        customerId =
          customerResult
            .rows[0]
            .id;
      }

      const reference =
        createOrderReference();

      const client =
        await pool.connect();

      try {

        await client.query(
          "BEGIN"
        );

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
            RETURNING id,reference,total
            `,
            [
              reference,
              customerId,
              name,
              email,
              phone,
              address,
              calculated.total
            ]
          );

        const order =
          orderResult.rows[0];

        for (
          const item
          of calculated.items
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
          "COMMIT"
        );

      } catch (error) {

        await client.query(
          "ROLLBACK"
        );

        throw error;

      } finally {

        client.release();

      }

      const callbackUrl =
        process.env.PAYSTACK_CALLBACK_URL ||
        `${req.protocol}://${req.get(
          "host"
        )}/payment-success.html`;

      const payload = {
        email,
        amount:
          Math.round(
            calculated.total * 100
          ),
        currency:
          "NGN",
        reference,
        callback_url:
          callbackUrl,

        metadata: {
          order_reference:
            reference,

          customer_name:
            name,

          customer_phone:
            phone
        }
      };

      const paystackResponse =
        await fetch(
          "https://api.paystack.co/transaction/initialize",
          {
            method: "POST",

            headers: {
              Authorization:
                `Bearer ${PAYSTACK_SECRET_KEY}`,

              "Content-Type":
                "application/json"
            },

            body:
              JSON.stringify(
                payload
              )
          }
        );

      const data =
        await paystackResponse.json();

      if (
        !paystackResponse.ok ||
        !data.status ||
        !data.data?.authorization_url
      ) {

        await pool.query(
          `
          UPDATE orders
          SET
            payment_status = 'FAILED',
            updated_at = NOW()
          WHERE reference = $1
          `,
          [reference]
        );

        return res
          .status(502)
          .json({
            ok: false,
            message:
              data.message ||
              "Unable to initialize Paystack payment."
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
          data.data.reference ||
            reference,
          reference
        ]
      );

      res.json({
        ok: true,

        reference,

        authorization_url:
          data.data
            .authorization_url
      });

    } catch (error) {

      console.error(
        "Paystack initialization error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          error.message ||
          "Payment initialization failed."
      });
    }
  }
);


/* =========================================================
   PAYSTACK VERIFY
========================================================= */

app.get(
  "/api/paystack/verify/:reference",
  async (req, res) => {

    if (!pool) {
      return res.status(503).json({
        ok: false,
        message:
          "Database is not configured."
      });
    }

    if (!PAYSTACK_SECRET_KEY) {
      return res.status(503).json({
        ok: false,
        message:
          "Paystack is not configured."
      });
    }

    const reference =
      cleanString(
        req.params.reference,
        200
      );

    try {

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

      if (!orderResult.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            "Order not found."
        });
      }

      const order =
        orderResult.rows[0];

      const response =
        await fetch(
          `https://api.paystack.co/transaction/verify/${encodeURIComponent(
            reference
          )}`,
          {
            headers: {
              Authorization:
                `Bearer ${PAYSTACK_SECRET_KEY}`
            }
          }
        );

      const data =
        await response.json();

      const tx =
        data.data;

      const expectedAmount =
        Math.round(
          Number(order.total) * 100
        );

      const success =
        response.ok &&
        data.status &&
        tx?.status ===
          "success" &&
        tx.currency ===
          "NGN" &&
        Number(tx.amount) ===
          expectedAmount;

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

        return res.status(400).json({
          ok: false,
          paid: false,
          message:
            "Payment verification failed."
        });
      }

      await completePaidOrder(
        order.id,
        tx.reference ||
          reference
      );

      res.json({
        ok: true,
        paid: true,
        reference,
        amount:
          Number(order.total)
      });

    } catch (error) {

      console.error(
        "Paystack verify error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Payment verification error."
      });
    }
  }
);


/* =========================================================
   COMPLETE PAID ORDER
========================================================= */

async function completePaidOrder(
  orderId,
  paystackReference
) {

  const client =
    await pool.connect();

  try {

    await client.query(
      "BEGIN"
    );

    const orderResult =
      await client.query(
        `
        SELECT *
        FROM orders
        WHERE id = $1
        FOR UPDATE
        `,
        [orderId]
      );

    if (!orderResult.rowCount) {
      throw new Error(
        "Order not found."
      );
    }

    const order =
      orderResult.rows[0];

    if (
      order.payment_status ===
      "PAID"
    ) {

      await client.query(
        "COMMIT"
      );

      return order;
    }

    const items =
      await client.query(
        `
        SELECT *
        FROM order_items
        WHERE order_id = $1
        ORDER BY id ASC
        `,
        [orderId]
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
            stock = stock - $1,
            updated_at = NOW()
          WHERE id = $2
            AND active = TRUE
            AND stock >= $1
          RETURNING id,stock
          `,
          [
            item.quantity,
            item.product_id
          ]
        );

      if (!stock.rowCount) {
        throw new Error(
          `Insufficient stock for ${item.product_name}.`
        );
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
        paystackReference,
        orderId
      ]
    );

    await client.query(
      "COMMIT"
    );

    return order;

  } catch (error) {

    await client.query(
      "ROLLBACK"
    );

    throw error;

  } finally {

    client.release();
  }
}


/* =========================================================
   PAYSTACK WEBHOOK
========================================================= */

app.post(
  "/api/paystack/webhook",
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
          "x-paystack-signature"
        ] || ""
      );

    if (
      !signature ||
      !req.rawBody
    ) {
      return res.sendStatus(
        401
      );
    }

    const expected =
      crypto
        .createHmac(
          "sha512",
          PAYSTACK_SECRET_KEY
        )
        .update(
          req.rawBody
        )
        .digest("hex");

    const received =
      Buffer.from(
        signature,
        "utf8"
      );

    const expectedBuffer =
      Buffer.from(
        expected,
        "utf8"
      );

    if (
      received.length !==
        expectedBuffer.length ||
      !crypto.timingSafeEqual(
        received,
        expectedBuffer
      )
    ) {
      return res.sendStatus(
        401
      );
    }

    try {

      if (
        req.body?.event !==
        "charge.success"
      ) {
        return res.sendStatus(
          200
        );
      }

      const transaction =
        req.body.data || {};

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

      const result =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE reference = $1
          LIMIT 1
          `,
          [reference]
        );

      if (!result.rowCount) {
        return res.sendStatus(
          200
        );
      }

      const order =
        result.rows[0];

      const expectedAmount =
        Math.round(
          Number(order.total) * 100
        );

      if (
        transaction.status !==
          "success" ||
        transaction.currency !==
          "NGN" ||
        Number(transaction.amount) !==
          expectedAmount
      ) {
        return res.sendStatus(
          200
        );
      }

      await completePaidOrder(
        order.id,
        reference
      );

      return res.sendStatus(
        200
      );

    } catch (error) {

      console.error(
        "Paystack webhook error:",
        error
      );

      return res.sendStatus(
        200
      );
    }
  }
);


/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/api/health",
  async (req, res) => {

    let database = false;

    if (pool) {

      try {

        await pool.query(
          "SELECT 1"
        );

        database = true;

      } catch {}

    }

    res.json({
      ok: true,

      service:
        "Face of Style Hijab Factory",

      version:
        "2.0.0",

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
   FRONTEND ROUTES
========================================================= */

/*
   CUSTOMER PORTAL
   Main storefront
*/
app.get(
  "/",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

app.get(
  "/index.html",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/*
   CUSTOMER ALIASES
   These make Admin -> Customer Portal
   navigation reliable.
*/
app.get(
  "/customer",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

app.get(
  "/customer.html",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);


/*
   ADMIN PORTAL
*/
app.get(
  "/admin",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "admin.html"
      )
    );
  }
);

app.get(
  "/admin.html",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "admin.html"
      )
    );
  }
);


/*
   PAYMENT SUCCESS
*/
app.get(
  "/payment-success",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "payment-success.html"
      )
    );
  }
);

app.get(
  "/payment-success.html",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "payment-success.html"
      )
    );
  }
);


/* =========================================================
   API 404
========================================================= */

app.use(
  "/api",
  (req, res) => {

    res.status(404).json({
      ok: false,
      message:
        "API endpoint not found."
    });
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
      "Server error:",
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
        "Internal server error."
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
      "0.0.0.0",
      () => {

        console.log(
          `Face of Style Version 2 running on port ${PORT}`
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

      }
    );

  } catch (error) {

    console.error(
      "Server startup failed:",
      error
    );

    process.exit(1);
  }
}

startServer();
