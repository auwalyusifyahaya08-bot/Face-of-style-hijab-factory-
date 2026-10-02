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
const PORT = Number(process.env.PORT || 10000);

/* =========================================================
FACE OF STYLE HIJAB FACTORY
VERSION 2 MASTER SERVER
========================================================= */

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
process.env.WHATSAPP_NUMBER ||
'2349065828886';

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
limit: '8mb',
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

/*
Version 2 uses public/ as the main frontend folder.
*/
app.use(
express.static(
path.join(__dirname, 'public')
)
);

/* =========================================================
SESSIONS
========================================================= */

const adminSessions = new Map();
const customerSessions = new Map();

const SESSION_MAX_AGE =
1000 * 60 * 60 * 24 * 30;

/* =========================================================
HELPERS
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
return /^[^\s@]+@[^\s@]+.[^\s@]+$/.test(
String(email || '').trim()
);
}

function validPhone(phone) {
return /^[0-9+-\s()]{7,25}$/.test(
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

if (!image) return '';

image = image.replace(/\/g, '/');

if (
image.startsWith('http://') ||
image.startsWith('https://') ||
image.startsWith('data:')
) {
return image;
}

image = image.replace(/^/+/, '');

if (image.startsWith('public/')) {
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
PASSWORD
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

if (!token) return null;

const session =
adminSessions.get(token);

if (!session) return null;

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
  INSERT INTO customer_sessions   (   token,   customer_id,   expires_at   )   VALUES   (   $1,   $2,   NOW() + INTERVAL '30 days'   )  ,
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

if (!token) return null;

if (pool) {
try {
const result =
await pool.query(
  SELECT   cs.token,   cs.customer_id,   cs.expires_at,   c.name,   c.email,   c.phone   FROM customer_sessions cs   JOIN customers c   ON c.id = cs.customer_id   WHERE cs.token = $1   AND cs.expires_at > NOW()   LIMIT 1  ,
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

if (!memory) return null;

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

/* PRODUCTS */

await pool.query(  CREATE TABLE IF NOT EXISTS products (   id SERIAL PRIMARY KEY,   name TEXT NOT NULL,   category TEXT NOT NULL DEFAULT 'Fashion',   description TEXT DEFAULT '',   price NUMERIC(12,2) NOT NULL DEFAULT 0,   color TEXT DEFAULT '',   image TEXT DEFAULT '',   stock INTEGER NOT NULL DEFAULT 0,   active BOOLEAN NOT NULL DEFAULT TRUE,   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()   )  );

/* CUSTOMERS */

await pool.query(  CREATE TABLE IF NOT EXISTS customers (   id BIGSERIAL PRIMARY KEY,   name TEXT NOT NULL,   email TEXT UNIQUE NOT NULL,   phone TEXT DEFAULT '',   password_hash TEXT NOT NULL,   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()   )  );

/* CUSTOMER SESSIONS */

await pool.query(  CREATE TABLE IF NOT EXISTS customer_sessions (   token TEXT PRIMARY KEY,   customer_id BIGINT NOT NULL   REFERENCES customers(id)   ON DELETE CASCADE,   expires_at TIMESTAMPTZ NOT NULL,   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()   )  );

/* CUSTOMER ADDRESSES */

await pool.query(  CREATE TABLE IF NOT EXISTS customer_addresses (   id BIGSERIAL PRIMARY KEY,   customer_id BIGINT NOT NULL   REFERENCES customers(id)   ON DELETE CASCADE,   full_name TEXT DEFAULT '',   phone TEXT DEFAULT '',   address TEXT NOT NULL,   city TEXT DEFAULT '',   state TEXT DEFAULT '',   landmark TEXT DEFAULT '',   is_default BOOLEAN NOT NULL DEFAULT FALSE,   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()   )  );

/* ORDERS */

await pool.query(  CREATE TABLE IF NOT EXISTS orders (   id BIGSERIAL PRIMARY KEY,   reference TEXT UNIQUE NOT NULL,   customer_id BIGINT,   customer_name TEXT NOT NULL,   customer_email TEXT NOT NULL,   customer_phone TEXT NOT NULL,   delivery_address TEXT NOT NULL,   payment_method TEXT NOT NULL DEFAULT 'paystack',   payment_status TEXT NOT NULL DEFAULT 'PENDING',   order_status TEXT NOT NULL DEFAULT 'PENDING',   total NUMERIC(12,2) NOT NULL DEFAULT 0,   currency TEXT NOT NULL DEFAULT 'NGN',   paystack_reference TEXT,   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()   )  );

/* ORDER ITEMS */

await pool.query(  CREATE TABLE IF NOT EXISTS order_items (   id BIGSERIAL PRIMARY KEY,   order_id BIGINT NOT NULL   REFERENCES orders(id)   ON DELETE CASCADE,   product_id INTEGER NOT NULL,   product_name TEXT NOT NULL,   price NUMERIC(12,2) NOT NULL,   quantity INTEGER NOT NULL,   subtotal NUMERIC(12,2) NOT NULL   )  );

/* STORE SETTINGS */

await pool.query(  CREATE TABLE IF NOT EXISTS store_settings (   id INTEGER PRIMARY KEY DEFAULT 1,   store_name TEXT DEFAULT 'Face of Style Hijab Factory',   tagline TEXT DEFAULT 'HIJAB FACTORY',   whatsapp TEXT DEFAULT '2349065828886',   phone TEXT DEFAULT '',   email TEXT DEFAULT '',   address TEXT DEFAULT '',   hero_title TEXT DEFAULT 'Modesty, Elegance & Style.',   hero_text TEXT DEFAULT '',   about_text TEXT DEFAULT '',   delivery_text TEXT DEFAULT '',   delivery_fee NUMERIC(12,2) DEFAULT 0,   free_delivery_from NUMERIC(12,2) DEFAULT 0,   bank_name TEXT DEFAULT '',   account_name TEXT DEFAULT '',   account_number TEXT DEFAULT '',   bank_instructions TEXT DEFAULT '',   logo TEXT DEFAULT '',   hero_image TEXT DEFAULT '/assets/product-1.jpg',   primary_color TEXT DEFAULT '#651630',   secondary_color TEXT DEFAULT '#4d1024',   gold_color TEXT DEFAULT '#c9a45b',   background_color TEXT DEFAULT '#fcf8f1',   text_color TEXT DEFAULT '#251c20',   low_stock_limit INTEGER DEFAULT 5,   enable_cart BOOLEAN DEFAULT TRUE,   enable_whatsapp BOOLEAN DEFAULT TRUE,   show_stock BOOLEAN DEFAULT TRUE,   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()   )  );

/* OLD DATABASE COMPATIBILITY FOR STORE SETTINGS */

const settingColumns = [
['store_name', TEXT DEFAULT 'Face of Style Hijab Factory'],
['tagline', TEXT DEFAULT 'HIJAB FACTORY'],
['whatsapp', TEXT DEFAULT '2349065828886'],
['phone', TEXT DEFAULT ''],
['email', TEXT DEFAULT ''],
['address', TEXT DEFAULT ''],
['hero_title', TEXT DEFAULT 'Modesty, Elegance & Style.'],
['hero_text', TEXT DEFAULT ''],
['about_text', TEXT DEFAULT ''],
['delivery_text', TEXT DEFAULT ''],
['delivery_fee', NUMERIC(12,2) DEFAULT 0],
['free_delivery_from', NUMERIC(12,2) DEFAULT 0],
['bank_name', TEXT DEFAULT ''],
['account_name', TEXT DEFAULT ''],
['account_number', TEXT DEFAULT ''],
['bank_instructions', TEXT DEFAULT ''],
['logo', TEXT DEFAULT ''],
['hero_image', TEXT DEFAULT '/assets/product-1.jpg'],
['primary_color', TEXT DEFAULT '#651630'],
['secondary_color', TEXT DEFAULT '#4d1024'],
['gold_color', TEXT DEFAULT '#c9a45b'],
['background_color', TEXT DEFAULT '#fcf8f1'],
['text_color', TEXT DEFAULT '#251c20'],
['low_stock_limit', INTEGER DEFAULT 5],
['enable_cart', BOOLEAN DEFAULT TRUE],
['enable_whatsapp', BOOLEAN DEFAULT TRUE],
['show_stock', BOOLEAN DEFAULT TRUE],
['updated_at', TIMESTAMPTZ NOT NULL DEFAULT NOW()]
];

for (const [column, definition] of settingColumns) {
const exists = await pool.query(  SELECT 1   FROM information_schema.columns   WHERE table_schema='public'   AND table_name='store_settings'   AND column_name=$1   LIMIT 1  , [column]);

if (!exists.rowCount) {  
  await pool.query(`  
    ALTER TABLE store_settings  
    ADD COLUMN ${column} ${definition}  
  `);  
}

}

/*
IMPORTANT: Do not use ON CONFLICT here.
Some older Version 2 databases have store_settings.id
without a UNIQUE/PRIMARY KEY constraint.
*/
const existingSettings = await pool.query(  SELECT id   FROM store_settings   WHERE id = 1   LIMIT 1  );

if (!existingSettings.rowCount) {
await pool.query(  INSERT INTO store_settings (id)   VALUES (1)  );
}

/* OLD DATABASE COMPATIBILITY */

const columns = [
[
'products',
'description',
TEXT DEFAULT ''
],
[
'products',
'color',
TEXT DEFAULT ''
],
[
'products',
'image',
TEXT DEFAULT ''
],
[
'products',
'stock',
INTEGER NOT NULL DEFAULT 0
],
[
'products',
'active',
BOOLEAN NOT NULL DEFAULT TRUE
],
[
'orders',
'customer_id',
BIGINT
],
[
'orders',
'paystack_reference',
TEXT
],
[
'orders',
'payment_status',
TEXT NOT NULL DEFAULT 'PENDING'
],
[
'orders',
'order_status',
TEXT NOT NULL DEFAULT 'PENDING'
],
[
'orders',
'updated_at',
TIMESTAMPTZ NOT NULL DEFAULT NOW()
]
];

for (const [
table,
column,
definition
] of columns) {
const exists =
await pool.query(
  SELECT 1   FROM information_schema.columns   WHERE table_schema='public'   AND table_name=$1   AND column_name=$2   LIMIT 1  ,
[table, column]
);

if (!exists.rowCount) {  
  await pool.query(  
    `  
    ALTER TABLE ${table}  
    ADD COLUMN ${column}  
    ${definition}  
    `  
  );  
}

}

await pool.query(  CREATE INDEX IF NOT EXISTS   idx_products_active   ON products(active)  );

await pool.query(  CREATE INDEX IF NOT EXISTS   idx_orders_created   ON orders(created_at DESC)  );

await pool.query(  CREATE INDEX IF NOT EXISTS   idx_orders_customer   ON orders(customer_id)  );

await pool.query(  CREATE INDEX IF NOT EXISTS   idx_order_items_order   ON order_items(order_id)  );

console.log(
'Face of Style Version 2 database ready.'
);
}

/* =========================================================
HEALTH
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
  } catch {}  
}  

res.json({  
  ok: true,  
  service:  
    'Face of Style Hijab Factory',  
  version: '2',  
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
return res.status(503).json({
ok: false,
products: [],
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
        category,  
        description,  
        price,  
        color,  
        image AS img,  
        image,  
        stock,  
        active,  
        created_at,  
        updated_at  
      FROM products  
      WHERE active = TRUE  
      ORDER BY created_at DESC, id DESC  
    `);  

  const products =  
    result.rows.map(p => ({  
      ...p,  
      id: Number(p.id),  
      price: Number(p.price),  
      stock: Number(p.stock),  
      img: normalizeImage(  
        p.image || p.img  
      ),  
      image: normalizeImage(  
        p.image || p.img  
      )  
    }));  

  res.json({  
    ok: true,  
    products,  
    data: products,  
    count: products.length  
  });  
} catch (error) {  
  console.error(  
    'Products error:',  
    error  
  );  

  res.status(500).json({  
    ok: false,  
    products: [],  
    message:  
      'Unable to load products.'  
  });  
}

}
);

app.get(
'/api/products/:id',
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
      SELECT  
        id,  
        name,  
        category AS cat,  
        category,  
        description,  
        price,  
        color,  
        image AS img,  
        image,  
        stock,  
        active,  
        created_at,  
        updated_at  
      FROM products  
      WHERE id=$1  
        AND active=TRUE  
      LIMIT 1  
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

  const p =  
    result.rows[0];  

  const product = {  
    ...p,  
    id: Number(p.id),  
    price: Number(p.price),  
    stock: Number(p.stock),  
    img: normalizeImage(  
      p.image || p.img  
    ),  
    image: normalizeImage(  
      p.image || p.img  
    )  
  };  

  res.json({  
    ok: true,  
    product,  
    data: product  
  });  
} catch (error) {  
  console.error(  
    'Single product error:',  
    error  
  );  

  res.status(500).json({  
    ok: false,  
    message:  
      'Unable to load product.'  
  });  
}

}
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
CUSTOMER LOGIN
========================================================= */

app.post(
'/api/customer/login',
async (req, res) => {
if (!pool) {
return res.status(503).json({
ok: false,
message:
'Database is not configured.'
});
}

const email =  
  cleanString(  
    req.body?.email,  
    200  
  ).toLowerCase();  

const password =  
  String(  
    req.body?.password || ''  
  );  

if (!email || !password) {  
  return res.status(400).json({  
    ok: false,  
    message:  
      'Email and password are required.'  
  });  
}  

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
      WHERE LOWER(email)=LOWER($1)  
      LIMIT 1  
      `,  
      [email]  
    );  

  if (!result.rowCount) {  
    return res.status(401).json({  
      ok: false,  
      message:  
        'Invalid email or password.'  
    });  
  }  

  const customer =  
    result.rows[0];  

  if (  
    !verifyPassword(  
      password,  
      customer.password_hash  
    )  
  ) {  
    return res.status(401).json({  
      ok: false,  
      message:  
        'Invalid email or password.'  
    });  
  }  

  delete customer.password_hash;  

  const token =  
    await createCustomerSession(  
      customer.id  
    );  

  res.json({  
    ok: true,  
    token,  
    customer  
  });  
} catch (error) {  
  console.error(error);  

  res.status(500).json({  
    ok: false,  
    message:  
      'Unable to login.'  
  });  
}

}
);

/* =========================================================
CUSTOMER ME
========================================================= */

app.get(
'/api/customer/me',
requireCustomer,
async (req, res) => {
try {
const result =
await pool.query(
  SELECT   id,   name,   email,   phone,   created_at   FROM customers   WHERE id=$1   LIMIT 1  ,
[
req.customer.customerId
]
);

if (!result.rowCount) {  
    return res.status(404).json({  
      ok: false,  
      message:  
        'Customer account not found.'  
    });  
  }  

  res.json({  
    ok: true,  
    customer:  
      result.rows[0]  
  });  
} catch (error) {  
  console.error(error);  

  res.status(500).json({  
    ok: false,  
    message:  
      'Unable to load customer.'  
  });  
}

}
);

/* =========================================================
CUSTOMER PROFILE
========================================================= */

app.put(
'/api/customer/profile',
requireCustomer,
async (req, res) => {
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

if (!name || !validEmail(email)) {  
  return res.status(400).json({  
    ok: false,  
    message:  
      'Valid name and email are required.'  
  });  
}  

try {  
  const duplicate =  
    await pool.query(  
      `  
      SELECT id  
      FROM customers  
      WHERE LOWER(email)=LOWER($1)  
        AND id<>$2  
      LIMIT 1  
      `,  
      [  
        email,  
        req.customer.customerId  
      ]  
    );  

  if (duplicate.rowCount) {  
    return res.status(409).json({  
      ok: false,  
      message:  
        'Email is already in use.'  
    });  
  }  

  const result =  
    await pool.query(  
      `  
      UPDATE customers  
      SET  
        name=$1,  
        email=$2,  
        phone=$3,  
        updated_at=NOW()  
      WHERE id=$4  
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
        req.customer.customerId  
      ]  
    );  

  res.json({  
    ok: true,  
    message:  
      'Profile updated successfully.',  
    customer:  
      result.rows[0]  
  });  
} catch (error) {  
  console.error(error);  

  res.status(500).json({  
    ok: false,  
    message:  
      'Unable to update profile.'  
  });  
}

}
);

/* =========================================================
CUSTOMER LOGOUT
========================================================= */

app.post(
'/api/customer/logout',
requireCustomer,
async (req, res) => {
try {
if (pool) {
await pool.query(
  DELETE FROM customer_sessions   WHERE token=$1  ,
[req.customer.token]
);
}

customerSessions.delete(  
    req.customer.token  
  );  

  res.json({  
    ok: true  
  });  
} catch (error) {  
  console.error(error);  

  res.json({  
    ok: true  
  });  
}

}
);

/* =========================================================
CUSTOMER ADDRESSES
========================================================= */

app.get(
'/api/customer/addresses',
requireCustomer,
async (req, res) => {
try {
const result =
await pool.query(
  SELECT *   FROM customer_addresses   WHERE customer_id=$1   ORDER BY   is_default DESC,   created_at DESC  ,
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
  console.error(error);  

  res.status(500).json({  
    ok: false,  
    addresses: [],  
    message:  
      'Unable to load addresses.'  
  });  
}

}
);

app.post(
'/api/customer/addresses',
requireCustomer,
async (req, res) => {
const address =
cleanString(
req.body?.address,
1000
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
    req.body?.phone ||  
    req.customer.phone ||  
    '',  
    40  
  );  

if (!address) {  
  return res.status(400).json({  
    ok: false,  
    message:  
      'Delivery address is required.'  
  });  
}  

try {  
  await pool.query(  
    `  
    UPDATE customer_addresses  
    SET  
      is_default=FALSE,  
      updated_at=NOW()  
    WHERE customer_id=$1  
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
        full_name,  
        phone,  
        address,  
        city,  
        state,  
        is_default  
      )  
      VALUES  
      ($1,$2,$3,$4,$5,$6,TRUE)  
      RETURNING *  
      `,  
      [  
        req.customer.customerId,  
        req.customer.name || '',  
        phone,  
        address,  
        city,  
        state  
      ]  
    );  

  res.status(201).json({  
    ok: true,  
    message:  
      'Delivery information saved.',  
    address:  
      result.rows[0]  
  });  
} catch (error) {  
  console.error(error);  

  res.status(500).json({  
    ok: false,  
    message:  
      'Unable to save address.'  
  });  
}

}
);

app.delete(
'/api/customer/addresses/:id',
requireCustomer,
async (req, res) => {
const id =
positiveInteger(
req.params.id
);

if (!id) {  
  return res.status(400).json({  
    ok: false,  
    message:  
      'Invalid address ID.'  
  });  
}  

try {  
  const result =  
    await pool.query(  
      `  
      DELETE FROM customer_addresses  
      WHERE id=$1  
        AND customer_id=$2  
      RETURNING id  
      `,  
      [  
        id,  
        req.customer.customerId  
      ]  
    );  

  if (!result.rowCount) {  
    return res.status(404).json({  
      ok: false,  
      message:  
        'Address not found.'  
    });  
  }  

  res.json({  
    ok: true  
  });  
} catch (error) {  
  console.error(error);  

  res.status(500).json({  
    ok: false,  
    message:  
      'Unable to delete address.'  
  });  
}

}
);

/* =========================================================
CUSTOMER ORDERS
========================================================= */

app.get(
'/api/customer/orders',
requireCustomer,
async (req, res) => {
try {
const orders =
await pool.query(
  SELECT *   FROM orders   WHERE customer_id=$1   ORDER BY created_at DESC  ,
[
req.customer.customerId
]
);

const ids =  
    orders.rows.map(  
      o => Number(o.id)  
    );  

  let items = [];  

  if (ids.length) {  
    const result =  
      await pool.query(  
        `  
        SELECT *  
        FROM order_items  
        WHERE order_id = ANY($1::bigint[])  
        ORDER BY id ASC  
        `,  
        [ids]  
      );  

    items = result.rows;  
  }  

  const output =  
    orders.rows.map(order => ({  
      ...order,  
      id: Number(order.id),  
      total: Number(order.total),  
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
      createdAt:  
        order.created_at,  
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
        items  
          .filter(  
            item =>  
              Number(  
                item.order_id  
              ) ===  
              Number(order.id)  
          )  
          .map(item => ({  
            ...item,  
            price:  
              Number(item.price),  
            quantity:  
              Number(item.quantity),  
            qty:  
              Number(item.quantity),  
            subtotal:  
              Number(item.subtotal)  
          }))  
    }));  

  res.json({  
    ok: true,  
    orders: output  
  });  
} catch (error) {  
  console.error(error);  

  res.status(500).json({  
    ok: false,  
    orders: [],  
    message:  
      'Unable to load customer orders.'  
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
'/api/admin/logout',
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
ADMIN DASHBOARD
========================================================= */

app.get(
'/api/admin/dashboard',
requireAdmin,
async (req, res) => {
if (!pool) {
return res.status(503).json({
ok: false,
stats: {},
message:
'Database is not configured.'
});
}

try {  
  const result =  
    await pool.query(`  
      SELECT  
        COUNT(*)::int AS orders,  

        COUNT(*)  
        FILTER(  
          WHERE payment_status='PAID'  
        )::int AS paid,  

        COUNT(*)  
        FILTER(  
          WHERE payment_status='PENDING'  
        )::int AS pending,  

        COUNT(*)  
        FILTER(  
          WHERE order_status='PROCESSING'  
        )::int AS processing,  

        COALESCE(  
          SUM(total)  
          FILTER(  
            WHERE payment_status='PAID'  
          ),  
          0  
        )::numeric AS revenue  

      FROM orders  
    `);  

  const row =  
    result.rows[0] || {};  

  res.json({  
    ok: true,  
    stats: {  
      orders:  
        Number(row.orders || 0),  
      paid:  
        Number(row.paid || 0),  
      pending:  
        Number(row.pending || 0),  
      processing:  
        Number(row.processing || 0),  
      revenue:  
        Number(row.revenue || 0)  
    }  
  });  
} catch (error) {  
  console.error(error);  

  res.status(500).json({  
    ok: false,  
    stats: {},  
    message:  
      'Unable to load dashboard.'  
  });  
}

}
);

/* =========================================================
ADMIN PRODUCTS
========================================================= */

app.get(
'/api/admin/products',
requireAdmin,
async (req, res) => {
try {
const result =
await pool.query(  SELECT *   FROM products   ORDER BY created_at DESC, id DESC  );

const products =  
    result.rows.map(p => ({  
      ...p,  
      id: Number(p.id),  
      price: Number(p.price),  
      stock: Number(p.stock),  
      img:  
        normalizeImage(  
          p.image  
        ),  
      image:  
        normalizeImage(  
          p.image  
        )  
    }));  

  res.json({  
    ok: true,  
    products,  
    data: products,  
    count:  
      products.length  
  });  
} catch (error) {  
  console.error(error);  

  res.status(500).json({  
    ok: false,  
    products: [],  
    message:  
      'Unable to load admin products.'  
  });  
}

}
);

app.post(
'/api/admin/products',
requireAdmin,
async (req, res) => {
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

const image =  
  cleanString(  
    req.body?.image ||  
    req.body?.img,  
    2500000  
  );  

const price =  
  positivePrice(  
    req.body?.price  
  );  

const stock =  
  nonNegativeInteger(  
    req.body?.stock || 0  
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
            stock,
            active
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8)
          RETURNING *
          `,
          [
            name,
            category,
            description,
            price,
            color,
            image,
            safeStock,
            true
          ]
        );

      const product =
        result.rows[0];

      res.status(201).json({
        ok: true,
        product
      });
    } catch (error) {
      console.error(
        'Create product error:',
        error
      );

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

    const image =
      cleanString(
        req.body?.image ||
        req.body?.img,
        2500000
      );

    const price =
      positivePrice(
        req.body?.price
      );

    const stock =
      nonNegativeInteger(
        req.body?.stock ?? 0
      );

    const active =
      req.body?.active === false ||
      req.body?.active === 'false'
        ? false
        : true;

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

    if (
      stock === null ||
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
            name=$1,
            category=$2,
            description=$3,
            price=$4,
            color=$5,
            image=$6,
            stock=$7,
            active=$8,
            updated_at=NOW()
          WHERE id=$9
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

      const product =
        result.rows[0];

      res.json({
        ok: true,
        product
      });
    } catch (error) {
      console.error(
        'Update product error:',
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
   DELETE / DEACTIVATE PRODUCT
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
        orders: [],
        message:
          'Database is not configured.'
      });
    }

    try {
      const orders =
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
              '[]'::json
            ) AS items
          FROM orders o
          LEFT JOIN order_items oi
            ON oi.order_id=o.id
          GROUP BY o.id
          ORDER BY
            o.created_at DESC
        `);

      const output =
        orders.rows.map(
          order => ({
            ...order,
            id:
              Number(order.id),
            customerId:
              order.customer_id
                ? Number(
                    order.customer_id
                  )
                : null,
            total:
              Number(order.total),
            createdAt:
              order.created_at,
            updatedAt:
              order.updated_at,
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
            paymentStatus:
              String(
                order.payment_status ||
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
                      id:
                        Number(
                          item.id
                        ),
                      productId:
                        Number(
                          item.productId
                        ),
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
        orders: output,
        data: output,
        count: output.length
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
      const orderResult =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE id=$1
          LIMIT 1
          `,
          [id]
        );

      if (!orderResult.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Order not found.'
        });
      }

      const itemsResult =
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
        orderResult.rows[0];

      const output = {
        ...order,
        id: Number(order.id),
        customerId:
          order.customer_id
            ? Number(
                order.customer_id
              )
            : null,
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
        paymentStatus:
          String(
            order.payment_status ||
            'PENDING'
          ).toLowerCase(),
        items:
          itemsResult.rows.map(
            item => ({
              ...item,
              id:
                Number(item.id),
              productId:
                Number(
                  item.product_id
                ),
              price:
                Number(item.price),
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
      };

      res.json({
        ok: true,
        order: output,
        data: output
      });
    } catch (error) {
      console.error(
        'Admin single order error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to load order.'
      });
    }
  }
);
/* =========================================================
   ADMIN ORDER STATUS UPDATE
========================================================= */

app.put(
  '/api/admin/orders/:id/status',
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

    const orderStatus =
      cleanString(
        req.body?.orderStatus ||
        req.body?.status,
        50
      ).toUpperCase();

    const allowedStatuses = [
      'PENDING',
      'PROCESSING',
      'READY',
      'SHIPPED',
      'DELIVERED',
      'CANCELLED'
    ];

    if (
      !allowedStatuses.includes(
        orderStatus
      )
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid order status.'
      });
    }

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
          UPDATE orders
          SET
            order_status=$1,
            updated_at=NOW()
          WHERE id=$2
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

      const order =
        result.rows[0];

      res.json({
        ok: true,
        message:
          'Order status updated successfully.',
        order
      });
    } catch (error) {
      console.error(
        'Order status update error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to update order status.'
      });
    }
  }
);

/* =========================================================
   ADMIN PAYMENT STATUS UPDATE
========================================================= */

app.put(
  '/api/admin/orders/:id/payment-status',
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

    const paymentStatus =
      cleanString(
        req.body?.paymentStatus ||
        req.body?.status,
        50
      ).toUpperCase();

    const allowedStatuses = [
      'PENDING',
      'PAID',
      'FAILED',
      'CANCELLED'
    ];

    if (
      !allowedStatuses.includes(
        paymentStatus
      )
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid payment status.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          UPDATE orders
          SET
            payment_status=$1,
            updated_at=NOW()
          WHERE id=$2
          RETURNING *
          `,
          [
            paymentStatus,
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
          'Payment status updated successfully.',
        order:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Payment status update error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to update payment status.'
      });
    }
  }
);

/* =========================================================
   STORE SETTINGS - PUBLIC
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
        await pool.query(`
          SELECT *
          FROM store_settings
          WHERE id=1
          LIMIT 1
        `);

      if (!result.rowCount) {
        return res.json({
          ok: true,
          settings: {}
        });
      }

      const settings =
        result.rows[0];

      settings.delivery_fee =
        Number(
          settings.delivery_fee || 0
        );

      settings.free_delivery_from =
        Number(
          settings.free_delivery_from || 0
        );

      settings.low_stock_limit =
        Number(
          settings.low_stock_limit || 0
        );

      settings.logo =
        normalizeImage(
          settings.logo
        );

      settings.hero_image =
        normalizeImage(
          settings.hero_image
        );

      res.json({
        ok: true,
        settings
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
   ADMIN SETTINGS
========================================================= */

app.get(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT *
          FROM store_settings
          WHERE id=1
          LIMIT 1
        `);

      const settings =
        result.rows[0] || {};

      res.json({
        ok: true,
        settings
      });
    } catch (error) {
      console.error(
        'Admin settings error:',
        error
      );

      res.status(500).json({
        ok: false,
        settings: {},
        message:
          'Unable to load settings.'
      });
    }
  }
);

app.put(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {
    const body =
      req.body || {};

    const storeName =
      cleanString(
        body.store_name ||
        body.storeName,
        200
      );

    const tagline =
      cleanString(
        body.tagline,
        200
      );

    const whatsapp =
      cleanString(
        body.whatsapp,
        50
      );

    const phone =
      cleanString(
        body.phone,
        50
      );

    const email =
      cleanString(
        body.email,
        200
      );

    const address =
      cleanString(
        body.address,
        1000
      );

    const heroTitle =
      cleanString(
        body.hero_title ||
        body.heroTitle,
        300
      );

    const heroText =
      cleanString(
        body.hero_text ||
        body.heroText,
        3000
      );

    const aboutText =
      cleanString(
        body.about_text ||
        body.aboutText,
        5000
      );

    const deliveryText =
      cleanString(
        body.delivery_text ||
        body.deliveryText,
        5000
      );

    const deliveryFee =
      positivePrice(
        body.delivery_fee ??
        body.deliveryFee ??
        0
      );

    const freeDeliveryFrom =
      positivePrice(
        body.free_delivery_from ??
        body.freeDeliveryFrom ??
        0
      );

    const bankName =
      cleanString(
        body.bank_name ||
        body.bankName,
        200
      );

    const accountName =
      cleanString(
        body.account_name ||
        body.accountName,
        200
      );

    const accountNumber =
      cleanString(
        body.account_number ||
        body.accountNumber,
        100
      );

    const bankInstructions =
      cleanString(
        body.bank_instructions ||
        body.bankInstructions,
        3000
      );

    const logo =
      cleanString(
        body.logo,
        2500000
      );

    const heroImage =
      cleanString(
        body.hero_image ||
        body.heroImage,
        2500000
      );

    const primaryColor =
      cleanString(
        body.primary_color ||
        body.primaryColor,
        30
      );

    const secondaryColor =
      cleanString(
        body.secondary_color ||
        body.secondaryColor,
        30
      );

    const goldColor =
      cleanString(
        body.gold_color ||
        body.goldColor,
        30
      );

    const backgroundColor =
      cleanString(
        body.background_color ||
        body.backgroundColor,
        30
      );

    const textColor =
      cleanString(
        body.text_color ||
        body.textColor,
        30
      );

    const lowStockLimit =
      nonNegativeInteger(
        body.low_stock_limit ??
        body.lowStockLimit ??
        5
      );

    const enableCart =
      body.enable_cart ??
      body.enableCart ??
      true;

    const enableWhatsapp =
      body.enable_whatsapp ??
      body.enableWhatsapp ??
      true;

    const showStock =
      body.show_stock ??
      body.showStock ??
      true;

    if (deliveryFee === null) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid delivery fee.'
      });
    }

    if (
      freeDeliveryFrom === null
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid free delivery amount.'
      });
    }

    if (
      lowStockLimit === null
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Invalid low stock limit.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          UPDATE store_settings
          SET
            store_name=$1,
            tagline=$2,
            whatsapp=$3,
            phone=$4,
            email=$5,
            address=$6,
            hero_title=$7,
            hero_text=$8,
            about_text=$9,
            delivery_text=$10,
            delivery_fee=$11,
            free_delivery_from=$12,
            bank_name=$13,
            account_name=$14,
            account_number=$15,
            bank_instructions=$16,
            logo=$17,
            hero_image=$18,
            primary_color=$19,
            secondary_color=$20,
            gold_color=$21,
            background_color=$22,
            text_color=$23,
            low_stock_limit=$24,
            enable_cart=$25,
            enable_whatsapp=$26,
            show_stock=$27,
            updated_at=NOW()
          WHERE id=1
          RETURNING *
          `,
          [
            storeName ||
              'Face of Style Hijab Factory',
            tagline ||
              'HIJAB FACTORY',
            whatsapp ||
              WHATSAPP_NUMBER,
            phone,
            email,
            address,
            heroTitle ||
              'Modesty, Elegance & Style.',
            heroText,
            aboutText,
            deliveryText,
            deliveryFee,
            freeDeliveryFrom,
            bankName,
            accountName,
            accountNumber,
            bankInstructions,
            logo,
            heroImage ||
              '/assets/product-1.jpg',
            primaryColor ||
              '#651630',
            secondaryColor ||
              '#4d1024',
            goldColor ||
              '#c9a45b',
            backgroundColor ||
              '#fcf8f1',
            textColor ||
              '#251c20',
            lowStockLimit,
            Boolean(enableCart),
            Boolean(enableWhatsapp),
            Boolean(showStock)
          ]
        );

      res.json({
        ok: true,
        message:
          'Store settings updated successfully.',
        settings:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        'Update settings error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to update store settings.'
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

    const name =
      cleanString(
        body.name ||
        body.customerName,
        150
      );

    const email =
      cleanString(
        body.email ||
        body.customerEmail,
        200
      ).toLowerCase();

    const phone =
      cleanString(
        body.phone ||
        body.customerPhone,
        40
      );

    const address =
      cleanString(
        body.address ||
        body.deliveryAddress,
        1500
      );

    const paymentMethod =
      cleanString(
        body.paymentMethod ||
        'paystack',
        50
      ).toLowerCase();

    let items =
      Array.isArray(body.items)
        ? body.items
        : [];

    if (
      !name ||
      !validEmail(email) ||
      !validPhone(phone) ||
      !address
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Valid customer and delivery information are required.'
      });
    }

    if (!items.length) {
      return res.status(400).json({
        ok: false,
        message:
          'Your cart is empty.'
      });
    }

    if (items.length > 100) {
      return res.status(400).json({
        ok: false,
        message:
          'Too many products in one order.'
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      let total = 0;
      const orderItems = [];

      for (const item of items) {
        const productId =
          positiveInteger(
            item.productId ??
            item.id
          );

        const quantity =
          positiveInteger(
            item.quantity ??
            item.qty
          );

        if (
          !productId ||
          !quantity
        ) {
          throw new Error(
            'Invalid order item.'
          );
        }

        const productResult =
          await client.query(
            `
            SELECT
              id,
              name,
              price,
              stock,
              active
            FROM products
            WHERE id=$1
            FOR UPDATE
            `,
            [productId]
          );

        if (
          !productResult.rowCount
        ) {
          throw new Error(
            'One of the selected products was not found.'
          );
        }

        const product =
          productResult.rows[0];

        if (!product.active) {
          throw new Error(
            `${product.name} is no longer available.`
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
          Math.round(
            price *
              quantity *
              100
          ) / 100;

        total += subtotal;

        orderItems.push({
          productId:
            Number(product.id),
          productName:
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

      const reference =
        createOrderReference();

      let customerId = null;

      const customerSession =
        await getCustomerSession(
          req
        );

      if (customerSession) {
        customerId =
          customerSession.customerId;
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
            $1,$2,$3,$4,$5,$6,$7,
            'PENDING',
            'PENDING',
            $8,
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
            paymentMethod,
            total
          ]
        );

      const order =
        orderResult.rows[0];

      for (const item of orderItems) {
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
            item.productName,
            item.price,
            item.quantity,
            item.subtotal
          ]
        );
      }

      /*
        Stock is reserved by reducing it when
        the order is created.
      */
      for (const item of orderItems) {
        await client.query(
          `
          UPDATE products
          SET
            stock=stock-$1,
            updated_at=NOW()
          WHERE id=$2
          `,
          [
            item.quantity,
            item.productId
          ]
        );
      }

      await client.query(
        'COMMIT'
      );

      res.status(201).json({
        ok: true,
        message:
          'Order created successfully.',
        order: {
          ...order,
          id:
            Number(order.id),
          total:
            Number(order.total),
          reference:
            order.reference
        },
        reference:
          order.reference,
        total:
          Number(order.total)
      });
    } catch (error) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

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
   TRACK ORDER
========================================================= */

app.get(
  '/api/track-order/:reference',
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
          'Order reference is required.'
      });
    }

    try {
      const orderResult =
        await pool.query(
          `
          SELECT *
          FROM orders
          WHERE reference=$1
          LIMIT 1
          `,
          [reference]
        );

      if (!orderResult.rowCount) {
        return res.status(404).json({
          ok: false,
          message:
            'Order not found.'
        });
      }

      const order =
        orderResult.rows[0];

      const itemsResult =
        await pool.query(
          `
          SELECT *
          FROM order_items
          WHERE order_id=$1
          ORDER BY id ASC
          `,
          [order.id]
        );

      const output = {
        ...order,
        id:
          Number(order.id),
        total:
          Number(order.total),
        paymentStatus:
          String(
            order.payment_status
          ).toLowerCase(),
        orderStatus:
          String(
            order.order_status
          ).toLowerCase(),
        items:
          itemsResult.rows.map(
            item => ({
              ...item,
              id:
                Number(item.id),
              productId:
                Number(
                  item.product_id
                ),
              price:
                Number(item.price),
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
      };

      res.json({
        ok: true,
        order: output,
        data: output
      });
    } catch (error) {
      console.error(
        'Track order error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to track order.'
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
    if (!PAYSTACK_SECRET_KEY) {
      return res.status(503).json({
        ok: false,
        message:
          'Paystack is not configured.'
      });
    }

    const email =
      cleanString(
        req.body?.email,
        200
      ).toLowerCase();

    const amount =
      positivePrice(
        req.body?.amount
      );

    const reference =
      cleanString(
        req.body?.reference,
        150
      );

    const callbackUrl =
      cleanString(
        req.body?.callback_url ||
        req.body?.callbackUrl ||
        PAYSTACK_CALLBACK_URL,
        1000
      );

    if (!validEmail(email)) {
      return res.status(400).json({
        ok: false,
        message:
          'Valid email is required.'
      });
    }

    if (
      amount === null ||
      amount <= 0
    ) {
      return res.status(400).json({
        ok: false,
        message:
          'Valid payment amount is required.'
      });
    }

    try {
      const payload = {
        email,
        amount:
          Math.round(
            amount * 100
          ),
        currency: 'NGN'
      };

      if (reference) {
        payload.reference =
          reference;
      }

      if (callbackUrl) {
        payload.callback_url =
          callbackUrl;
      }

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
              JSON.stringify(
                payload
              )
          }
        );

      const data =
        await response.json();

      if (
        !response.ok ||
        !data.status
      ) {
        return res.status(400).json({
          ok: false,
          message:
            data.message ||
            'Unable to initialize Paystack payment.'
        });
      }

      res.json({
        ok: true,
        status:
          data.status,
        message:
          data.message,
        data:
          data.data
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

app.get(
  '/api/paystack/verify/:reference',
  async (req, res) => {
    if (!PAYSTACK_SECRET_KEY) {
      return res.status(503).json({
        ok: false,
        message:
          'Paystack is not configured.'
      });
    }

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
      const response =
        await fetch(
          `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
          {
            method: 'GET',
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
        return res.status(400).json({
          ok: false,
          message:
            data.message ||
            'Unable to verify payment.'
        });
      }

      const payment =
        data.data || {};

      const paid =
        payment.status ===
        'success';

      if (pool) {
        await pool.query(
          `
          UPDATE orders
          SET
            payment_status=$1,
            paystack_reference=$2,
            updated_at=NOW()
          WHERE
            reference=$3
             OR paystack_reference=$3
          `,
          [
            paid
              ? 'PAID'
              : 'FAILED',
            reference,
            reference
          ]
        );
      }

      res.json({
        ok: true,
        paid,
        status:
          payment.status,
        data:
          payment
      });
    } catch (error) {
      console.error(
        'Paystack verify error:',
        error
      );

      res.status(500).json({
        ok: false,
        message:
          'Unable to verify payment.'
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
        '/payment-failed.html'
      );
    }

    if (!PAYSTACK_SECRET_KEY) {
      return res.redirect(
        '/payment-failed.html'
      );
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

      const paid =
        Boolean(
          response.ok &&
          data.status &&
          data.data?.status ===
            'success'
        );

      if (pool) {
        await pool.query(
          `
          UPDATE orders
          SET
            payment_status=$1,
            paystack_reference=$2,
            updated_at=NOW()
          WHERE
            reference=$3
             OR paystack_reference=$3
          `,
          [
            paid
              ? 'PAID'
              : 'FAILED',
            reference,
            reference
          ]
        );
      }

      if (paid) {
        return res.redirect(
          `/payment-success.html?reference=${encodeURIComponent(reference)}`
        );
      }

      return res.redirect(
        `/payment-failed.html?reference=${encodeURIComponent(reference)}`
      );
    } catch (error) {
      console.error(
        'Paystack callback error:',
        error
      );

      return res.redirect(
        '/payment-failed.html'
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
    if (!PAYSTACK_SECRET_KEY) {
      return res.sendStatus(200);
    }

    try {
      const signature =
        req.headers[
          'x-paystack-signature'
        ];

      if (!signature) {
        return res.sendStatus(401);
      }

      const rawBody =
        req.rawBody ||
        Buffer.from(
          JSON.stringify(
            req.body || {}
          )
        );

      const expected =
        crypto
          .createHmac(
            'sha512',
            PAYSTACK_SECRET_KEY
          )
          .update(rawBody)
          .digest('hex');

      const suppliedBuffer =
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
        suppliedBuffer.length !==
        expectedBuffer.length
      ) {
        return res.sendStatus(401);
      }

      if (
        !crypto.timingSafeEqual(
          suppliedBuffer,
          expectedBuffer
        )
      ) {
        return res.sendStatus(401);
      }

      const event =
        req.body || {};

      const data =
        event.data || {};

      const reference =
        cleanString(
          data.reference,
          150
        );

      if (
        reference &&
        pool
      ) {
        let paymentStatus =
          null;

        if (
          event.event ===
            'charge.success' ||
          data.status ===
            'success'
        ) {
          paymentStatus =
            'PAID';
        }

        if (
          event.event ===
            'charge.failed'
        ) {
          paymentStatus =
            'FAILED';
        }

        if (paymentStatus) {
          await pool.query(
            `
            UPDATE orders
            SET
              payment_status=$1,
              paystack_reference=$2,
              updated_at=NOW()
            WHERE
              reference=$3
               OR paystack_reference=$3
            `,
            [
              paymentStatus,
              reference,
              reference
            ]
          );
        }
      }

      return res.sendStatus(200);
    } catch (error) {
      console.error(
        'Paystack webhook error:',
        error
      );

      return res.sendStatus(500);
    }
  }
);

/* =========================================================
   PUBLIC CONFIG
========================================================= */

app.get(
  '/api/config',
  async (req, res) => {
    let settings = {};

    if (pool) {
      try {
        const result =
          await pool.query(`
            SELECT *
            FROM store_settings
            WHERE id=1
            LIMIT 1
          `);

        settings =
          result.rows[0] || {};
      } catch (error) {
        console.error(
          'Config settings error:',
          error
        );
      }
    }

    res.json({
      ok: true,
      version: '2',
      store: {
        name:
          settings.store_name ||
          'Face of Style Hijab Factory',
        tagline:
          settings.tagline ||
          'HIJAB FACTORY',
        whatsapp:
          settings.whatsapp ||
          WHATSAPP_NUMBER,
        phone:
          settings.phone || '',
        email:
          settings.email || '',
        address:
          settings.address || '',
        heroTitle:
          settings.hero_title ||
          'Modesty, Elegance & Style.',
        heroText:
          settings.hero_text || '',
        aboutText:
          settings.about_text || '',
        deliveryText:
          settings.delivery_text || '',
        deliveryFee:
          Number(
            settings.delivery_fee || 0
          ),
        freeDeliveryFrom:
          Number(
            settings.free_delivery_from ||
              0
          ),
        logo:
          normalizeImage(
            settings.logo || ''
          ),
        heroImage:
          normalizeImage(
            settings.hero_image ||
              '/assets/product-1.jpg'
          ),
        primaryColor:
          settings.primary_color ||
          '#651630',
        secondaryColor:
          settings.secondary_color ||
          '#4d1024',
        goldColor:
          settings.gold_color ||
          '#c9a45b',
        backgroundColor:
          settings.background_color ||
          '#fcf8f1',
        textColor:
          settings.text_color ||
          '#251c20',
        lowStockLimit:
          Number(
            settings.low_stock_limit ||
              5
          ),
        enableCart:
          settings.enable_cart !==
          false,
        enableWhatsapp:
          settings.enable_whatsapp !==
          false,
        showStock:
          settings.show_stock !==
          false
      },
      payment: {
        paystack:
          Boolean(
            PAYSTACK_SECRET_KEY
          )
      }
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
  '/payment-success',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'payment-success.html'
      ),
      error => {
        if (error) {
          res.redirect('/');
        }
      }
    );
  }
);

app.get(
  '/payment-success.html',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'payment-success.html'
      ),
      error => {
        if (error) {
          res.redirect('/');
        }
      }
    );
  }
);

app.get(
  '/payment-failed',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'payment-failed.html'
      ),
      error => {
        if (error) {
          res.redirect('/');
        }
      }
    );
  }
);

app.get(
  '/payment-failed.html',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'payment-failed.html'
      ),
      error => {
        if (error) {
          res.redirect('/');
        }
      }
    );
  }
);

/* =========================================================
   API 404
========================================================= */

app.use(
  '/api',
  (req, res) => {
    res.status(404).json({
      ok: false,
      message:
        'API endpoint not found.',
      path:
        req.originalUrl
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
          `Face of Style server started on port ${PORT}.`
        );
      }
    );
  } catch (error) {
    console.error(
      'Database initialization failed:',
      error
    );

    /*
      Keep the server alive so Render can still
      report the actual application error instead
      of silently terminating the process.
    */

    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          `Face of Style server started on port ${PORT}, but database initialization failed.`
        );
      }
    );
  }
}

startServer();
