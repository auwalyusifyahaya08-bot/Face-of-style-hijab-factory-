import express from "express";
import dotenv from "dotenv";
import pg from "pg";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const PORT =
  Number(process.env.PORT) || 10000;

/* =========================================================
   DATABASE
========================================================= */

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString:
        process.env.DATABASE_URL,

      ssl: {
        rejectUnauthorized: false
      }
    })
  : null;

/* =========================================================
   CONFIG
========================================================= */

const WHATSAPP =
  String(
    process.env.WHATSAPP_NUMBER ||
    "2349065828886"
  ).replace(
    /[^0-9]/g,
    ""
  );

const ADMIN_USERNAME =
  String(
    process.env.ADMIN_USERNAME ||
    "admin"
  );

const ADMIN_PASSWORD =
  String(
    process.env.ADMIN_PASSWORD ||
    ""
  );

const PAYSTACK_SECRET_KEY =
  String(
    process.env.PAYSTACK_SECRET_KEY ||
    ""
  ).trim();

/* =========================================================
   SESSIONS
========================================================= */

const sessions =
  new Map();

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
  express.json({
    limit: "2mb",

    verify(req, res, buffer) {
      req.rawBody = buffer;
    }
  })
);

app.use(
  express.urlencoded({
    extended: true
  })
);

/* =========================================================
   HELPERS
========================================================= */

function moneyNumber(value) {

  const number =
    Number(value);

  return Number.isFinite(number)
    ? number
    : 0;

}

function makeToken() {

  return crypto
    .randomBytes(32)
    .toString("hex");

}

function requireAdmin(
  req,
  res,
  next
) {

  const header =
    String(
      req.headers.authorization ||
      ""
    );

  const token =
    header.startsWith("Bearer ")
      ? header
          .slice(7)
          .trim()
      : "";

  if(
    !token ||
    !sessions.has(token)
  ){

    return res.status(401).json({
      ok:false,
      message:"Unauthorized"
    });

  }

  req.admin =
    sessions.get(token);

  next();

}

/* =========================================================
   NORMALIZE PRODUCT
========================================================= */

function normalizeProduct(row){

  return {

    id:
      Number(row.id),

    name:
      String(
        row.name ||
        ""
      ),

    cat:
      String(
        row.cat ||
        "Custom"
      ),

    price:
      moneyNumber(
        row.price
      ),

    img:
      String(
        row.img ||
        ""
      ),

    description:
      String(
        row.description ||
        ""
      ),

    desc:
      String(
        row.description ||
        ""
      ),

    stock:
      Number(
        row.stock ||
        0
      ),

    active:
      row.active !== false

  };

}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initDatabase(){

  if(!pool){

    console.warn(
      "DATABASE_URL is not configured."
    );

    return;

  }

  await pool.query(`

    CREATE TABLE IF NOT EXISTS products (

      id SERIAL PRIMARY KEY,

      name TEXT NOT NULL,

      cat TEXT NOT NULL
        DEFAULT 'Custom',

      price NUMERIC(12,2)
        NOT NULL DEFAULT 0,

      img TEXT NOT NULL
        DEFAULT '',

      description TEXT NOT NULL
        DEFAULT '',

      stock INTEGER NOT NULL
        DEFAULT 0,

      active BOOLEAN NOT NULL
        DEFAULT TRUE,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()

    );

  `);

  /*
    Make sure old databases also receive
    the latest columns.
  */

  await pool.query(`

    ALTER TABLE products

      ADD COLUMN IF NOT EXISTS
        cat TEXT NOT NULL
        DEFAULT 'Custom',

      ADD COLUMN IF NOT EXISTS
        price NUMERIC(12,2)
        NOT NULL DEFAULT 0,

      ADD COLUMN IF NOT EXISTS
        img TEXT NOT NULL
        DEFAULT '',

      ADD COLUMN IF NOT EXISTS
        description TEXT NOT NULL
        DEFAULT '',

      ADD COLUMN IF NOT EXISTS
        stock INTEGER NOT NULL
        DEFAULT 0,

      ADD COLUMN IF NOT EXISTS
        active BOOLEAN NOT NULL
        DEFAULT TRUE,

      ADD COLUMN IF NOT EXISTS
        created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW();

  `);

  await pool.query(`

    CREATE TABLE IF NOT EXISTS orders (

      id SERIAL PRIMARY KEY,

      customer_name TEXT NOT NULL,

      customer_email TEXT NOT NULL,

      customer_phone TEXT NOT NULL,

      delivery_address TEXT NOT NULL,

      items JSONB NOT NULL
        DEFAULT '[]'::jsonb,

      amount NUMERIC(12,2)
        NOT NULL DEFAULT 0,

      reference TEXT UNIQUE,

      status TEXT NOT NULL
        DEFAULT 'pending',

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      paid_at TIMESTAMPTZ

    );

  `);

  await pool.query(`

    CREATE INDEX IF NOT EXISTS
    products_active_idx

    ON products(active);

  `);

  await pool.query(`

    CREATE INDEX IF NOT EXISTS
    orders_status_idx

    ON orders(status);

  `);

  const countResult =
    await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM products
      `
    );

  const count =
    Number(
      countResult
        .rows[0]
        ?.count ||
      0
    );

  if(count === 0){

    await pool.query(
      `
      INSERT INTO products
      (
        name,
        cat,
        price,
        img,
        description,
        stock,
        active
      )

      VALUES

      (
        $1,$2,$3,$4,$5,$6,$7
      ),

      (
        $8,$9,$10,$11,$12,$13,$14
      ),

      (
        $15,$16,$17,$18,$19,$20,$21
      ),

      (
        $22,$23,$24,$25,$26,$27,$28
      ),

      (
        $29,$30,$31,$32,$33,$34,$35
      ),

      (
        $36,$37,$38,$39,$40,$41,$42
      )
      `,
      [

        "Elegant Zip Abaya",
        "Abaya",
        25000,
        "product-1.jpg",
        "Flowing full-length abaya with refined finishing.",
        99,
        true,

        "Two-Tone Signature Gown",
        "Gown",
        22000,
        "product-2.jpg",
        "Elegant two-tone modest gown design.",
        99,
        true,

        "Teal Classic Hijab Dress",
        "Gown",
        20000,
        "product-3.jpg",
        "Comfortable modest dress with clean detailing.",
        99,
        true,

        "Premium Black & White",
        "Abaya",
        28000,
        "product-4.jpg",
        "Statement modest outfit with premium contrast.",
        99,
        true,

        "Ruffle Hijab Collection",
        "Hijab",
        12000,
        "product-5.jpg",
        "Soft, colourful hijab styles with beautiful ruffles.",
        99,
        true,

        "Rose Signature Gown",
        "Custom",
        24000,
        "product-6.jpg",
        "Elegant flowing gown; custom colours available.",
        99,
        true

      ]
    );

  }

  console.log(
    "Database initialized."
  );

}

/* =========================================================
   GET PRODUCTS
========================================================= */

async function getProducts(
  includeInactive = false
){

  if(!pool){

    return [];

  }

  const result =
    await pool.query(

      includeInactive

        ? `
          SELECT *
          FROM products
          ORDER BY id DESC
        `

        : `
          SELECT *
          FROM products
          WHERE active = TRUE
          ORDER BY id DESC
        `

    );

  return result.rows.map(
    normalizeProduct
  );

}

/* =========================================================
   VALIDATE CART
========================================================= */

async function validateCartItems(
  items
){

  if(
    !Array.isArray(items) ||
    items.length === 0
  ){

    throw new Error(
      "Cart is empty."
    );

  }

  const clean = [];

  for(
    const raw of items
  ){

    const id =
      Number(
        raw?.id
      );

    const qty =
      Number(
        raw?.qty
      );

    if(
      !Number.isInteger(id) ||
      qty < 1 ||
      qty > 99
    ){

      throw new Error(
        "Invalid cart item."
      );

    }

    const existing =
      clean.find(
        item =>
          item.id === id
      );

    if(existing){

      existing.qty +=
        qty;

    }else{

      clean.push({
        id,
        qty
      });

    }

  }

  const ids =
    clean.map(
      item =>
        item.id
    );

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
        row => [
          Number(row.id),
          row
        ]
      )
    );

  let total = 0;

  for(
    const item of clean
  ){

    const product =
      productMap.get(
        item.id
      );

    if(
      !product ||
      product.active === false
    ){

      throw new Error(
        "One of the selected products is unavailable."
      );

    }

    const stock =
      Number(
        product.stock ||
        0
      );

    if(
      stock <
      item.qty
    ){

      throw new Error(
        `${product.name} has only ${stock} item(s) in stock.`
      );

    }

    total +=
      moneyNumber(
        product.price
      ) *
      item.qty;

  }

  return {
    items:clean,
    total
  };

}

/* =========================================================
   PUBLIC CONFIG
========================================================= */

app.get(
  "/api/config",
  (req,res) => {

    res.json({

      ok:true,

      whatsapp:
        WHATSAPP,

      paystackConfigured:
        Boolean(
          PAYSTACK_SECRET_KEY
        ),

      adminConfigured:
        Boolean(
          ADMIN_PASSWORD
        ),

      databaseConfigured:
        Boolean(
          pool
        )

    });

  }
);

/* =========================================================
   PUBLIC PRODUCTS
========================================================= */

app.get(
  "/api/products",
  async (req,res) => {

    if(!pool){

      return res.json({
        products:[]
      });

    }

    try{

      const products =
        await getProducts(
          false
        );

      res.json({
        products
      });

    }catch(error){

      console.error(
        "GET /api/products:",
        error
      );

      res.status(500).json({

        products:[],

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
  (req,res) => {

    if(!ADMIN_PASSWORD){

      return res.status(503).json({

        ok:false,

        message:
          "Admin password is not configured on the server."

      });

    }

    const username =
      String(
        req.body?.username ||
        ""
      ).trim();

    const password =
      String(
        req.body?.password ||
        ""
      );

    if(
      username !==
      ADMIN_USERNAME ||

      password !==
      ADMIN_PASSWORD
    ){

      return res.status(401).json({

        ok:false,

        message:
          "Invalid username or password."

      });

    }

    const token =
      makeToken();

    sessions.set(
      token,
      {
        username,
        createdAt:
          Date.now()
      }
    );

    res.json({

      ok:true,

      token

    });

  }
);

/* =========================================================
   ADMIN LOGOUT
========================================================= */

app.post(
  "/api/admin/logout",
  requireAdmin,
  (req,res) => {

    const header =
      String(
        req.headers.authorization ||
        ""
      );

    const token =
      header.startsWith(
        "Bearer "
      )
        ? header
            .slice(7)
            .trim()
        : "";

    sessions.delete(
      token
    );

    res.json({
      ok:true
    });

  }
);

/* =========================================================
   ADMIN ME
========================================================= */

app.get(
  "/api/admin/me",
  requireAdmin,
  (req,res) => {

    res.json({

      ok:true,

      username:
        req.admin.username

    });

  }
);

/* =========================================================
   ADMIN PRODUCTS - GET
========================================================= */

app.get(
  "/api/admin/products",
  requireAdmin,
  async (req,res) => {

    try{

      const products =
        await getProducts(
          true
        );

      res.json({

        ok:true,

        products

      });

    }catch(error){

      console.error(
        "GET /api/admin/products:",
        error
      );

      res.status(500).json({

        ok:false,

        message:
          "Unable to load products."

      });

    }

  }
);

/* =========================================================
   ADMIN PRODUCTS - CREATE
========================================================= */

app.post(
  "/api/admin/products",
  requireAdmin,
  async (req,res) => {

    if(!pool){

      return res.status(503).json({

        ok:false,

        message:
          "Database is not configured."

      });

    }

    try{

      const name =
        String(
          req.body?.name ||
          ""
        ).trim();

      const cat =
        String(
          req.body?.cat ||
          req.body?.category ||
          "Custom"
        ).trim();

      const price =
        moneyNumber(
          req.body?.price
        );

      const img =
        String(
          req.body?.img ||
          req.body?.image ||
          ""
        ).trim();

      const description =
        String(
          req.body?.description ||
          req.body?.desc ||
          ""
        ).trim();

      const stock =
        Math.max(
          0,
          Math.floor(
            Number(
              req.body?.stock ||
              0
            )
          )
        );

      const active =
        req.body?.active === undefined
          ? true
          : Boolean(
              req.body.active
            );

      if(!name){

        return res.status(400).json({

          ok:false,

          message:
            "Product name is required."

        });

      }

      if(price < 0){

        return res.status(400).json({

          ok:false,

          message:
            "Price cannot be negative."

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
            img,
            description,
            stock,
            active
          )

          VALUES
          (
            $1,$2,$3,$4,$5,$6,$7
          )

          RETURNING *
          `,
          [
            name,
            cat,
            price,
            img,
            description,
            stock,
            active
          ]
        );

      res.status(201).json({

        ok:true,

        product:
          normalizeProduct(
            result.rows[0]
          )

      });

    }catch(error){

      console.error(
        "POST /api/admin/products:",
        error
      );

      res.status(500).json({

        ok:false,

        message:
          "Unable to create product."

      });

    }

  }
);

/* =========================================================
   ADMIN PRODUCTS - UPDATE
========================================================= */

app.put(
  "/api/admin/products/:id",
  requireAdmin,
  async (req,res) => {

    if(!pool){

      return res.status(503).json({

        ok:false,

        message:
          "Database is not configured."

      });

    }

    try{

      const id =
        Number(
          req.params.id
        );

      if(
        !Number.isInteger(id)
      ){

        return res.status(400).json({

          ok:false,

          message:
            "Invalid product ID."

        });

      }

      const name =
        String(
          req.body?.name ||
          ""
        ).trim();

      const cat =
        String(
          req.body?.cat ||
          req.body?.category ||
          "Custom"
        ).trim();

      const price =
        moneyNumber(
          req.body?.price
        );

      const img =
        String(
          req.body?.img ||
          req.body?.image ||
          ""
        ).trim();

      const description =
        String(
          req.body?.description ||
          req.body?.desc ||
          ""
        ).trim();

      const stock =
        Math.max(
          0,
          Math.floor(
            Number(
              req.body?.stock ||
              0
            )
          )
        );

      const active =
        req.body?.active === undefined
          ? true
          : Boolean(
              req.body.active
            );

      if(!name){

        return res.status(400).json({

          ok:false,

          message:
            "Product name is required."

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
            img = $4,
            description = $5,
            stock = $6,
            active = $7

          WHERE id = $8

          RETURNING *
          `,
          [
            name,
            cat,
            price,
            img,
            description,
            stock,
            active,
            id
          ]
        );

      if(
        !result.rows.length
      ){

        return res.status(404).json({

          ok:false,

          message:
            "Product not found."

        });

      }

      res.json({

        ok:true,

        product:
          normalizeProduct(
            result.rows[0]
          )

      });

    }catch(error){

      console.error(
        "PUT /api/admin/products/:id:",
        error
      );

      res.status(500).json({

        ok:false,

        message:
          "Unable to update product."

      });

    }

  }
);

/* =========================================================
   ADMIN PRODUCTS - DELETE
========================================================= */

app.delete(
  "/api/admin/products/:id",
  requireAdmin,
  async (req,res) => {

    if(!pool){

      return res.status(503).json({

        ok:false,

        message:
          "Database is not configured."

      });

    }

    try{

      const id =
        Number(
          req.params.id
        );

      if(
        !Number.isInteger(id)
      ){

        return res.status(400).json({

          ok:false,

          message:
            "Invalid product ID."

        });

      }

      const result =
        await pool.query(
          `
          UPDATE products

          SET active = FALSE

          WHERE id = $1

          RETURNING id
          `,
          [id]
        );

      if(
        !result.rows.length
      ){

        return res.status(404).json({

          ok:false,

          message:
            "Product not found."

        });

      }

      res.json({

        ok:true,

        message:
          "Product removed."

      });

    }catch(error){

      console.error(
        "DELETE /api/admin/products/:id:",
        error
      );

      res.status(500).json({

        ok:false,

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
  async (req,res) => {

    if(!pool){

      return res.status(503).json({

        ok:false,

        message:
          "Database is not configured."

      });

    }

    try{

      const result =
        await pool.query(
          `
          SELECT *

          FROM orders

          ORDER BY
            created_at DESC
          `
        );

      res.json({

        ok:true,

        orders:
          result.rows

      });

    }catch(error){

      console.error(
        "GET /api/admin/orders:",
        error
      );

      res.status(500).json({

        ok:false,

        message:
          "Unable to load orders."

      });

    }

  }
);

/* =========================================================
   ADMIN ORDER STATUS
========================================================= */

app.patch(
  "/api/admin/orders/:id",
  requireAdmin,
  async (req,res) => {

    if(!pool){

      return res.status(503).json({

        ok:false,

        message:
          "Database is not configured."

      });

    }

    try{

      const id =
        Number(
          req.params.id
        );

      const status =
        String(
          req.body?.status ||
          ""
        ).trim();

      const allowed = [

        "pending",
        "paid",
        "processing",
        "shipped",
        "completed",
        "cancelled"

      ];

      if(
        !Number.isInteger(id) ||
        !allowed.includes(status)
      ){

        return res.status(400).json({

          ok:false,

          message:
            "Invalid order or status."

        });

      }

      const result =
        await pool.query(
          `
          UPDATE orders

          SET status = $1

          WHERE id = $2

          RETURNING *
          `,
          [
            status,
            id
          ]
        );

      if(
        !result.rows.length
      ){

        return res.status(404).json({

          ok:false,

          message:
            "Order not found."

        });

      }

      res.json({

        ok:true,

        order:
          result.rows[0]

      });

    }catch(error){

      console.error(
        "PATCH /api/admin/orders/:id:",
        error
      );

      res.status(500).json({

        ok:false,

        message:
          "Unable to update order."

      });

    }

  }
);

/* =========================================================
   PAYSTACK INITIALIZE
========================================================= */

app.post(
  "/api/paystack/initialize",
  async (req,res) => {

    if(!pool){

      return res.status(503).json({

        ok:false,

        message:
          "Database is not configured."

      });

    }

    if(
      !PAYSTACK_SECRET_KEY
    ){

      return res.status(503).json({

        ok:false,

        message:
          "Paystack secret key is not configured."

      });

    }

    try{

      const customer =
        req.body?.customer ||
        {};

      const name =
        String(
          customer.name ||
          ""
        ).trim();

      const email =
        String(
          customer.email ||
          ""
        ).trim();

      const phone =
        String(
          customer.phone ||
          ""
        ).trim();

      const address =
        String(
          customer.address ||
          ""
        ).trim();

      if(
        !name ||
        !email ||
        !phone ||
        !address
      ){

        return res.status(400).json({

          ok:false,

          message:
            "Complete customer details are required."

        });

      }

      const emailPattern =
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      if(
        !emailPattern.test(
          email
        )
      ){

        return res.status(400).json({

          ok:false,

          message:
            "Please enter a valid email address."

        });

      }

      const {
        items,
        total
      } =
        await validateCartItems(
          req.body?.items
        );

      if(total <= 0){

        return res.status(400).json({

          ok:false,

          message:
            "Order amount must be greater than zero."

        });

      }

      const reference =
        `FOS-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;

      await pool.query(
        `
        INSERT INTO orders
        (
          customer_name,
          customer_email,
          customer_phone,
          delivery_address,
          items,
          amount,
          reference,
          status
        )

        VALUES
        (
          $1,$2,$3,$4,$5,$6,$7,'pending'
        )
        `,
        [
          name,
          email,
          phone,
          address,
          JSON.stringify(
            items
          ),
          total,
          reference
        ]
      );

      const callbackUrl =
        process.env.PAYSTACK_CALLBACK_URL ||
        `${req.protocol}://${req.get("host")}/api/paystack/callback`;

      const paystackResponse =
        await fetch(
          "https://api.paystack.co/transaction/initialize",
          {

            method:"POST",

            headers:{

              Authorization:
                `Bearer ${PAYSTACK_SECRET_KEY}`,

              "Content-Type":
                "application/json"

            },

            body:
              JSON.stringify({

                email,

                amount:
                  Math.round(
                    total * 100
                  ),

                reference,

                callback_url:
                  callbackUrl,

                metadata:{

                  custom_fields:[

                    {

                      display_name:
                        "Customer Name",

                      variable_name:
                        "customer_name",

                      value:
                        name

                    },

                    {

                      display_name:
                        "Phone",

                      variable_name:
                        "phone",

                      value:
                        phone

                    },

                    {

                      display_name:
                        "Delivery Address",

                      variable_name:
                        "delivery_address",

                      value:
                        address

                    }

                  ]

                }

              })

          }
        );

      const data =
        await paystackResponse.json();

      if(
        !paystackResponse.ok ||
        !data.status ||
        !data.data?.authorization_url
      ){

        console.error(
          "Paystack initialize failed:",
          data
        );

        await pool.query(
          `
          UPDATE orders

          SET status =
            'cancelled'

          WHERE reference =
            $1
          `,
          [reference]
        );

        return res.status(502).json({

          ok:false,

          message:
            data.message ||
            "Paystack could not initialize the payment."

        });

      }

      res.json({

        ok:true,

        reference,

        authorization_url:
          data.data.authorization_url,

        access_code:
          data.data.access_code

      });

    }catch(error){

      console.error(
        "POST /api/paystack/initialize:",
        error
      );

      res.status(500).json({

        ok:false,

        message:
          error.message ||
          "Unable to initialize payment."

      });

    }

  }
);

/* =========================================================
   PAYSTACK VERIFY
========================================================= */

async function verifyPaystackReference(
  reference
){

  if(
    !PAYSTACK_SECRET_KEY
  ){

    throw new Error(
      "Paystack secret key is not configured."
    );

  }

  const response =
    await fetch(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      {

        method:"GET",

        headers:{

          Authorization:
            `Bearer ${PAYSTACK_SECRET_KEY}`

        }

      }
    );

  const data =
    await response.json();

  if(
    !response.ok ||
    !data.status ||
    !data.data
  ){

    throw new Error(
      data.message ||
      "Unable to verify Paystack transaction."
    );

  }

  return data.data;

}

/* =========================================================
   COMPLETE PAID ORDER
========================================================= */

async function completePaidOrder(
  reference
){

  const client =
    await pool.connect();

  try{

    await client.query(
      "BEGIN"
    );

    const orderResult =
      await client.query(
        `
        SELECT *

        FROM orders

        WHERE reference = $1

        FOR UPDATE
        `,
        [reference]
      );

    if(
      !orderResult.rows.length
    ){

      throw new Error(
        "Order not found."
      );

    }

    const order =
      orderResult.rows[0];

    if(
      order.status === "paid" ||
      order.status === "processing" ||
      order.status === "completed"
    ){

      await client.query(
        "COMMIT"
      );

      return order;

    }

    const items =
      Array.isArray(
        order.items
      )
        ? order.items
        : [];

    for(
      const item of items
    ){

      const qty =
        Number(
          item.qty
        );

      const id =
        Number(
          item.id
        );

      if(
        !Number.isInteger(id) ||
        qty < 1
      ){

        throw new Error(
          "Invalid order item."
        );

      }

      const productResult =
        await client.query(
          `
          UPDATE products

          SET stock =
            stock - $1

          WHERE id = $2

          AND active = TRUE

          AND stock >= $1

          RETURNING id
          `,
          [
            qty,
            id
          ]
        );

      if(
        !productResult.rows.length
      ){

        throw new Error(
          "One or more products no longer have enough stock."
        );

      }

    }

    const updated =
      await client.query(
        `
        UPDATE orders

        SET
          status = 'paid',
          paid_at = NOW()

        WHERE id = $1

        RETURNING *
        `,
        [order.id]
      );

    await client.query(
      "COMMIT"
    );

    return updated.rows[0];

  }catch(error){

    await client.query(
      "ROLLBACK"
    );

    throw error;

  }finally{

    client.release();

  }

}

/* =========================================================
   PAYSTACK CALLBACK
========================================================= */

app.get(
  "/api/paystack/callback",
  async (req,res) => {

    const reference =
      String(
        req.query.reference ||
        ""
      ).trim();

    if(!reference){

      return res.redirect(
        "/?payment=missing_reference"
      );

    }

    try{

      const transaction =
        await verifyPaystackReference(
          reference
        );

      if(
        transaction.status !==
        "success"
      ){

        return res.redirect(
          `/?payment=failed&reference=${encodeURIComponent(reference)}`
        );

      }

      await completePaidOrder(
        reference
      );

      res.redirect(
        `/?payment=success&reference=${encodeURIComponent(reference)}`
      );

    }catch(error){

      console.error(
        "Paystack callback:",
        error
      );

      res.redirect(
        `/?payment=error&reference=${encodeURIComponent(reference)}`
      );

    }

  }
);

/* =========================================================
   PAYSTACK WEBHOOK
========================================================= */

app.post(
  "/api/paystack/webhook",
  async (req,res) => {

    try{

      if(
        !PAYSTACK_SECRET_KEY
      ){

        return res.sendStatus(
          503
        );

      }

      const signature =
        String(
          req.headers[
            "x-paystack-signature"
          ] ||
          ""
        );

      const rawBody =
        Buffer.isBuffer(
          req.rawBody
        )
          ? req.rawBody
          : Buffer.from(
              JSON.stringify(
                req.body ||
                {}
              )
            );

      const expected =
        crypto
          .createHmac(
            "sha512",
            PAYSTACK_SECRET_KEY
          )
          .update(
            rawBody
          )
          .digest(
            "hex"
          );

      const signatureBuffer =
        Buffer.from(
          signature
        );

      const expectedBuffer =
        Buffer.from(
          expected
        );

      if(
        signatureBuffer.length !==
        expectedBuffer.length
      ){

        return res.sendStatus(
          401
        );

      }

      if(
        !crypto.timingSafeEqual(
          signatureBuffer,
          expectedBuffer
        )
      ){

        return res.sendStatus(
          401
        );

      }

      const payload =
        JSON.parse(
          rawBody.toString(
            "utf8"
          )
        );

      if(
        payload.event ===
          "charge.success" &&

        payload.data?.reference
      ){

        try{

          await completePaidOrder(
            String(
              payload.data.reference
            )
          );

        }catch(error){

          console.error(
            "Webhook order completion:",
            error
          );

        }

      }

      res.sendStatus(
        200
      );

    }catch(error){

      console.error(
        "Paystack webhook:",
        error
      );

      res.sendStatus(
        400
      );

    }

  }
);

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  "/api/health",
  async (req,res) => {

    let database =
      false;

    if(pool){

      try{

        await pool.query(
          "SELECT 1"
        );

        database =
          true;

      }catch{

        database =
          false;

      }

    }

    res.json({

      ok:true,

      service:
        "Face of Style Hijab Factory",

      database,

      paystackConfigured:
        Boolean(
          PAYSTACK_SECRET_KEY
        ),

      adminConfigured:
        Boolean(
          ADMIN_PASSWORD
        )

    });

  }
);

/* =========================================================
   STATIC FILES
========================================================= */

app.use(
  express.static(
    __dirname,
    {
      index:false
    }
  )
);

/* =========================================================
   ADMIN PAGE
========================================================= */

app.get(
  "/admin",
  (req,res) => {

    res.sendFile(
      path.join(
        __dirname,
        "admin.html"
      )
    );

  }
);

app.get(
  "/admin.html",
  (req,res) => {

    res.sendFile(
      path.join(
        __dirname,
        "admin.html"
      )
    );

  }
);

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.use(
  (req,res,next) => {

    if(
      req.path.startsWith(
        "/api/"
      )
    ){

      return res.status(404).json({

        ok:false,

        message:
          "API route not found."

      });

    }

    res.sendFile(
      path.join(
        __dirname,
        "index.html"
      )
    );

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
      "Unhandled server error:",
      error
    );

    if(
      res.headersSent
    ){

      return next(
        error
      );

    }

    res.status(500).json({

      ok:false,

      message:
        "Internal server error."

    });

  }
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer(){

  try{

    await initDatabase();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `Face of Style Hijab Factory running on port ${PORT}`
        );

        console.log(
          `Database configured: ${Boolean(pool)}`
        );

        console.log(
          `Paystack configured: ${Boolean(PAYSTACK_SECRET_KEY)}`
        );

        console.log(
          `Admin configured: ${Boolean(ADMIN_PASSWORD)}`
        );

      }
    );

  }catch(error){

    console.error(
      "Server startup failed:",
      error
    );

    process.exit(
      1
    );

  }

}

startServer();
