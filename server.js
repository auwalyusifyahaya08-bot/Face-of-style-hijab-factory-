import'dotenv/config';import express from'express';import pg from'pg';import crypto from'crypto';import path from'path';import{fileURLToPath}from'url';const{Pool}=pg;const __filename=fileURLToPath(import.meta.url);const __dirname=path.dirname(__filename);const app=express();const PORT=process.env.PORT||10000;const PAYSTACK_SECRET_KEY=process.env.PAYSTACK_SECRET_KEY||'';const ADMIN_USERNAME=process.env.ADMIN_USERNAME||'';const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||'';const DATABASE_URL=process.env.DATABASE_URL||'';const WHATSAPP_NUMBER=process.env.WHATSAPP_NUMBER||'2349065828886';const PAYSTACK_CALLBACK_URL=process.env.PAYSTACK_CALLBACK_URL||'';const isProduction=process.env.NODE_ENV==='production';const pool=DATABASE_URL?new Pool({connectionString:DATABASE_URL,ssl:isProduction?{rejectUnauthorized:false}:false}):null;app.use(express.json({limit:'8mb',verify:(req,res,buf)=>{req.rawBody=Buffer.from(buf);}}));app.use(express.urlencoded({extended:true,limit:'8mb'}));app.use(express.static(path.join(__dirname,'public')));const adminSessions=new Map();const customerSessions=new Map();const SESSION_MAX_AGE=1000*60*60*24*30;function cleanString(value,max=500){return String(value??'').trim().slice(0,max);}function positiveInteger(value){const number=Number(value);if(!Number.isInteger(number)||number<1){return null;}return number;}function nonNegativeInteger(value){const number=Number(value);if(!Number.isInteger(number)||number<0){return null;}return number;}function positivePrice(value){const number=Number(value);if(!Number.isFinite(number)||number<0){return null;}return Math.round(number*100)/100;}function validEmail(email){return/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email||'').trim());}function validPhone(phone){return/^[0-9+\-\s()]{7,25}$/.test(String(phone||'').trim());}function normalizeCategory(value){const category=cleanString(value,50);return category||'Fashion';}function normalizeImage(value){let image=cleanString(value,1000);if(!image){return'';}image=image.replace(/\\/g,'/');if(image.startsWith('http://')||image.startsWith('https://')||image.startsWith('data:')){return image;}image=image.replace(/^\/+/,'');if(image.startsWith('public/')){image=image.slice('public/'.length);}if(image.startsWith('assets/')){return'/'+image;}if(image.startsWith('/assets/')){return image;}return'/assets/'+image;}function createToken(){return crypto.randomBytes(48).toString('hex');}function createOrderReference(){return('FS-'+Date.now().toString(36).toUpperCase()+'-'+crypto.randomBytes(4).toString('hex').toUpperCase());}function hashPassword(password){const salt=crypto.randomBytes(16);const derived=crypto.scryptSync(String(password),salt,64);return(salt.toString('hex')+':'+derived.toString('hex'));}function verifyPassword(password,storedHash){try{const parts=String(storedHash||'').split(':');if(parts.length!==2){return false;}const salt=Buffer.from(parts[0],'hex');const stored=Buffer.from(parts[1],'hex');const derived=crypto.scryptSync(String(password),salt,64);if(derived.length!==stored.length){return false;}return crypto.timingSafeEqual(derived,stored);}catch{return false;}}function createAdminSession(username){const token=createToken();adminSessions.set(token,{username,createdAt:Date.now()});return token;}function getAdminSession(req){const auth=req.headers.authorization||'';if(!auth.startsWith('Bearer ')){return null;}const token=auth.slice(7).trim();if(!token){return null;}const session=adminSessions.get(token);if(!session){return null;}if(Date.now()-session.createdAt>SESSION_MAX_AGE){adminSessions.delete(token);return null;}return{token,...session};}function requireAdmin(req,res,next){const session=getAdminSession(req);if(!session){return res.status(401).json({ok:false,message:'Admin authentication required.'});}req.admin=session;next();}function createCustomerMemorySession(customerId){const token=createToken();customerSessions.set(token,{customerId:Number(customerId),createdAt:Date.now()});return token;}function getBearerToken(req){const auth=req.headers.authorization||'';if(!auth.startsWith('Bearer ')){return'';}return auth.slice(7).trim();}async function createCustomerSession(customerId){const token=createToken();if(!pool){return createCustomerMemorySession(customerId);}try{await pool.query(`
      INSERT INTO customer_sessions
      (
        token,
        customer_id,
        expires_at
      )
      VALUES
      (
        $1,
        $2,
        NOW() + INTERVAL '30 days'
      )
      `,[token,customerId]);return token;}catch(error){console.error('Customer session database error:',error);return createCustomerMemorySession(customerId);}}async function getCustomerSession(req){const token=getBearerToken(req);if(!token){return null;}if(pool){try{const result=await pool.query(`
          SELECT
            cs.token,
            cs.customer_id,
            cs.expires_at,
            c.name,
            c.email,
            c.phone
          FROM customer_sessions cs
          JOIN customers c
            ON c.id = cs.customer_id
          WHERE cs.token = $1
            AND cs.expires_at > NOW()
          LIMIT 1
          `,[token]);if(result.rowCount){return{token,customerId:Number(result.rows[0].customer_id),name:result.rows[0].name,email:result.rows[0].email,phone:result.rows[0].phone};}}catch(error){console.error('Customer session lookup error:',error);}}const memory=customerSessions.get(token);if(!memory){return null;}if(Date.now()-memory.createdAt>SESSION_MAX_AGE){customerSessions.delete(token);return null;}return{token,customerId:memory.customerId};}async function requireCustomer(req,res,next){const session=await getCustomerSession(req);if(!session){return res.status(401).json({ok:false,message:'Customer login required.'});}req.customer=session;next();}async function columnExists(tableName,columnName){const result=await pool.query(`
      SELECT 1
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = $1
        AND column_name = $2
      LIMIT 1
      `,[tableName,columnName]);return Boolean(result.rowCount);}async function ensureColumn(tableName,columnName,definition){const exists=await columnExists(tableName,columnName);if(!exists){await pool.query(`
      ALTER TABLE ${tableName}
      ADD COLUMN ${columnName}
      ${definition}
      `);}}async function initDatabase(){if(!pool){console.warn('DATABASE_URL is not configured.');return;}await pool.query(`
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
  `);const imageExists=await columnExists('products','image');const oldImgExists=await columnExists('products','img');if(!imageExists&&oldImgExists){await pool.query(`
      ALTER TABLE products
      RENAME COLUMN img TO image
    `);}await ensureColumn('products','category',`TEXT NOT NULL DEFAULT 'Fashion'`);await ensureColumn('products','description',`TEXT DEFAULT ''`);await ensureColumn('products','price',`NUMERIC(12,2) NOT NULL DEFAULT 0`);await ensureColumn('products','color',`TEXT DEFAULT ''`);await ensureColumn('products','image',`TEXT DEFAULT ''`);await ensureColumn('products','stock',`INTEGER NOT NULL DEFAULT 0`);await ensureColumn('products','active',`BOOLEAN NOT NULL DEFAULT TRUE`);await ensureColumn('products','created_at',`TIMESTAMPTZ NOT NULL DEFAULT NOW()`);await ensureColumn('products','updated_at',`TIMESTAMPTZ NOT NULL DEFAULT NOW()`);await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT DEFAULT '',
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);await ensureColumn('customers','phone',`TEXT DEFAULT ''`);await ensureColumn('customers','password_hash',`TEXT DEFAULT ''`);await ensureColumn('customers','created_at',`TIMESTAMPTZ NOT NULL DEFAULT NOW()`);await ensureColumn('customers','updated_at',`TIMESTAMPTZ NOT NULL DEFAULT NOW()`);await pool.query(`
    CREATE TABLE IF NOT EXISTS customer_sessions (
      token TEXT PRIMARY KEY,
      customer_id BIGINT NOT NULL
        REFERENCES customers(id)
        ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_customer_sessions_customer
    ON customer_sessions(customer_id)
  `);await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_customer_sessions_expires
    ON customer_sessions(expires_at)
  `);await pool.query(`
    CREATE TABLE IF NOT EXISTS customer_addresses (
      id BIGSERIAL PRIMARY KEY,
      customer_id BIGINT NOT NULL
        REFERENCES customers(id)
        ON DELETE CASCADE,
      full_name TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      address TEXT NOT NULL,
      city TEXT DEFAULT '',
      state TEXT DEFAULT '',
      landmark TEXT DEFAULT '',
      is_default BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);await pool.query(`
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
  `);await ensureColumn('orders','customer_id',`BIGINT`);await ensureColumn('orders','paystack_reference',`TEXT`);await ensureColumn('orders','payment_status',`TEXT NOT NULL DEFAULT 'PENDING'`);await ensureColumn('orders','order_status',`TEXT NOT NULL DEFAULT 'PENDING'`);await ensureColumn('orders','updated_at',`TIMESTAMPTZ NOT NULL DEFAULT NOW()`);await pool.query(`
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
  `);await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_products_active
    ON products(active)
  `);await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_products_created
    ON products(created_at DESC)
  `);await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_orders_created
    ON orders(created_at DESC)
  `);await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_orders_customer
    ON orders(customer_id)
  `);await pool.query(`
    CREATE INDEX IF NOT EXISTS
    idx_order_items_order
    ON order_items(order_id)
  `);try{await pool.query(`
      DELETE FROM customer_sessions
      WHERE expires_at <= NOW()
    `);}catch{}console.log('Database initialized successfully.');}app.get('/api/health',async(req,res)=>{let database=false;if(pool){try{await pool.query('SELECT 1');database=true;}catch(error){console.error('Database health error:',error);}}res.json({ok:true,service:'Face of Style Hijab Factory',database,paystackConfigured:Boolean(PAYSTACK_SECRET_KEY),adminConfigured:Boolean(ADMIN_USERNAME&&ADMIN_PASSWORD)});});app.get('/api/products',async(req,res)=>{if(!pool){return res.status(503).json({ok:false,products:[],message:'Database is not configured.'});}try{const result=await pool.query(`
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
        `);const products=result.rows.map(product=>({...product,id:Number(product.id),price:Number(product.price),stock:Number(product.stock),img:normalizeImage(product.image||product.img),image:normalizeImage(product.image||product.img)}));res.json({ok:true,products,data:products,count:products.length});}catch(error){console.error('Products error:',error);res.status(500).json({ok:false,products:[],message:'Unable to load products.'});}});app.get('/api/products/:id',async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const id=positiveInteger(req.params.id);if(!id){return res.status(400).json({ok:false,message:'Invalid product ID.'});}try{const result=await pool.query(`
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
          WHERE id = $1
            AND active = TRUE
          LIMIT 1
          `,[id]);if(!result.rowCount){return res.status(404).json({ok:false,message:'Product not found.'});}const product=result.rows[0];product.id=Number(product.id);product.price=Number(product.price);product.stock=Number(product.stock);product.img=normalizeImage(product.image||product.img);product.image=product.img;res.json({ok:true,product});}catch(error){console.error('Product detail error:',error);res.status(500).json({ok:false,message:'Unable to load product.'});}});async function sendProductDetail(req,res){if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const id=positiveInteger(req.params.id);if(!id){return res.status(400).json({ok:false,message:'Invalid product ID.'});}try{const result=await pool.query(`SELECT id,name,category AS cat,category,description,price,color,image AS img,image,stock,active,created_at,updated_at
       FROM products WHERE id=$1 AND active=TRUE LIMIT 1`,[id]);if(!result.rowCount){return res.status(404).json({ok:false,message:'Product not found.'});}const product=result.rows[0];product.id=Number(product.id);product.price=Number(product.price);product.stock=Number(product.stock);product.img=normalizeImage(product.image||product.img);product.image=product.img;return res.json({ok:true,product});}catch(error){console.error('Product alias error:',error);return res.status(500).json({ok:false,message:'Unable to load product.'});}}app.get('/api/product/:id',sendProductDetail);app.get('/api/product-details/:id',sendProductDetail);app.get('/api/customer/products/:id',sendProductDetail);app.post('/api/customer/register',async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const name=cleanString(req.body?.name,150);const email=cleanString(req.body?.email,200).toLowerCase();const phone=cleanString(req.body?.phone,40);const password=String(req.body?.password||'');if(!name||!email||!password){return res.status(400).json({ok:false,message:'Name, email and password are required.'});}if(!validEmail(email)){return res.status(400).json({ok:false,message:'Please provide a valid email.'});}if(password.length<6){return res.status(400).json({ok:false,message:'Password must be at least 6 characters.'});}if(phone&&!validPhone(phone)){return res.status(400).json({ok:false,message:'Please provide a valid phone number.'});}try{const existing=await pool.query(`
          SELECT id
          FROM customers
          WHERE LOWER(email) = LOWER($1)
          LIMIT 1
          `,[email]);if(existing.rowCount){return res.status(409).json({ok:false,message:'An account with this email already exists.'});}const passwordHash=hashPassword(password);const result=await pool.query(`
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
          `,[name,email,phone,passwordHash]);const customer=result.rows[0];const token=await createCustomerSession(customer.id);res.status(201).json({ok:true,token,customer});}catch(error){console.error('Customer register error:',error);res.status(500).json({ok:false,message:'Unable to create customer account.'});}});app.post('/api/customer/login',async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const email=cleanString(req.body?.email,200).toLowerCase();const password=String(req.body?.password||'');if(!email||!password){return res.status(400).json({ok:false,message:'Email and password are required.'});}try{const result=await pool.query(`
          SELECT
            id,
            name,
            email,
            phone,
            password_hash
          FROM customers
          WHERE LOWER(email) = LOWER($1)
          LIMIT 1
          `,[email]);if(!result.rowCount){return res.status(401).json({ok:false,message:'Invalid email or password.'});}const customer=result.rows[0];if(!verifyPassword(password,customer.password_hash)){return res.status(401).json({ok:false,message:'Invalid email or password.'});}const token=await createCustomerSession(customer.id);delete customer.password_hash;res.json({ok:true,token,customer});}catch(error){console.error('Customer login error:',error);res.status(500).json({ok:false,message:'Unable to login.'});}});
app.get('/api/customer/me',requireCustomer,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}try{const result=await pool.query(`
          SELECT
            id,
            name,
            email,
            phone,
            created_at
          FROM customers
          WHERE id = $1
          LIMIT 1
          `,[req.customer.customerId]);if(!result.rowCount){return res.status(401).json({ok:false,message:'Customer account not found.'});}res.json({ok:true,customer:result.rows[0]});}catch(error){console.error('Customer me error:',error);res.status(500).json({ok:false,message:'Unable to load customer session.'});}});app.post('/api/customer/logout',requireCustomer,async(req,res)=>{const token=req.customer.token;customerSessions.delete(token);if(pool){try{await pool.query(`
          DELETE FROM customer_sessions
          WHERE token = $1
          `,[token]);}catch(error){console.error('Customer logout DB error:',error);}}res.json({ok:true});});app.get('/api/customer/addresses',requireCustomer,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,addresses:[],message:'Database is not configured.'});}try{const result=await pool.query(`
          SELECT
            id,
            customer_id,
            full_name,
            phone,
            address,
            city,
            state,
            landmark,
            is_default,
            created_at,
            updated_at
          FROM customer_addresses
          WHERE customer_id = $1
          ORDER BY
            is_default DESC,
            created_at DESC
          `,[req.customer.customerId]);res.json({ok:true,addresses:result.rows});}catch(error){console.error('Customer addresses error:',error);res.status(500).json({ok:false,addresses:[],message:'Unable to load delivery addresses.'});}});app.get('/api/customer/address',requireCustomer,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}try{const result=await pool.query(`
          SELECT *
          FROM customer_addresses
          WHERE customer_id = $1
          ORDER BY
            is_default DESC,
            created_at DESC
          LIMIT 1
          `,[req.customer.customerId]);res.json({ok:true,address:result.rows[0]||null});}catch(error){console.error('Default address error:',error);res.status(500).json({ok:false,message:'Unable to load delivery address.'});}});app.post('/api/customer/addresses',requireCustomer,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const address=cleanString(req.body?.address,1000);const fullName=cleanString(req.body?.full_name||req.body?.name,150);const phone=cleanString(req.body?.phone,40);const city=cleanString(req.body?.city,100);const state=cleanString(req.body?.state,100);const landmark=cleanString(req.body?.landmark,300);const isDefault=Boolean(req.body?.is_default||req.body?.isDefault);if(!address){return res.status(400).json({ok:false,message:'Delivery address is required.'});}if(phone&&!validPhone(phone)){return res.status(400).json({ok:false,message:'Please provide a valid phone number.'});}const client=await pool.connect();try{await client.query('BEGIN');if(isDefault){await client.query(`
          UPDATE customer_addresses
          SET
            is_default = FALSE,
            updated_at = NOW()
          WHERE customer_id = $1
          `,[req.customer.customerId]);}const result=await client.query(`
          INSERT INTO customer_addresses
          (
            customer_id,
            full_name,
            phone,
            address,
            city,
            state,
            landmark,
            is_default
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8)
          RETURNING *
          `,[req.customer.customerId,fullName,phone,address,city,state,landmark,isDefault]);await client.query('COMMIT');res.status(201).json({ok:true,address:result.rows[0]});}catch(error){try{await client.query('ROLLBACK');}catch{}console.error('Create address error:',error);res.status(500).json({ok:false,message:'Unable to save delivery address.'});}finally{client.release();}});app.put('/api/customer/addresses/:id',requireCustomer,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const id=positiveInteger(req.params.id);if(!id){return res.status(400).json({ok:false,message:'Invalid address ID.'});}const address=cleanString(req.body?.address,1000);const fullName=cleanString(req.body?.full_name||req.body?.name,150);const phone=cleanString(req.body?.phone,40);const city=cleanString(req.body?.city,100);const state=cleanString(req.body?.state,100);const landmark=cleanString(req.body?.landmark,300);const isDefault=Boolean(req.body?.is_default||req.body?.isDefault);if(!address){return res.status(400).json({ok:false,message:'Delivery address is required.'});}const client=await pool.connect();try{await client.query('BEGIN');if(isDefault){await client.query(`
          UPDATE customer_addresses
          SET
            is_default = FALSE,
            updated_at = NOW()
          WHERE customer_id = $1
          `,[req.customer.customerId]);}const result=await client.query(`
          UPDATE customer_addresses
          SET
            full_name = $1,
            phone = $2,
            address = $3,
            city = $4,
            state = $5,
            landmark = $6,
            is_default = $7,
            updated_at = NOW()
          WHERE id = $8
            AND customer_id = $9
          RETURNING *
          `,[fullName,phone,address,city,state,landmark,isDefault,id,req.customer.customerId]);if(!result.rowCount){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Address not found.'});}await client.query('COMMIT');res.json({ok:true,address:result.rows[0]});}catch(error){try{await client.query('ROLLBACK');}catch{}console.error('Update address error:',error);res.status(500).json({ok:false,message:'Unable to update delivery address.'});}finally{client.release();}});app.delete('/api/customer/addresses/:id',requireCustomer,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const id=positiveInteger(req.params.id);if(!id){return res.status(400).json({ok:false,message:'Invalid address ID.'});}try{const result=await pool.query(`
          DELETE FROM customer_addresses
          WHERE id = $1
            AND customer_id = $2
          RETURNING id
          `,[id,req.customer.customerId]);if(!result.rowCount){return res.status(404).json({ok:false,message:'Address not found.'});}res.json({ok:true,message:'Delivery address removed.'});}catch(error){console.error('Delete address error:',error);res.status(500).json({ok:false,message:'Unable to delete address.'});}});app.get('/api/customer/delivery-address',requireCustomer,async(req,res)=>{try{const result=await pool.query(`SELECT *
         FROM customer_addresses
         WHERE customer_id = $1
         ORDER BY is_default DESC, created_at DESC
         LIMIT 1`,[req.customer.customerId]);res.json({ok:true,address:result.rows[0]||null,addresses:result.rows});}catch(error){console.error('Delivery address compatibility error:',error);res.status(500).json({ok:false,message:'Unable to load delivery address.'});}});app.post('/api/customer/delivery-address',requireCustomer,async(req,res)=>{const address=cleanString(req.body?.address,1000);const fullName=cleanString(req.body?.full_name||req.body?.name,150);const phone=cleanString(req.body?.phone,40);const city=cleanString(req.body?.city,100);const state=cleanString(req.body?.state,100);const landmark=cleanString(req.body?.landmark,300);const isDefault=Boolean(req.body?.is_default??req.body?.isDefault??true);if(!address){return res.status(400).json({ok:false,message:'Delivery address is required.'});}if(phone&&!validPhone(phone)){return res.status(400).json({ok:false,message:'Please provide a valid phone number.'});}const client=await pool.connect();try{await client.query('BEGIN');if(isDefault){await client.query(`UPDATE customer_addresses
           SET is_default = FALSE, updated_at = NOW()
           WHERE customer_id = $1`,[req.customer.customerId]);}const result=await client.query(`INSERT INTO customer_addresses
         (customer_id, full_name, phone, address, city, state, landmark, is_default)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         RETURNING *`,[req.customer.customerId,fullName,phone,address,city,state,landmark,isDefault]);await client.query('COMMIT');res.status(201).json({ok:true,address:result.rows[0],addresses:[result.rows[0]]});}catch(error){try{await client.query('ROLLBACK');}catch{}console.error('Create delivery address compatibility error:',error);res.status(500).json({ok:false,message:'Unable to save delivery address.'});}finally{client.release();}});app.put('/api/customer/delivery-address/:id',requireCustomer,async(req,res)=>{const id=positiveInteger(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid address ID.'});const address=cleanString(req.body?.address,1000);const fullName=cleanString(req.body?.full_name||req.body?.name,150);const phone=cleanString(req.body?.phone,40);const city=cleanString(req.body?.city,100);const state=cleanString(req.body?.state,100);const landmark=cleanString(req.body?.landmark,300);const isDefault=Boolean(req.body?.is_default??req.body?.isDefault??true);if(!address)return res.status(400).json({ok:false,message:'Delivery address is required.'});if(phone&&!validPhone(phone))return res.status(400).json({ok:false,message:'Please provide a valid phone number.'});const client=await pool.connect();try{await client.query('BEGIN');if(isDefault){await client.query(`UPDATE customer_addresses SET is_default=FALSE, updated_at=NOW() WHERE customer_id=$1`,[req.customer.customerId]);}const result=await client.query(`UPDATE customer_addresses
         SET full_name=$1, phone=$2, address=$3, city=$4, state=$5, landmark=$6, is_default=$7, updated_at=NOW()
         WHERE id=$8 AND customer_id=$9
         RETURNING *`,[fullName,phone,address,city,state,landmark,isDefault,id,req.customer.customerId]);if(!result.rowCount){await client.query('ROLLBACK');return res.status(404).json({ok:false,message:'Address not found.'});}await client.query('COMMIT');res.json({ok:true,address:result.rows[0]});}catch(error){try{await client.query('ROLLBACK');}catch{}console.error('Update delivery address compatibility error:',error);res.status(500).json({ok:false,message:'Unable to update delivery address.'});}finally{client.release();}});app.delete('/api/customer/delivery-address/:id',requireCustomer,async(req,res)=>{const id=positiveInteger(req.params.id);if(!id)return res.status(400).json({ok:false,message:'Invalid address ID.'});try{const result=await pool.query(`DELETE FROM customer_addresses WHERE id=$1 AND customer_id=$2 RETURNING id`,[id,req.customer.customerId]);if(!result.rowCount)return res.status(404).json({ok:false,message:'Address not found.'});res.json({ok:true,message:'Delivery address removed.'});}catch(error){console.error('Delete delivery address compatibility error:',error);res.status(500).json({ok:false,message:'Unable to delete address.'});}});app.get('/api/customer/delivery-addresses',requireCustomer,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,addresses:[],message:'Database is not configured.'});}try{const result=await pool.query(`SELECT * FROM customer_addresses
         WHERE customer_id=$1
         ORDER BY is_default DESC, created_at DESC`,[req.customer.customerId]);res.json({ok:true,addresses:result.rows,address:result.rows[0]||null});}catch(error){console.error('Delivery addresses alias error:',error);res.status(500).json({ok:false,addresses:[],message:'Unable to load delivery addresses.'});}});app.get('/api/customer/orders',requireCustomer,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,orders:[],message:'Database is not configured.'});}try{const ordersResult=await pool.query(`
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
          WHERE customer_id = $1
          ORDER BY created_at DESC
          `,[req.customer.customerId]);const orders=ordersResult.rows;if(!orders.length){return res.json({ok:true,orders:[]});}const ids=orders.map(order=>order.id);const itemsResult=await pool.query(`
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
          `,[ids]);const itemsByOrder=new Map();for(const item of itemsResult.rows){if(!itemsByOrder.has(item.order_id)){itemsByOrder.set(item.order_id,[]);}itemsByOrder.get(item.order_id).push({...item,product_id:Number(item.product_id),price:Number(item.price),quantity:Number(item.quantity),subtotal:Number(item.subtotal)});}const output=orders.map(order=>({...order,id:Number(order.id),total:Number(order.total),items:itemsByOrder.get(order.id)||[]}));res.json({ok:true,orders:output});}catch(error){console.error('Customer orders error:',error);res.status(500).json({ok:false,orders:[],message:'Unable to load your orders.'});}});app.get('/api/customer/orders/:id',requireCustomer,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const id=positiveInteger(req.params.id);if(!id){return res.status(400).json({ok:false,message:'Invalid order ID.'});}try{const orderResult=await pool.query(`
          SELECT *
          FROM orders
          WHERE id = $1
            AND customer_id = $2
          LIMIT 1
          `,[id,req.customer.customerId]);if(!orderResult.rowCount){return res.status(404).json({ok:false,message:'Order not found.'});}const itemsResult=await pool.query(`
          SELECT
            id,
            order_id,
            product_id,
            product_name,
            price,
            quantity,
            subtotal
          FROM order_items
          WHERE order_id = $1
          ORDER BY id ASC
          `,[id]);const order=orderResult.rows[0];order.id=Number(order.id);order.total=Number(order.total);order.items=itemsResult.rows.map(item=>({...item,product_id:Number(item.product_id),price:Number(item.price),quantity:Number(item.quantity),subtotal:Number(item.subtotal)}));res.json({ok:true,order});}catch(error){console.error('Customer single order error:',error);res.status(500).json({ok:false,message:'Unable to load order.'});}});app.post('/api/admin/login',(req,res)=>{const username=cleanString(req.body?.username,100);const password=String(req.body?.password||'');if(!ADMIN_USERNAME||!ADMIN_PASSWORD){return res.status(503).json({ok:false,message:'Admin credentials are not configured on the server.'});}if(username!==ADMIN_USERNAME||password!==ADMIN_PASSWORD){return res.status(401).json({ok:false,message:'Invalid admin credentials.'});}const token=createAdminSession(username);res.json({ok:true,token,username});});app.post('/api/admin/logout',requireAdmin,(req,res)=>{adminSessions.delete(req.admin.token);res.json({ok:true});});app.get('/api/admin/me',requireAdmin,(req,res)=>{res.json({ok:true,username:req.admin.username});});app.get('/api/admin/products',requireAdmin,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,products:[],message:'Database is not configured.'});}try{const result=await pool.query(`
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
          ORDER BY created_at DESC, id DESC
        `);const products=result.rows.map(product=>({...product,id:Number(product.id),price:Number(product.price),stock:Number(product.stock),img:normalizeImage(product.image||product.img),image:normalizeImage(product.image||product.img)}));res.json({ok:true,products,data:products,count:products.length});}catch(error){console.error('Admin products error:',error);res.status(500).json({ok:false,products:[],message:'Unable to load admin products.'});}});app.post('/api/admin/products',requireAdmin,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const name=cleanString(req.body?.name,150);const category=normalizeCategory(req.body?.category||req.body?.cat);const description=cleanString(req.body?.description||req.body?.desc,2000);const color=cleanString(req.body?.color,100);const image=cleanString(req.body?.image||req.body?.img,1000);const price=positivePrice(req.body?.price);const stock=nonNegativeInteger(req.body?.stock);const safeStock=stock===null?0:stock;if(!name){return res.status(400).json({ok:false,message:'Product name is required.'});}if(price===null){return res.status(400).json({ok:false,message:'A valid product price is required.'});}if(safeStock<0||safeStock>1000000){return res.status(400).json({ok:false,message:'Invalid stock quantity.'});}try{const result=await pool.query(`
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
          ($1,$2,$3,$4,$5,$6,$7,TRUE)
          RETURNING *
          `,[name,category,description,price,color,image,safeStock]);const product=result.rows[0];product.id=Number(product.id);product.price=Number(product.price);product.stock=Number(product.stock);product.img=normalizeImage(product.image);product.image=product.img;res.status(201).json({ok:true,product});}catch(error){console.error('Create product error:',error);res.status(500).json({ok:false,message:'Unable to create product.'});}});app.put('/api/admin/products/:id',requireAdmin,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const id=positiveInteger(req.params.id);if(!id){return res.status(400).json({ok:false,message:'Invalid product ID.'});}const name=cleanString(req.body?.name,150);const category=normalizeCategory(req.body?.category||req.body?.cat);const description=cleanString(req.body?.description||req.body?.desc,2000);const color=cleanString(req.body?.color,100);const image=cleanString(req.body?.image||req.body?.img,1000);const price=positivePrice(req.body?.price);const stock=nonNegativeInteger(req.body?.stock);const active=req.body?.active!==false;if(!name||price===null){return res.status(400).json({ok:false,message:'Product name and valid price are required.'});}if(stock===null){return res.status(400).json({ok:false,message:'Invalid stock quantity.'});}try{const result=await pool.query(`
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
          `,[name,category,description,price,color,image,stock,active,id]);if(!result.rowCount){return res.status(404).json({ok:false,message:'Product not found.'});}const product=result.rows[0];product.id=Number(product.id);product.price=Number(product.price);product.stock=Number(product.stock);product.img=normalizeImage(product.image);product.image=product.img;res.json({ok:true,product});}catch(error){console.error('Update product error:',error);res.status(500).json({ok:false,message:'Unable to update product.'});}});app.delete('/api/admin/products/:id',requireAdmin,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const id=positiveInteger(req.params.id);if(!id){return res.status(400).json({ok:false,message:'Invalid product ID.'});}try{const result=await pool.query(`
          UPDATE products
          SET
            active = FALSE,
            updated_at = NOW()
          WHERE id = $1
          RETURNING id
          `,[id]);if(!result.rowCount){return res.status(404).json({ok:false,message:'Product not found.'});}res.json({ok:true,message:'Product removed from the store.'});}catch(error){console.error('Delete product error:',error);res.status(500).json({ok:false,message:'Unable to remove product.'});}});app.get('/api/admin/orders',requireAdmin,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,orders:[],message:'Database is not configured.'});}try{const ordersResult=await pool.query(`
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
        `);const orders=ordersResult.rows;if(!orders.length){return res.json({ok:true,orders:[]});}const ids=orders.map(order=>order.id);const itemsResult=await pool.query(`
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
          `,[ids]);const itemsByOrder=new Map();for(const item of itemsResult.rows){if(!itemsByOrder.has(item.order_id)){itemsByOrder.set(item.order_id,[]);}itemsByOrder.get(item.order_id).push({...item,product_id:Number(item.product_id),price:Number(item.price),quantity:Number(item.quantity),subtotal:Number(item.subtotal)});}const output=orders.map(order=>({...order,id:Number(order.id),customer_id:order.customer_id?Number(order.customer_id):null,total:Number(order.total),items:itemsByOrder.get(order.id)||[]}));res.json({ok:true,orders:output});}catch(error){console.error('Admin orders error:',error);res.status(500).json({ok:false,orders:[],message:'Unable to load orders.'});}});app.patch('/api/admin/orders/:id',requireAdmin,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const id=positiveInteger(req.params.id);const orderStatus=cleanString(req.body?.order_status||req.body?.status,30).toUpperCase();const allowed=['PENDING','PROCESSING','SHIPPED','DELIVERED','CANCELLED'];if(!id){return res.status(400).json({ok:false,message:'Invalid order ID.'});}if(!allowed.includes(orderStatus)){return res.status(400).json({ok:false,message:'Invalid order status.'});}try{const result=await pool.query(`
          UPDATE orders
          SET
            order_status = $1,
            updated_at = NOW()
          WHERE id = $2
          RETURNING *
          `,[orderStatus,id]);if(!result.rowCount){return res.status(404).json({ok:false,message:'Order not found.'});}res.json({ok:true,order:result.rows[0]});}catch(error){console.error('Update order status error:',error);res.status(500).json({ok:false,message:'Unable to update order.'});}});app.patch('/api/admin/orders/:id/payment',requireAdmin,async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}const id=positiveInteger(req.params.id);const status=cleanString(req.body?.payment_status||req.body?.status,30).toUpperCase();const allowed=['PENDING','PAID','FAILED','REFUNDED'];if(!id){return res.status(400).json({ok:false,message:'Invalid order ID.'});}if(!allowed.includes(status)){return res.status(400).json({ok:false,message:'Invalid payment status.'});}try{const result=await pool.query(`
          UPDATE orders
          SET
            payment_status = $1,
            order_status =
              CASE
                WHEN $1 = 'PAID'
                  AND order_status = 'PENDING'
                THEN 'PROCESSING'
                ELSE order_status
              END,
            updated_at = NOW()
          WHERE id = $2
          RETURNING *
          `,[status,id]);if(!result.rowCount){return res.status(404).json({ok:false,message:'Order not found.'});}res.json({ok:true,order:result.rows[0]});}catch(error){console.error('Admin payment update error:',error);res.status(500).json({ok:false,message:'Unable to update payment status.'});}});app.post('/api/paystack/initialize',async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}if(!PAYSTACK_SECRET_KEY){return res.status(503).json({ok:false,message:'Paystack is not configured on the server.'});}const customer=req.body?.customer||{};const name=cleanString(customer.name,150);const email=cleanString(customer.email,200).toLowerCase();const phone=cleanString(customer.phone,40);const address=cleanString(customer.address,1000);const rawItems=Array.isArray(req.body?.items)?req.body.items:[];if(!name||!email||!phone||!address){return res.status(400).json({ok:false,message:'Complete customer details are required.'});}if(!validEmail(email)){return res.status(400).json({ok:false,message:'Please provide a valid email address.'});}if(!validPhone(phone)){return res.status(400).json({ok:false,message:'Please provide a valid phone number.'});}if(!rawItems.length){return res.status(400).json({ok:false,message:'Your cart is empty.'});}const client=await pool.connect();try{await client.query('BEGIN');const customerSession=await getCustomerSession(req);let customerId=customerSession?.customerId||null;const productIds=rawItems.map(item=>positiveInteger(item.id)).filter(Boolean);if(!productIds.length){throw new Error('Invalid cart items.');}const uniqueProductIds=[...new Set(productIds)];const productsResult=await client.query(`
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
          `,[uniqueProductIds]);const productMap=new Map(productsResult.rows.map(product=>[Number(product.id),product]));const orderItems=[];let total=0;for(const rawItem of rawItems){const productId=positiveInteger(rawItem.id);const quantity=positiveInteger(rawItem.qty||rawItem.quantity);if(!productId||!quantity){throw new Error('Invalid cart quantity.');}if(quantity>99){throw new Error('Maximum quantity per item is 99.');}const product=productMap.get(productId);if(!product||!product.active){throw new Error('One of the products is no longer available.');}if(Number(product.stock)<quantity){throw new Error(`${product.name} does not have enough stock.`);}const price=Number(product.price);const subtotal=Math.round(price*quantity*100)/100;total+=subtotal;orderItems.push({productId,name:product.name,price,quantity,subtotal});}total=Math.round(total*100)/100;if(!Number.isFinite(total)||total<=0){throw new Error('Invalid order total.');}if(!customerId){try{const customerResult=await client.query(`
              SELECT id
              FROM customers
              WHERE LOWER(email) =
                LOWER($1)
              LIMIT 1
              `,[email]);if(customerResult.rowCount){customerId=Number(customerResult.rows[0].id);}}catch{}}const reference=createOrderReference();const orderResult=await client.query(`
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
          RETURNING
            id,
            reference,
            total
          `,[reference,customerId,name,email,phone,address,total]);const order=orderResult.rows[0];for(const item of orderItems){await client.query(`
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
          `,[order.id,item.productId,item.name,item.price,item.quantity,item.subtotal]);}await client.query('COMMIT');const amountInKobo=Math.round(total*100);const paystackPayload={email,amount:amountInKobo,currency:'NGN',reference,metadata:{order_id:String(order.id),order_reference:reference,customer_name:name,customer_phone:phone}};const callbackUrl=PAYSTACK_CALLBACK_URL||`${req.protocol}://${req.get('host')}/api/paystack/callback`;if(callbackUrl){paystackPayload.callback_url=callbackUrl;}const response=await fetch('https://api.paystack.co/transaction/initialize',{method:'POST',headers:{Authorization:`Bearer ${PAYSTACK_SECRET_KEY}`,'Content-Type':'application/json'},body:JSON.stringify(paystackPayload)});const data=await response.json();if(!response.ok||!data.status||!data.data?.authorization_url){console.error('Paystack initialize error:',data);await pool.query(`
          UPDATE orders
          SET
            payment_status = 'FAILED',
            updated_at = NOW()
          WHERE reference = $1
          `,[reference]);return res.status(502).json({ok:false,message:data.message||'Unable to initialize Paystack payment.'});}await pool.query(`
        UPDATE orders
        SET
          paystack_reference = $1,
          updated_at = NOW()
        WHERE reference = $2
        `,[data.data.reference||reference,reference]);res.json({ok:true,reference,authorization_url:data.data.authorization_url,access_code:data.data.access_code||null});}catch(error){try{await client.query('ROLLBACK');}catch{}console.error('Payment initialization error:',error);res.status(400).json({ok:false,message:error.message||'Payment initialization failed.'});}finally{client.release();}});async function completePaidOrder(reference,transaction){if(!pool){throw new Error('Database is not configured.');}const client=await pool.connect();try{await client.query('BEGIN');const orderResult=await client.query(`
        SELECT *
        FROM orders
        WHERE reference = $1
        FOR UPDATE
        `,[reference]);if(!orderResult.rowCount){throw new Error('Order not found.');}const order=orderResult.rows[0];const expectedAmount=Math.round(Number(order.total)*100);const paidAmount=Number(transaction.amount);if(transaction.status!=='success'||transaction.currency!=='NGN'||paidAmount!==expectedAmount){throw new Error('Payment amount or status does not match the order.');}if(order.payment_status!=='PAID'){const itemsResult=await client.query(`
          SELECT *
          FROM order_items
          WHERE order_id = $1
          ORDER BY id ASC
          `,[order.id]);for(const item of itemsResult.rows){const stockResult=await client.query(`
            UPDATE products
            SET
              stock =
                stock - $1,
              updated_at = NOW()
            WHERE id = $2
              AND active = TRUE
              AND stock >= $1
            RETURNING id
            `,[item.quantity,item.product_id]);if(!stockResult.rowCount){throw new Error(`Insufficient stock for ${item.product_name}.`);}}}await client.query(`
      UPDATE orders
      SET
        payment_status = 'PAID',
        order_status =
          CASE
            WHEN order_status = 'PENDING'
            THEN 'PROCESSING'
            ELSE order_status
          END,
        paystack_reference = $1,
        updated_at = NOW()
      WHERE id = $2
      `,[transaction.reference||reference,order.id]);await client.query('COMMIT');return{id:Number(order.id),reference:order.reference,total:Number(order.total),customer_name:order.customer_name};}catch(error){try{await client.query('ROLLBACK');}catch{}throw error;}finally{client.release();}}app.get('/api/paystack/verify/:reference',async(req,res)=>{if(!pool){return res.status(503).json({ok:false,message:'Database is not configured.'});}if(!PAYSTACK_SECRET_KEY){return res.status(503).json({ok:false,message:'Paystack is not configured on the server.'});}const reference=cleanString(req.params.reference,200);if(!reference){return res.status(400).json({ok:false,message:'Payment reference is required.'});}try{const response=await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,{headers:{Authorization:`Bearer ${PAYSTACK_SECRET_KEY}`}});const data=await response.json();if(!response.ok||!data.status||!data.data){return res.status(502).json({ok:false,paid:false,message:data.message||'Unable to verify payment.'});}const transaction=data.data;if(transaction.status!=='success'){await pool.query(`
          UPDATE orders
          SET
            payment_status = 'FAILED',
            updated_at = NOW()
          WHERE reference = $1
            AND payment_status <> 'PAID'
          `,[reference]);return res.status(400).json({ok:false,paid:false,message:'Payment was not successful.'});}const completed=await completePaidOrder(reference,transaction);res.json({ok:true,success:true,paid:true,verified:true,reference,order_reference:completed.reference,amount:completed.total,customer_name:completed.customer_name});}catch(error){console.error('Paystack verify error:',error);res.status(500).json({ok:false,paid:false,message:error.message||'Payment verification error.'});}});app.get('/api/paystack/callback',async(req,res)=>{const reference=cleanString(req.query?.reference,200);if(!reference){return res.redirect('/payment-failed?message=Payment%20reference%20missing');}if(!pool||!PAYSTACK_SECRET_KEY){return res.redirect(`/payment-success?reference=${encodeURIComponent(reference)}&status=pending`);}try{const response=await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,{headers:{Authorization:`Bearer ${PAYSTACK_SECRET_KEY}`}});const data=await response.json();if(response.ok&&data.status&&data.data?.status==='success'){await completePaidOrder(reference,data.data);return res.redirect(`/payment-success?reference=${encodeURIComponent(reference)}&status=success`);}if(data.data?.status==='failed'){await pool.query(`UPDATE orders
           SET payment_status='FAILED', updated_at=NOW()
           WHERE reference=$1 AND payment_status <> 'PAID'`,[reference]);return res.redirect(`/payment-failed?reference=${encodeURIComponent(reference)}`);}return res.redirect(`/payment-success?reference=${encodeURIComponent(reference)}&status=pending`);}catch(error){console.error('Paystack callback verification error:',error);return res.redirect(`/payment-success?reference=${encodeURIComponent(reference)}&status=pending`);}});app.post('/api/paystack/webhook',async(req,res)=>{if(!PAYSTACK_SECRET_KEY||!pool){return res.sendStatus(200);}const signature=String(req.headers['x-paystack-signature']||'');if(!signature||!req.rawBody){return res.sendStatus(401);}const hash=crypto.createHmac('sha512',PAYSTACK_SECRET_KEY).update(req.rawBody).digest('hex');try{const expected=Buffer.from(hash,'utf8');const received=Buffer.from(signature,'utf8');if(expected.length!==received.length||!crypto.timingSafeEqual(expected,received)){return res.sendStatus(401);}}catch{return res.sendStatus(401);}try{const event=req.body||{};if(event.event!=='charge.success'){return res.sendStatus(200);}const transaction=event.data||{};const reference=cleanString(transaction.reference,200);if(!reference){return res.sendStatus(200);}await completePaidOrder(reference,transaction);return res.sendStatus(200);}catch(error){console.error('Paystack webhook error:',error);return res.sendStatus(200);}});app.get('/api/config',(req,res)=>{res.json({ok:true,whatsapp:WHATSAPP_NUMBER,paystackConfigured:Boolean(PAYSTACK_SECRET_KEY),customerAuth:true,customerAddresses:true,customerOrders:true,paystackCallback:'/api/paystack/callback',paystackWebhook:'/api/paystack/webhook',productDetail:'/api/products/:id'});});app.get('/',(req,res)=>{res.sendFile(path.join(__dirname,'public','index.html'));});app.get('/admin',(req,res)=>{res.sendFile(path.join(__dirname,'public','admin.html'));});app.get('/payment-success',(req,res)=>{res.sendFile(path.join(__dirname,'public','payment-success.html'));});app.get('/payment-failed',(req,res)=>{const file=path.join(__dirname,'public','payment-failed.html');res.sendFile(file,error=>{if(error){res.redirect('/');}});});app.use('/api',(req,res)=>{res.status(404).json({ok:false,message:'API endpoint not found.',path:req.originalUrl});});app.use((error,req,res,next)=>{console.error('Server error:',error);if(res.headersSent){return next(error);}res.status(500).json({ok:false,message:'Internal server error.'});});async function startServer(){try{await initDatabase();app.listen(PORT,'0.0.0.0',()=>{console.log(`Face of Style Hijab Factory running on port ${PORT}`);console.log(`Paystack configured: ${Boolean(
            PAYSTACK_SECRET_KEY
          )}`);console.log(`Admin configured: ${Boolean(
            ADMIN_USERNAME &&
            ADMIN_PASSWORD
          )}`);console.log(`Database configured: ${Boolean(
            pool
          )}`);console.log('Customer authentication: ENABLED');console.log('Customer orders: ENABLED');console.log('Customer addresses: ENABLED');console.log('Public product detail: ENABLED');});}catch(error){console.error('Failed to start server:',error);process.exit(1);}}startServer();
