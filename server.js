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
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const DATA = path.join(__dirname, 'data');
const ORDERS = path.join(DATA, 'orders.json');

fs.mkdirSync(DATA, { recursive: true });
if (!fs.existsSync(ORDERS)) fs.writeFileSync(ORDERS, '[]');

const PRODUCTS = [
  { id: 1, name: 'Elegant Zip Abaya', cat: 'Abaya', price: 25000 },
  { id: 2, name: 'Two-Tone Signature Gown', cat: 'Gown', price: 22000 },
  { id: 3, name: 'Teal Classic Hijab Dress', cat: 'Gown', price: 20000 },
  { id: 4, name: 'Premium Black & White', cat: 'Abaya', price: 28000 },
  { id: 5, name: 'Ruffle Hijab Collection', cat: 'Hijab', price: 12000 },
  { id: 6, name: 'Rose Signature Gown', cat: 'Custom', price: 24000 }
];

let adminSessions = new Set();

function readOrders() {
  return JSON.parse(fs.readFileSync(ORDERS, 'utf8') || '[]');
}
function writeOrders(orders) {
  const tmp = `${ORDERS}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(orders, null, 2));
  fs.renameSync(tmp, ORDERS);
}
function ref() {
  return `FS-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`.toUpperCase();
}
function adminAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!adminSessions.has(token)) return res.status(401).json({ message: 'Unauthorized' });
  next();
}
function calculateOrder(items) {
  if (!Array.isArray(items) || !items.length) return null;
  let total = 0;
  const clean = [];
  for (const item of items) {
    const p = PRODUCTS.find(x => x.id === Number(item.id));
    const qty = Math.floor(Number(item.qty));
    if (!p || !Number.isInteger(qty) || qty < 1 || qty > 99) return null;
    total += p.price * qty;
    clean.push({ id: p.id, name: p.name, price: p.price, qty });
  }
  return { items: clean, total };
}

// Keep rawBody for secure Paystack webhook signature verification.
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use(express.static(__dirname));

app.post('/api/admin/login', (req, res) => {
  const user = String(req.body?.username || '');
  const pass = String(req.body?.password || '');
  const expectedUser = process.env.ADMIN_USER;
  const expectedPass = process.env.ADMIN_PASSWORD;
  if (!expectedUser || !expectedPass) {
    return res.status(503).json({ message: 'Admin credentials are not configured on the server.' });
  }
  if (user !== expectedUser || pass !== expectedPass) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.add(token);
  res.json({ token });
});

app.get('/api/admin/dashboard', adminAuth, (req, res) => {
  const orders = readOrders();
  res.json({
    stats: {
      orders: orders.length,
      paid: orders.filter(x => x.status === 'paid').length,
      pending: orders.filter(x => x.status === 'pending').length,
      revenue: orders.filter(x => x.status === 'paid').reduce((a, x) => a + Number(x.total), 0)
    }
  });
});
app.get('/api/admin/orders', adminAuth, (req, res) => {
  res.json({ orders: readOrders().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)) });
});
app.get('/api/admin/orders/:id', adminAuth, (req, res) => {
  const order = readOrders().find(x => x.id === req.params.id);
  order ? res.json({ order }) : res.status(404).json({ message: 'Order not found' });
});
app.get('/api/admin/products', adminAuth, (req, res) => res.json({ products: PRODUCTS }));
app.get('/api/admin/settings', adminAuth, (req, res) => res.json({
  paystackConfigured: Boolean(process.env.PAYSTACK_SECRET_KEY),
  whatsapp: '09065828886'
}));

app.post('/api/paystack/initialize', async (req, res) => {
  try {
    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(500).json({ message: 'Paystack is not configured. Add PAYSTACK_SECRET_KEY on the server.' });
    }
    const customer = req.body?.customer;
    const calculated = calculateOrder(req.body?.items);
    if (!customer?.name || !customer?.email || !customer?.phone || !customer?.address || !calculated) {
      return res.status(400).json({ message: 'Incomplete order details.' });
    }

    const id = crypto.randomUUID();
    const reference = ref();
    const order = {
      id,
      reference,
      status: 'pending',
      customer: {
        name: String(customer.name).slice(0, 120),
        email: String(customer.email).slice(0, 200),
        phone: String(customer.phone).slice(0, 40),
        address: String(customer.address).slice(0, 500)
      },
      items: calculated.items,
      total: calculated.total,
      payment: { provider: 'paystack', reference },
      createdAt: new Date().toISOString()
    };

    const orders = readOrders();
    orders.push(order);
    writeOrders(orders);

    const r = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: order.customer.email,
        amount: calculated.total * 100,
        currency: 'NGN',
        reference,
        callback_url: `${BASE_URL}/payment-success.html`,
        metadata: { order_id: id }
      })
    });

    const data = await r.json();
    if (!r.ok || !data.status) {
      order.status = 'failed';
      order.payment.error = data.message || 'Paystack initialization failed';
      writeOrders(orders);
      return res.status(400).json({ message: data.message || 'Paystack initialization failed.' });
    }
    res.json({ authorization_url: data.data.authorization_url, reference });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Payment service error.' });
  }
});

app.get('/api/paystack/verify/:reference', async (req, res) => {
  try {
    if (!process.env.PAYSTACK_SECRET_KEY) return res.status(500).json({ message: 'Paystack is not configured.' });
    const reference = req.params.reference;
    const orders = readOrders();
    const order = orders.find(x => x.reference === reference);
    if (!order) return res.status(404).json({ message: 'Order not found.' });

    const r = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
    });
    const data = await r.json();
    const tx = data.data;
    const expected = order.total * 100;

    if (data.status && tx?.status === 'success' && Number(tx.amount) === expected && tx.currency === 'NGN') {
      order.status = 'paid';
      order.payment.verifiedAt = new Date().toISOString();
      order.payment.channel = tx.channel;
      order.payment.paidAt = tx.paid_at;
      writeOrders(orders);
      return res.json({ success: true, reference });
    }

    order.status = tx?.status === 'failed' ? 'failed' : 'pending';
    writeOrders(orders);
    res.json({ success: false, message: 'Payment has not been verified as successful.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Verification error.' });
  }
});

app.post('/api/paystack/webhook', (req, res) => {
  try {
    const signature = req.headers['x-paystack-signature'];
    if (!signature || !process.env.PAYSTACK_SECRET_KEY || !req.rawBody) return res.sendStatus(401);
    const expected = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY).update(req.rawBody).digest('hex');
    const a = Buffer.from(String(signature));
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.sendStatus(401);

    const event = req.body;
    if (event?.event === 'charge.success') {
      const tx = event.data;
      const orders = readOrders();
      const order = orders.find(x => x.reference === tx.reference);
      if (order && Number(tx.amount) === order.total * 100 && tx.currency === 'NGN') {
        order.status = 'paid';
        order.payment.verifiedAt = new Date().toISOString();
        order.payment.channel = tx.channel;
        order.payment.paidAt = tx.paid_at;
        writeOrders(orders);
      }
    }
    res.sendStatus(200);
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true, paystackConfigured: Boolean(process.env.PAYSTACK_SECRET_KEY) }));

app.listen(PORT, () => console.log(`Face of Style store running at ${BASE_URL}`));
