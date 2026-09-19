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

const PAYSTACK_SECRET_KEY =
  process.env.PAYSTACK_SECRET_KEY || '';

const ADMIN_USERNAME =
  process.env.ADMIN_USERNAME || '';

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || '';

const DATABASE_URL =
  process.env.DATABASE_URL || '';

const WHATSAPP_NUMBER =
  process.env.WHATSAPP_NUMBER || '2349065828886';

const isProduction =
  process.env.NODE_ENV === 'production';

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
    limit: '5mb',
    verify: (req, res, buf) => {
      req.rawBody = Buffer.from(buf);
    }
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '5mb'
  })
);

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

/* =========================================================
   ADMIN SESSIONS
========================================================= */

const sessions = new Map();

function createSession(username) {
  const token =
    crypto.randomBytes(32).toString('hex');

  sessions.set(token, {
    username,
    createdAt: Date.now()
  });

  return token;
}

function getSession(req) {
  const authorization =
    req.headers.authorization || '';

  if (!authorization.startsWith('Bearer ')) {
    return null;
  }

  const token =
    authorization.slice(7).trim();

  if (!token) {
    return null;
  }

  const session =
    sessions.get(token);

  if (!session) {
    return null;
  }

  const maxAge =
    1000 * 60 * 60 * 24;

  if (
    Date.now() -
      session.createdAt >
    maxAge
  ) {
    sessions.delete(token);
    return null;
  }

  return {
    token,
    ...session
