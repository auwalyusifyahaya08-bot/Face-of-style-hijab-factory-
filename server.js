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
const ORDERS = path.join(DATA, 'orders.json');
const PRODUCTS_FILE = path.join(DATA, 'products.json');

fs.mkdirSync(DATA, { recursive: true });

if (!fs.existsSync(ORDERS)) {
  fs.writeFileSync(ORDERS, '[]');
}

const PRODUCTS = [
  {
    id: 1,
    name: 'Elegant Zip Abaya',
    cat: 'Abaya',
    price: 25000,
    image: '/assets/product-1.jpg',
    desc: 'Flowing full-length abaya with refined finishing.',
    color: '',
    stock: 99
  },
  {
    id: 2,
    name: 'Two-Tone Signature Gown',
    cat: 'Gown',
    price: 22000,
    image: '/assets/product-2.jpg',
    desc: 'Elegant two-tone modest gown design.',
    color: '',
    stock: 99
  },
  {
    id: 3,
    name: 'Teal Classic Hijab Dress',
    cat: 'Gown',
    price: 20000,
    image: '/assets/product-3.jpg',
    desc: 'Comfortable modest dress with clean detailing.',
    color: '',
    stock: 99
  },
  {
    id: 4,
    name: 'Premium Black & White',
    cat: 'Abaya',
    price: 28000,
    image: '/assets/product-4.jpg',
    desc: 'Statement modest outfit with premium contrast.',
    color: '',
    stock: 99
  },
  {
    id: 5,
    name: 'Ruffle Hijab Collection',
    cat: 'Hijab',
    price: 12000,
    image: '/assets/product-5.jpg',
    desc: 'Soft, colourful hijab styles with beautiful ruffles.',
    color: '',
    stock: 99
  },
  {
    id: 6,
    name: 'Rose Signature Gown',
    cat: 'Custom',
    price: 24000,
    image: '/assets/product-6.jpg',
    desc: 'Elegant flowing gown; custom colours available.',
    color: '',
    stock: 99
  }
];

if (!fs.existsSync(PRODUCTS_FILE)) {
  fs.writeFileSync(
    PRODUCTS_FILE,
    JSON.stringify(PRODUCTS, null, 2)
  );
}

function readProducts() {
  try {
    const data = fs.readFileSync(
      PRODUCTS_FILE,
      'utf8'
    );

    const products =
      JSON.parse(data || '[]');

    return Array.isArray(products)
      ? products.map(normalizeProduct)
      : [];
  } catch (error) {
    console.error(
      'Products read error:',
      error
    );

    return [];
  }
}

function normalizeProduct(product) {
  const image =
    product?.image ||
    product?.img ||
    '';

  return {
    id: Number(product?.id),
    name: String(
      product?.name || 'Product'
    ),
    cat: String(
      product?.cat ||
      product?.category ||
      'Fashion'
    ),
    price: Number(product?.price) || 0,
    image: normalizeImage(image),
    img: normalizeImage(image),
    color: String(
      product?.color || ''
    ),
    desc
