FACE OF STYLE HIJAB FACTORY — PAYSTACK + ADMIN
================================================

The store is already wired for a server-side Paystack checkout flow:
1. Customer submits cart + customer details.
2. Server calculates the real order total from the product catalogue.
3. Server initializes Paystack using PAYSTACK_SECRET_KEY.
4. Customer completes checkout on Paystack.
5. Callback verification checks status, amount and currency.
6. Paystack webhook can also mark a verified charge as PAID.
7. Admin Dashboard reads orders/revenue from the server.

IMPORTANT
---------
The public key you shared is not needed for this redirect-based checkout flow.
Do NOT put the Paystack secret key in the browser or send it in chat.

TEST SETUP
----------
1. Copy .env.example to .env
2. Put your Paystack TEST SECRET KEY in PAYSTACK_SECRET_KEY
3. Choose ADMIN_USER and a strong ADMIN_PASSWORD
4. Set BASE_URL to the URL where this Node app is reachable
5. Run:
   npm install
   npm start
6. Open:
   http://localhost:3000
7. Admin:
   http://localhost:3000/admin.html

WEBHOOK
-------
After deploying to a public HTTPS domain, configure this webhook in Paystack:
https://YOUR-DOMAIN.COM/api/paystack/webhook

LIVE
----
Only after test payments work:
- complete Paystack compliance/activation
- switch to LIVE credentials
- set PAYSTACK_SECRET_KEY to your live secret key
- keep HTTPS enabled
- test a small real transaction

SECURITY
--------
- Secret key stays server-side.
- Order totals are recalculated on the server; the browser cannot choose the payment amount.
- Payment verification checks successful status, exact amount and NGN currency.
- Webhook requests are checked with Paystack's x-paystack-signature.
- Change admin credentials before deployment.

PRODUCT IMAGES
--------------
The assets folder contains the current Face of Style product images and logo.
