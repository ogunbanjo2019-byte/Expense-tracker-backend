# Expense Tracker Backend

This package contains the backend only for the supplied Expense Tracker frontend. It exposes the `/api` routes already used by `script.js` and `reset.js`.

## Stack

The service uses Node.js, Express, MongoDB through Mongoose, JSON Web Tokens for authentication, bcrypt for password hashing, and Nodemailer for optional password-reset email delivery.

## Setup

Install Node.js 18 or newer and make sure MongoDB is available locally or through a hosted MongoDB connection string. Then run:

```bash
npm install
cp .env.example .env
npm run dev
```

The API starts on `http://localhost:5000` by default. Check `GET /api/health` to verify that the process is running.

For a production deployment, set a strong `JWT_SECRET`, a hosted `MONGODB_URI`, the deployed frontend URL in `CLIENT_ORIGIN`, and SMTP variables if password-reset email should be sent rather than printed to the server console.

## Frontend connection

Update the `BASE_URL` constant in the frontend `script.js` file from the old Render URL to the deployed backend URL, for example:

```js
const BASE_URL = "https://your-backend-domain.example/api";
```

The reset page uses the same backend host for `POST /api/auth/reset-password/:token`. Set `RESET_URL` to the public URL of the frontend reset page.

## API contract

| Method | Route | Authentication | Purpose |
|---|---|---:|---|
| GET | `/api/health` | No | Health check |
| POST | `/api/auth/signup` | No | Create an account with `name`, `email`, and `password` |
| POST | `/api/auth/login` | No | Authenticate with `email` and `password`; returns `{ token, user }` |
| POST | `/api/auth/forgot-password` | No | Request a reset link with `email` |
| POST | `/api/auth/reset-password/:token` | No | Set a new password with `password` |
| GET | `/api/expenses` | Bearer token | List the signed-in user's expenses |
| POST | `/api/expenses` | Bearer token | Create an expense with `description`, `amount`, and `category` |
| DELETE | `/api/expenses/:id` | Bearer token | Delete one expense belonging to the signed-in user |

Expense responses include `_id`, `description`, `amount`, `category`, `user`, `createdAt`, and `updatedAt`, which matches the frontend's use of `exp._id`, `exp.description`, and `exp.amount`.

## Password reset behavior

When SMTP is not configured, the reset link is printed to the server console for development. When SMTP is configured, the link is sent by email. Reset tokens are stored only as SHA-256 hashes and expire after the configured `RESET_TOKEN_TTL_MINUTES` value.

## Security notes

Passwords are never stored in plaintext. Expense queries are scoped to the authenticated user's ID, so one user cannot list or delete another user's expenses. Before production use, configure HTTPS at the hosting layer, a strong secret, a restricted `CLIENT_ORIGIN`, and a managed MongoDB instance with appropriate access controls.
