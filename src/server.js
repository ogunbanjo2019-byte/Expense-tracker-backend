require('dotenv').config();

const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
const PORT = Number(process.env.PORT || 5000);
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/expense_tracker';
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-development-secret';
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || '*';
const RESET_TOKEN_TTL_MINUTES = Number(process.env.RESET_TOKEN_TTL_MINUTES || 30);

if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'change-this-development-secret') {
  throw new Error('JWT_SECRET must be configured in production.');
}

app.use(cors({ origin: CLIENT_ORIGIN === '*' ? true : CLIENT_ORIGIN }));
app.use(express.json({ limit: '1mb' }));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, minlength: 2, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  passwordHash: { type: String, required: true },
  resetPasswordTokenHash: { type: String, default: null },
  resetPasswordExpiresAt: { type: Date, default: null }
}, { timestamps: true });

const expenseSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  description: { type: String, required: true, trim: true, maxlength: 200 },
  amount: { type: Number, required: true, min: 0.01 },
  category: { type: String, required: true, trim: true, maxlength: 50, default: 'Other' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Expense = mongoose.model('Expense', expenseSchema);

function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function isEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function publicUser(user) {
  return { id: user._id.toString(), name: user.name, email: user.email };
}

function issueAuthToken(user) {
  return jwt.sign({ sub: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
}

function hashResetToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function authRequired(req, res, next) {
  const header = req.get('authorization') || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ message: 'Authentication required.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

async function sendResetEmail(user, resetToken) {
  const resetUrl = `${process.env.RESET_URL || 'http://localhost:5500/reset.html'}?token=${encodeURIComponent(resetToken)}`;
  if (!process.env.SMTP_HOST) {
    console.log(`[password-reset] ${user.email}: ${resetUrl}`);
    return;
  }
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } : undefined
  });
  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: user.email,
    subject: 'Reset your Expense Tracker password',
    text: `Use this link to reset your password: ${resetUrl}`,
    html: `<p>Use this link to reset your password:</p><p><a href="${resetUrl}">${resetUrl}</a></p>`
  });
}

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'expense-tracker-backend' }));

app.post('/api/auth/signup', asyncRoute(async (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  const email = normalizeEmail(req.body.email);
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (name.length < 2) return res.status(400).json({ message: 'Name must be at least 2 characters.' });
  if (!isEmail(email)) return res.status(400).json({ message: 'Please provide a valid email.' });
  if (password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters.' });
  if (await User.exists({ email })) return res.status(409).json({ message: 'An account with this email already exists.' });
  const user = await User.create({ name, email, passwordHash: await bcrypt.hash(password, 12) });
  res.status(201).json({ message: 'Signup successful', user: publicUser(user) });
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ message: 'Invalid email or password.' });
  res.json({ token: issueAuthToken(user), user: publicUser(user) });
}));

app.post('/api/auth/forgot-password', asyncRoute(async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const user = await User.findOne({ email });
  if (user) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordTokenHash = hashResetToken(rawToken);
    user.resetPasswordExpiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MINUTES * 60 * 1000);
    await user.save();
    await sendResetEmail(user, rawToken);
  }
  res.json({ message: 'If an account exists for that email, a reset link has been sent.' });
}));

app.post('/api/auth/reset-password/:token', asyncRoute(async (req, res) => {
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters.' });
  const user = await User.findOne({ resetPasswordTokenHash: hashResetToken(req.params.token), resetPasswordExpiresAt: { $gt: new Date() } });
  if (!user) return res.status(400).json({ message: 'Invalid or expired reset token.' });
  user.passwordHash = await bcrypt.hash(password, 12);
  user.resetPasswordTokenHash = null;
  user.resetPasswordExpiresAt = null;
  await user.save();
  res.json({ message: 'Password reset successful.' });
}));

app.get('/api/expenses', authRequired, asyncRoute(async (req, res) => {
  const expenses = await Expense.find({ user: req.userId }).sort({ createdAt: -1 }).lean();
  res.json(expenses);
}));

app.post('/api/expenses', authRequired, asyncRoute(async (req, res) => {
  const description = typeof req.body.description === 'string' ? req.body.description.trim() : '';
  const amount = Number(req.body.amount);
  const category = typeof req.body.category === 'string' && req.body.category.trim() ? req.body.category.trim() : 'Other';
  if (!description) return res.status(400).json({ message: 'Description is required.' });
  if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ message: 'Amount must be a positive number.' });
  const expense = await Expense.create({ user: req.userId, description, amount, category });
  res.status(201).json(expense);
}));

app.delete('/api/expenses/:id', authRequired, asyncRoute(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid expense ID.' });
  const deleted = await Expense.findOneAndDelete({ _id: req.params.id, user: req.userId });
  if (!deleted) return res.status(404).json({ message: 'Expense not found.' });
  res.json({ message: 'Expense deleted successfully.' });
}));

app.use((req, res) => res.status(404).json({ message: 'Route not found.' }));
app.use((err, req, res, next) => {
  console.error(err);
  if (err instanceof mongoose.Error.ValidationError) return res.status(400).json({ message: 'Invalid request data.' });
  if (err.code === 11000) return res.status(409).json({ message: 'An account with this email already exists.' });
  res.status(500).json({ message: 'Internal server error.' });
});

async function start() {
  await mongoose.connect(MONGODB_URI);
  app.listen(PORT, () => console.log(`Expense Tracker API listening on port ${PORT}`));
}

if (require.main === module) start().catch((error) => { console.error('Unable to start server:', error.message); process.exit(1); });

module.exports = { app, User, Expense };
