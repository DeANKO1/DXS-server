require('dotenv').config();
const express = require('express');
const cors = require('cors');
const TelegramBot = require('node-telegram-bot-api');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const { parsePhoneNumber } = require('libphonenumber-js');
const { v4: uuidv4 } = require('uuid');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const crypto = require('crypto');
const https = require('https');

const app = express();

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'https://destrkod.github.io');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

app.use(express.json());

const {
  PORT = 3000,
  BOT_TOKEN,
  JWT_SECRET,
  SHOP_ID,
  BILEE_PASSWORD,
  FRONTEND_URL = 'https://destrkod.github.io/dxsvpn',
  BILEE_NOTIFY_IP = '147.45.247.34',
} = process.env;

if (!BOT_TOKEN || !JWT_SECRET || !SHOP_ID || !BILEE_PASSWORD) {
  console.error('Отсутствуют обязательные переменные в .env');
  process.exit(1);
}

const users = new Map();
const pendingRegistrations = new Map();
const otpCodes = new Map();

const codeLimiter = new RateLimiterMemory({
  keyPrefix: 'code',
  points: 3,
  duration: 600,
  blockDuration: 300,
});

const bot = new TelegramBot(BOT_TOKEN, { polling: true });

function keepAlive() {
  const options = {
    hostname: 'dxs-server.onrender.com',
    port: 443,
    path: '/health',
    method: 'GET',
    headers: {
      'User-Agent': 'Keep-Alive-Service'
    }
  };

  const req = https.request(options, (res) => {
    console.log(`[${new Date().toISOString()}] Keep-alive ping status: ${res.statusCode}`);
  });

  req.on('error', (error) => {
    console.error(`[${new Date().toISOString()}] Keep-alive error:`, error.message);
  });

  req.end();
}

setInterval(keepAlive, 5 * 60 * 1000);

bot.onText(/\/start reg_(.+)/, (msg, match) => {
  const token = match[1];
  const chatId = msg.chat.id;

  const pending = pendingRegistrations.get(token);
  if (!pending || pending.expiresAt < Date.now()) {
    bot.sendMessage(chatId, 'Ссылка недействительна или устарела. Начните регистрацию заново на сайте.');
    return;
  }

  pending.chatId = chatId;

  bot.sendMessage(chatId, `Привет, ${pending.first_name}! Поделитесь своим номером телефона, чтобы мы убедились, что это вы.`, {
    reply_markup: {
      keyboard: [[{ text: 'Поделиться номером', request_contact: true }]],
      one_time_keyboard: true,
      resize_keyboard: true,
    },
  });
});

bot.on('contact', async (msg) => {
  const chatId = msg.chat.id;
  const contact = msg.contact;
  const phoneFromTg = contact.phone_number.startsWith('+') ? contact.phone_number : `+${contact.phone_number}`;

  let foundToken = null;
  for (const [token, data] of pendingRegistrations) {
    if (data.chatId === chatId) {
      foundToken = token;
      break;
    }
  }

  if (!foundToken) {
    bot.sendMessage(chatId, 'Активная регистрация не найдена. Начните заново на сайте.');
    return;
  }

  const pending = pendingRegistrations.get(foundToken);
  let normalizedTgPhone;
  try {
    normalizedTgPhone = normalizePhone(phoneFromTg);
  } catch {
    bot.sendMessage(chatId, 'Не удалось распознать номер. Попробуйте снова.');
    return;
  }

  if (normalizedTgPhone !== pending.phone) {
    bot.sendMessage(chatId, 'Номер телефона не совпадает с указанным на сайте. Попробуйте заново.');
    return;
  }

  const passwordHash = await argon2.hash(pending.password);
  users.set(pending.phone, {
    telegram_id: msg.from.id,
    first_name: pending.first_name,
    phone: pending.phone,
    password_hash: passwordHash,
    created_at: new Date().toISOString(),
    telegram_confirmed: true
  });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  otpCodes.set(pending.phone, {
    code,
    expiresAt: Date.now() + 5 * 60 * 1000,
    attempts: 0,
  });

  bot.sendMessage(chatId, `Всё совпало! Ваш код подтверждения: *${code}*\n\nВернитесь на сайт и введите его.`, {
    parse_mode: 'Markdown',
    reply_markup: {
      inline_keyboard: [[{ text: 'Вернуться на сайт и ввести код', url: `${FRONTEND_URL}/registration.html?token=${foundToken}&stage=verify` }]],
    },
  });

  pendingRegistrations.delete(foundToken);
});

function normalizePhone(input) {
  try {
    let phone = parsePhoneNumber(input, 'RU');
    if (!phone || !phone.isValid()) phone = parsePhoneNumber(input);
    if (!phone || !phone.isValid()) throw new Error();
    return phone.format('E.164');
  } catch {
    throw new Error('Неверный формат номера телефона');
  }
}

function generateSignature(data, password) {
  const tokenData = { ...data, password };
  const excluded = ['metadata', 'signature'];
  const sortedValues = Object.keys(tokenData)
    .filter(key => !excluded.includes(key))
    .sort()
    .map(key => tokenData[key])
    .join('');

  return crypto.createHash('sha256').update(sortedValues).digest('hex');
}

app.post('/api/register/start', async (req, res) => {
  const { first_name, phone, password, password_confirm } = req.body;

  if (!first_name || !phone || !password || password !== password_confirm) {
    return res.status(400).json({ error: 'Заполните все поля или пароли не совпадают' });
  }

  let normalized;
  try {
    normalized = normalizePhone(phone);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  if (users.has(normalized)) {
    return res.status(409).json({ error: 'Номер уже зарегистрирован' });
  }

  const token = uuidv4();
  pendingRegistrations.set(token, {
    first_name,
    phone: normalized,
    password,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000,
    chatId: null,
  });

  const botLink = `https://t.me/dxsconnection_bot?start=reg_${token}`;

  res.json({ success: true, botLink, token });
});

app.post('/api/register/verify', async (req, res) => {
  const { token, code } = req.body;

  const pending = pendingRegistrations.get(token);
  if (!pending || pending.expiresAt < Date.now()) {
    return res.status(410).json({ error: 'Регистрация устарела' });
  }

  const stored = otpCodes.get(pending.phone);
  if (!stored || stored.expiresAt < Date.now()) {
    return res.status(410).json({ error: 'Код устарел' });
  }

  if (stored.attempts >= 3) {
    return res.status(429).json({ error: 'Слишком много попыток' });
  }

  stored.attempts++;

  if (stored.code !== code) {
    return res.status(400).json({ error: 'Неверный код', attemptsLeft: 3 - stored.attempts });
  }

  const user = users.get(pending.phone);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }

  pendingRegistrations.delete(token);
  otpCodes.delete(pending.phone);

  const accessToken = jwt.sign({ phone: pending.phone }, JWT_SECRET, { expiresIn: '1h' });
  const refreshToken = jwt.sign({ phone: pending.phone }, JWT_SECRET, { expiresIn: '30d' });

  res.json({ success: true, accessToken, refreshToken });
});

app.post('/api/register/check', (req, res) => {
  const { phone } = req.body;

  let normalized;
  try {
    normalized = normalizePhone(phone);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const user = users.get(normalized);
  
  res.json({ 
    confirmed: !!(user && user.telegram_confirmed === true)
  });
});

app.post('/api/login', async (req, res) => {
  const { phone, password } = req.body;

  let normalized;
  try {
    normalized = normalizePhone(phone);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const user = users.get(normalized);
  if (!user) {
    return res.status(401).json({ error: 'Пользователь не найден' });
  }

  const match = await argon2.verify(user.password_hash, password);
  if (!match) {
    return res.status(401).json({ error: 'Неверный пароль' });
  }

  if (!user.telegram_id) {
    return res.status(403).json({ error: 'Telegram аккаунт не привязан' });
  }

  try {
    await codeLimiter.consume(normalized);
  } catch {
    return res.status(429).json({ error: 'Слишком много запросов' });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  otpCodes.set(normalized, {
    code,
    expiresAt: Date.now() + 5 * 60 * 1000,
    attempts: 0,
  });

  bot.sendMessage(user.telegram_id, `Код для входа: *${code}*`, { parse_mode: 'Markdown' });

  res.json({ success: true, message: 'Код отправлен в Telegram' });
});

app.post('/api/login/verify', (req, res) => {
  const { phone, code } = req.body;

  let normalized;
  try {
    normalized = normalizePhone(phone);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const stored = otpCodes.get(normalized);
  if (!stored || stored.expiresAt < Date.now()) {
    return res.status(410).json({ error: 'Код устарел' });
  }

  if (stored.attempts >= 3) {
    return res.status(429).json({ error: 'Слишком много попыток' });
  }

  stored.attempts++;

  if (stored.code !== code) {
    return res.status(400).json({ error: 'Неверный код', attemptsLeft: 3 - stored.attempts });
  }

  otpCodes.delete(normalized);

  const accessToken = jwt.sign({ phone: normalized }, JWT_SECRET, { expiresIn: '1h' });
  const refreshToken = jwt.sign({ phone: normalized }, JWT_SECRET, { expiresIn: '30d' });

  res.json({ success: true, accessToken, refreshToken });
});

app.get('/api/verify-token', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Токен не предоставлен' });
  }
  
  const token = authHeader.split(' ')[1];
  try {
    jwt.verify(token, JWT_SECRET);
    res.json({ valid: true });
  } catch {
    res.status(401).json({ valid: false, error: 'Недействительный токен' });
  }
});

app.post('/api/token/refresh', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Токен не предоставлен' });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    const user = users.get(decoded.phone);

    if (!user) {
      return res.status(401).json({ error: 'Пользователь не найден' });
    }

    const newAccessToken = jwt.sign({ phone: decoded.phone }, JWT_SECRET, { expiresIn: '1h' });
    const newRefreshToken = jwt.sign({ phone: decoded.phone }, JWT_SECRET, { expiresIn: '30d' });

    res.json({ success: true, accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    return res.status(401).json({ error: 'Недействительный токен' });
  }
});

app.post('/api/payment/create', async (req, res) => {
  const { amount, order_id = uuidv4().slice(0, 36) } = req.body;

  if (!amount || amount < 10 || amount > 10000) {
    return res.status(400).json({ error: 'Сумма от 10 до 10000 ₽' });
  }

  const payload = {
    order_id,
    method_slug: 'card',
    amount,
    shop_id: Number(SHOP_ID),
    success_url: `${FRONTEND_URL}/main.html?paid=1`,
    notify_url: `${req.protocol}://${req.get('host')}/api/notify`,
  };

  try {
    payload.signature = generateSignature(payload, BILEE_PASSWORD);

    const response = await fetch('https://paymentgate.bilee.ru/api/payment/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (data.success && data.url) {
      res.json({ success: true, url: data.url, order_id });
    } else {
      res.status(500).json({ error: data.error || 'Ошибка Bilee' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Ошибка соединения' });
  }
});

app.post('/api/notify', (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress;
  if (clientIp !== BILEE_NOTIFY_IP) {
    return res.sendStatus(403);
  }

  const body = req.body;
  const receivedSignature = body.signature;

  if (!receivedSignature) return res.sendStatus(400);

  const computed = generateSignature({ ...body, signature: undefined }, BILEE_PASSWORD);

  if (computed !== receivedSignature) {
    return res.sendStatus(401);
  }

  if (body.status !== 'confirmed') {
    return res.sendStatus(200);
  }

  console.log(`Успешный платёж: order_id=${body.order_id}, amount=${body.amount}`);

  res.sendStatus(200);
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    stats: {
      users: users.size,
      pending: pendingRegistrations.size,
      otp: otpCodes.size
    }
  });
});

app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
  console.log(`Ссылка: https://dxs-server.onrender.com`);
  console.log(`Keep-alive активирован (каждые 5 минут)`);
});
