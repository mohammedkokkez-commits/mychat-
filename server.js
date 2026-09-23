'use strict';

/**
 * محادثة خاصة بين شخصين فقط.
 * كل شيء يعمل بنماذج HTML عادية (POST) بدون أي JavaScript في المتصفح،
 * عشان يشتغل حتى على متصفحات قديمة جدًا زي Safari في iPad الجيل الأول.
 */

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const app = express();

// ---------- إعدادات ----------
const PORT = process.env.PORT || 3000;
const SESSION_HOURS = 12;
const SESSION_MS = SESSION_HOURS * 60 * 60 * 1000;
const MESSAGE_TTL_MS = 24 * 60 * 60 * 1000; // الرسائل تختفي تلقائيًا بعد 24 ساعة
const REFRESH_SECONDS = 5; // كل كام ثانية تتحدث شاشة الشات تلقائيًا

// ---------- التحقق من متغيرات البيئة المطلوبة ----------
const required = ['USER1_NAME', 'USER1_PASSWORD', 'USER2_NAME', 'USER2_PASSWORD', 'COOKIE_SECRET'];
for (const key of required) {
  if (!process.env[key]) {
    console.error('متغير بيئة ناقص: ' + key);
    process.exit(1);
  }
}

// المستخدمان الوحيدان المسموح لهما بالدخول
const USERS = {};
USERS[process.env.USER1_NAME] = bcrypt.hashSync(process.env.USER1_PASSWORD, 10);
USERS[process.env.USER2_NAME] = bcrypt.hashSync(process.env.USER2_PASSWORD, 10);
const USERNAMES = Object.keys(USERS);
if (USERNAMES.length !== 2) {
  console.error('لازم اسمين مستخدمين مختلفين بالظبط (USER1_NAME وUSER2_NAME).');
  process.exit(1);
}

function otherUser(name) {
  return USERNAMES[0] === name ? USERNAMES[1] : USERNAMES[0];
}

// ---------- تخزين في الذاكرة فقط (خصوصية: لا شيء يُحفظ على القرص) ----------
const sessions = new Map(); // sid -> { user, csrf, expires }
const messages = []; // { from, text, time }
const loginNonces = new Map(); // nonce -> expires (لحماية نموذج الدخول قبل وجود جلسة)

function cleanup() {
  const now = Date.now();
  for (const [sid, s] of sessions) {
    if (s.expires < now) sessions.delete(sid);
  }
  for (const [n, exp] of loginNonces) {
    if (exp < now) loginNonces.delete(n);
  }
  while (messages.length && now - messages[0].time > MESSAGE_TTL_MS) {
    messages.shift();
  }
}
setInterval(cleanup, 60 * 1000);

function token() {
  return crypto.randomBytes(24).toString('hex');
}

function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---------- إعدادات الحماية العامة ----------
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],
      scriptSrc: ["'none'"], // لا يوجد أي جافاسكريبت في الموقع أصلًا
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(express.urlencoded({ extended: false }));
app.use('/style.css', express.static(path.join(__dirname, 'public', 'style.css')));

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'محاولات كثيرة جدًا، حاول لاحقًا.',
});

// ---------- أدوات الجلسة ----------
function getSession(req) {
  const sid = req.signedCookies.sid;
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s || s.expires < Date.now()) return null;
  return { sid, ...s };
}

function requireAuth(req, res, next) {
  const s = getSession(req);
  if (!s) return res.redirect(303, '/');
  req.session = s;
  next();
}

function noStore(res) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
}

// ---------- القالب العام للصفحة ----------
function page(title, body) {
  return (
    '<!DOCTYPE html>\n' +
    '<html lang="ar" dir="rtl">\n' +
    '<head>\n' +
    '<meta charset="UTF-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    '<meta name="robots" content="noindex, nofollow">\n' +
    '<title>' + esc(title) + '</title>\n' +
    '<link rel="stylesheet" href="/style.css">\n' +
    '</head>\n<body>\n' + body + '\n</body>\n</html>'
  );
}

// ---------- صفحة تسجيل الدخول ----------
app.get('/', (req, res) => {
  noStore(res);
  const s = getSession(req);
  if (s) return res.redirect(303, '/chat');

  const nonce = token();
  loginNonces.set(nonce, Date.now() + 10 * 60 * 1000);

  const body =
    '<section class="card">' +
    '<h1>🔒 محادثة خاصة</h1>' +
    '<p class="hint">Private Chat</p>' +
    (req.query.err ? '<p class="error">اسم المستخدم أو كلمة المرور غير صحيحة</p>' : '') +
    '<form method="POST" action="/login">' +
    '<input type="hidden" name="nonce" value="' + nonce + '">' +
    '<label for="username">اسم المستخدم</label>' +
    '<input id="username" name="username" type="text" autocapitalize="none" autocorrect="off" maxlength="64" required>' +
    '<label for="password">كلمة المرور</label>' +
    '<input id="password" name="password" type="password" maxlength="128" required>' +
    '<button type="submit">دخول</button>' +
    '</form>' +
    '</section>';

  res.send(page('محادثة خاصة', body));
});

app.post('/login', loginLimiter, (req, res) => {
  const { username, password, nonce } = req.body;

  const validNonce = nonce && loginNonces.has(nonce);
  if (validNonce) loginNonces.delete(nonce);
  if (!validNonce) return res.redirect(303, '/?err=1');

  const hash = username ? USERS[username] : null;
  const ok = hash && password && bcrypt.compareSync(password, hash);
  if (!ok) return res.redirect(303, '/?err=1');

  const sid = token();
  sessions.set(sid, {
    user: username,
    csrf: token(),
    expires: Date.now() + SESSION_MS,
  });

  res.cookie('sid', sid, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    signed: true,
    maxAge: SESSION_MS,
  });

  res.redirect(303, '/chat');
});

// ---------- شاشة المحادثة ----------
app.get('/chat', requireAuth, (req, res) => {
  noStore(res);
  cleanup();

  const me = req.session.user;
  const partner = otherUser(me);

  const rows = messages.map((m) => {
    const mine = m.from === me;
    const time = new Date(m.time).toLocaleTimeString('ar-EG', { hour: '2-digit', minute: '2-digit' });
    return (
      '<li class="' + (mine ? 'mine' : 'theirs') + '">' +
      '<span class="who">' + esc(m.from) + '</span> ' +
      '<span class="text">' + esc(m.text) + '</span> ' +
      '<span class="time">' + esc(time) + '</span>' +
      '</li>'
    );
  }).join('');

  const body =
    '<header class="chat-header">' +
    '<strong>أنت: ' + esc(me) + '</strong>' +
    '<span class="with">تتحدث مع: ' + esc(partner) + '</span>' +
    '<form method="POST" action="/logout" class="inline">' +
    '<input type="hidden" name="csrf" value="' + req.session.csrf + '">' +
    '<button type="submit" class="link-btn">خروج</button>' +
    '</form>' +
    '</header>' +
    '<ul class="messages">' + (rows || '<li class="empty">لا توجد رسائل بعد</li>') + '</ul>' +
    '<form method="POST" action="/chat/send" class="send-form">' +
    '<input type="hidden" name="csrf" value="' + req.session.csrf + '">' +
    '<input type="text" name="text" maxlength="2000" placeholder="اكتب رسالة..." required autofocus>' +
    '<button type="submit">إرسال</button>' +
    '</form>' +
    '<form method="POST" action="/chat/clear" class="clear-form">' +
    '<input type="hidden" name="csrf" value="' + req.session.csrf + '">' +
    '<button type="submit" class="link-btn danger">مسح المحادثة بالكامل</button>' +
    '</form>';

  const html = page('محادثة خاصة', body).replace(
    '<head>',
    '<head>\n<meta http-equiv="refresh" content="' + REFRESH_SECONDS + '">'
  );

  res.send(html);
});

app.post('/chat/send', requireAuth, (req, res) => {
  const { text, csrf } = req.body;
  if (csrf !== req.session.csrf) return res.status(403).send('طلب غير صالح');

  const trimmed = (text || '').trim();
  if (trimmed) {
    messages.push({ from: req.session.user, text: trimmed.slice(0, 2000), time: Date.now() });
    while (messages.length > 500) messages.shift();
  }
  res.redirect(303, '/chat');
});

app.post('/chat/clear', requireAuth, (req, res) => {
  if (req.body.csrf !== req.session.csrf) return res.status(403).send('طلب غير صالح');
  messages.length = 0;
  res.redirect(303, '/chat');
});

app.post('/logout', requireAuth, (req, res) => {
  if (req.body.csrf !== req.session.csrf) return res.status(403).send('طلب غير صالح');
  sessions.delete(req.session.sid);
  res.clearCookie('sid');
  res.redirect(303, '/');
});

app.use((req, res) => {
  res.status(404).send(page('غير موجود', '<p style="padding:2rem;text-align:center">الصفحة غير موجودة</p>'));
});

app.listen(PORT, () => {
  console.log('السيرفر شغال على البورت ' + PORT);
});
