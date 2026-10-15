
import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const app = express();

// Trust reverse proxy (Render, Cloudflare, etc.)
app.set('trust proxy', 1);

// Configure CORS
const allowedOrigin = process.env.APP_URL && process.env.APP_URL.trim() ? process.env.APP_URL.trim() : '*';
app.use(
  cors({
    origin: allowedOrigin === '*' ? true : allowedOrigin,
    credentials: true,
  })
);

// Body parser
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Global rate limiting: 120 req/min
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please wait a minute and try again.' },
});
app.use('/api/', globalLimiter);

// -------------------------------------------------------------
// 1. Supabase Client
// -------------------------------------------------------------
const supabaseUrl = process.env.SUPABASE_URL || 'https://gcghayucdllhrbzvjbew.supabase.co';
const supabaseKey = process.env.SUPABASE_SERVICE_KEY || 'placeholder_service_key';
const JWT_SECRET = process.env.JWT_SECRET || 'hrs_ai_super_secret_jwt_key_2026_bd_9988776655';

export const supabase = createClient(supabaseUrl, supabaseKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});

// -------------------------------------------------------------
// 2. Auth Middleware
// -------------------------------------------------------------
async function auth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authentication required. Bearer token missing.' });
    }
    const token = authHeader.split(' ')[1];
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (jwtErr) {
      return res.status(401).json({ error: 'Session expired or invalid token.' });
    }

    const userId = decoded.id || decoded.userId;
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, name, role, credits, is_banned, created_at')
      .eq('id', userId)
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({ error: 'User not found. Please log in again.' });
    }
    if (user.is_banned) {
      return res.status(403).json({ error: 'Your account has been suspended.' });
    }
    req.user = user;
    next();
  } catch (err) {
    return res.status(500).json({ error: 'Internal auth error.' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Admin access required.' });
  }
  next();
}

// -------------------------------------------------------------
// 3. Health Endpoint
// -------------------------------------------------------------
app.get('/api/health', (req, res) => {
  return res.json({
    ok: true,
    service: 'HRS AI Chat',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    nodeVersion: process.version,
  });
});

// -------------------------------------------------------------
// 4. Auth Routes (/api/auth)
// -------------------------------------------------------------
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: 'Valid email and password (min 6 chars) required.' });
    }
    const cleanEmail = email.trim().toLowerCase();
    const cleanName = (name && typeof name === 'string' ? name.trim() : '') || cleanEmail.split('@')[0];

    const { data: existing } = await supabase.from('users').select('id').eq('email', cleanEmail).maybeSingle();
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const { data: newUser, error } = await supabase
      .from('users')
      .insert({
        email: cleanEmail,
        password_hash,
        name: cleanName,
        role: 'user',
        credits: 100,
        is_banned: false,
      })
      .select('id, email, name, role, credits, created_at')
      .single();

    if (error || !newUser) {
      console.error('[SIGNUP ERROR]', error);
      return res.status(500).json({ error: 'Failed to create user.' });
    }

    const token = jwt.sign({ id: newUser.id, email: newUser.email, role: newUser.role }, JWT_SECRET, { expiresIn: '7d' });
    return res.status(201).json({ token, user: newUser });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required.' });
    }
    const cleanEmail = email.trim().toLowerCase();
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, password_hash, name, role, credits, is_banned, created_at')
      .eq('email', cleanEmail)
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    if (user.is_banned) {
      return res.status(403).json({ error: 'Account suspended.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    const { password_hash, ...safeUser } = user;
    return res.json({ token, user: safeUser });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', auth, (req, res) => {
  return res.json({ user: req.user });
});

// -------------------------------------------------------------
// 5. Chat Routes (/api/chat)
// -------------------------------------------------------------
const DEFAULT_MODELS = [
  { id: 'llama-3.3-70b', name: 'Llama 3.3 70B (Default)' },
  { id: 'llama-3.1-405b', name: 'Llama 3.1 405B' },
  { id: 'mistral-31-24b', name: 'Mistral 3.1 24B' },
  { id: 'qwen-2.5-coder-32b', name: 'Qwen 2.5 Coder 32B' },
  { id: 'deepseek-r1-llama-70b', name: 'DeepSeek R1 Distill 70B' },
];

app.get('/api/chat/models', auth, async (req, res) => {
  const apiKey = process.env.VENICE_API_KEY;
  if (!apiKey || apiKey === 'YOUR_ACTUAL_VENICE_API_KEY') {
    return res.json({ models: DEFAULT_MODELS });
  }
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch('https://api.venice.ai/api/v1/models', {
      headers: { Authorization: `Bearer ${apiKey}` },
      signal: controller.signal,
    });
    clearTimeout(t);
    if (resp.ok) {
      const data = await resp.json();
      if (Array.isArray(data.data)) {
        return res.json({ models: data.data.map((m) => ({ id: m.id, name: m.id })) });
      }
    }
  } catch (e) {}
  return res.json({ models: DEFAULT_MODELS });
});

app.get('/api/chat/history', auth, async (req, res) => {
  try {
    const { data: chats } = await supabase
      .from('chats')
      .select('id, title, created_at')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    return res.json({ chats: chats || [] });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch history.' });
  }
});

app.get('/api/chat/:chatId', auth, async (req, res) => {
  try {
    const { data: chat } = await supabase.from('chats').select('id, title, user_id').eq('id', req.params.chatId).maybeSingle();
    if (!chat || (chat.user_id !== req.user.id && req.user.role !== 'admin')) {
      return res.status(404).json({ error: 'Chat not found.' });
    }
    const { data: messages } = await supabase
      .from('messages')
      .select('id, role, content, model, created_at')
      .eq('chat_id', req.params.chatId)
      .order('created_at', { ascending: true });
    return res.json({ chat, messages: messages || [] });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to load chat.' });
  }
});

app.delete('/api/chat/:chatId', auth, async (req, res) => {
  try {
    await supabase.from('chats').delete().eq('id', req.params.chatId).eq('user_id', req.user.id);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete chat.' });
  }
});

app.post('/api/chat', auth, async (req, res) => {
  try {
    let { chatId, message, model } = req.body;
    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Message cannot be empty.' });
    }
    const trimmedMsg = message.trim();
    const selectedModel = model || 'llama-3.3-70b';

    if (req.user.credits <= 0) {
      return res.status(403).json({ error: 'Insufficient credits. Contact admin for credits.' });
    }

    if (!chatId) {
      const title = trimmedMsg.length > 40 ? trimmedMsg.slice(0, 40) + '...' : trimmedMsg;
      const { data: newChat } = await supabase.from('chats').insert({ user_id: req.user.id, title }).select().single();
      chatId = newChat.id;
    }

    await supabase.from('messages').insert({
      chat_id: chatId,
      role: 'user',
      content: trimmedMsg,
      model: selectedModel,
    });

    const { data: history } = await supabase
      .from('messages')
      .select('role, content')
      .eq('chat_id', chatId)
      .order('created_at', { ascending: true })
      .limit(30);

    const payload = history && history.length > 0
      ? history.map((m) => ({ role: m.role, content: m.content }))
      : [{ role: 'user', content: trimmedMsg }];

    const apiKey = process.env.VENICE_API_KEY;
    let reply = '';

    if (!apiKey || apiKey === 'YOUR_ACTUAL_VENICE_API_KEY') {
      reply = `[Notice] Model "${selectedModel}" responded, but VENICE_API_KEY is not configured yet in Render Environment Variables.`;
    } else {
      const resp = await fetch('https://api.venice.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: selectedModel, messages: payload }),
      });
      if (!resp.ok) {
        const errTxt = await resp.text();
        return res.status(502).json({ error: `Venice AI Error: ${errTxt}` });
      }
      const cData = await resp.json();
      reply = cData.choices?.[0]?.message?.content || 'No reply from model.';
    }

    await supabase.from('messages').insert({ chat_id: chatId, role: 'assistant', content: reply, model: selectedModel });
    await supabase.from('usage_logs').insert({ user_id: req.user.id, model: selectedModel });

    const newCredits = Math.max(0, req.user.credits - 1);
    await supabase.from('users').update({ credits: newCredits }).eq('id', req.user.id);

    return res.json({ chatId, reply, model: selectedModel, creditsRemaining: newCredits });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 6. Admin Routes (/api/admin)
// -------------------------------------------------------------
app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  try {
    const [
      { count: usersCount },
      { count: chatsCount },
      { count: messagesCount },
      { count: usageCount },
    ] = await Promise.all([
      supabase.from('users').select('*', { count: 'exact', head: true }),
      supabase.from('chats').select('*', { count: 'exact', head: true }),
      supabase.from('messages').select('*', { count: 'exact', head: true }),
      supabase.from('usage_logs').select('*', { count: 'exact', head: true }),
    ]);

    return res.json({
      stats: {
        users: usersCount || 0,
        chats: chatsCount || 0,
        messages: messagesCount || 0,
        usage: usageCount || 0,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to load stats.' });
  }
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const { data: users } = await supabase
      .from('users')
      .select('id, email, name, role, credits, is_banned, created_at')
      .order('created_at', { ascending: false });
    return res.json({ users: users || [] });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to load users.' });
  }
});

app.patch('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const { role, credits, is_banned } = req.body;
    const updates = {};
    if (typeof role === 'string') updates.role = role.trim().toLowerCase();
    if (typeof credits !== 'undefined') updates.credits = parseInt(credits, 10);
    if (typeof is_banned === 'boolean') updates.is_banned = is_banned;

    const { data: updated, error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', id)
      .select('id, email, name, role, credits, is_banned, created_at')
      .single();

    if (error) return res.status(400).json({ error: 'Update failed.' });
    return res.json({ user: updated });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 7. Static Files & Root
// -------------------------------------------------------------
app.use(express.static(path.join(rootDir, 'public')));
app.get('/', (req, res) => res.redirect('/login.html'));
app.use('/api/*', (req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
app.use((req, res) => res.redirect('/login.html'));

// -------------------------------------------------------------
// 8. Start Server (Binding to 0.0.0.0 is required for Render)
// -------------------------------------------------------------
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`===============================================`);
  console.log(`HRS AI Platform running on http://0.0.0.0:${PORT}`);
  console.log(`Health Check: http://0.0.0.0:${PORT}/api/health`);
  console.log(`===============================================`);
});

export default app;
