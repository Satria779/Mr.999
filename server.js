const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: '*' }
});

app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = 'rahasia_chat_sederhana';
const users = []; // { id, username, passwordHash }
const messages = []; // { id, fromUserId, toUserId, message, timestamp }
let onlineUsers = new Map(); // userId -> socketId

// Helper
function findUserByUsername(username) {
  return users.find(u => u.username === username);
}

function findUserById(id) {
  return users.find(u => u.id === id);
}

// Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username dan password wajib diisi' });
  if (findUserByUsername(username)) return res.status(400).json({ error: 'Username sudah terdaftar' });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now().toString(), username, passwordHash: hashed };
  users.push(newUser);
  res.json({ success: true, userId: newUser.id, username: newUser.username });
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = findUserByUsername(username);
  if (!user) return res.status(400).json({ error: 'Username tidak ditemukan' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(400).json({ error: 'Password salah' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
  res.json({ success: true, token, userId: user.id, username: user.username });
});

// Daftar semua pengguna (kecuali diri sendiri)
app.get('/users', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Token diperlukan' });
  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const otherUsers = users.filter(u => u.id !== decoded.id).map(u => ({ id: u.id, username: u.username }));
    res.json(otherUsers);
  } catch (err) {
    res.status(401).json({ error: 'Token tidak valid' });
  }
});

// Ambil riwayat chat antara dua pengguna
app.get('/messages/:userId', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Token diperlukan' });
  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const otherUserId = req.params.userId;
    const chatHistory = messages.filter(m => 
      (m.fromUserId === decoded.id && m.toUserId === otherUserId) ||
      (m.fromUserId === otherUserId && m.toUserId === decoded.id)
    ).sort((a, b) => a.timestamp - b.timestamp);
    res.json(chatHistory);
  } catch (err) {
    res.status(401).json({ error: 'Token tidak valid' });
  }
});

// Socket.io dengan autentikasi JWT
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Token tidak ada'));
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('Token tidak valid'));
    socket.userId = decoded.id;
    socket.username = decoded.username;
    next();
  });
});

io.on('connection', (socket) => {
  console.log(`User ${socket.username} (${socket.userId}) terhubung`);
  onlineUsers.set(socket.userId, socket.id);
  
  // Kirim daftar online ke semua client (opsional)
  io.emit('online_users', Array.from(onlineUsers.keys()));

  // Bergabung ke room pribadi
  socket.join(`user_${socket.userId}`);

  // Kirim pesan offline yang belum diterima
  const pendingMessages = messages.filter(m => m.toUserId === socket.userId && !m.delivered);
  pendingMessages.forEach(msg => {
    socket.emit('new_message', {
      id: msg.id,
      fromUserId: msg.fromUserId,
      fromUsername: findUserById(msg.fromUserId)?.username,
      message: msg.message,
      timestamp: msg.timestamp
    });
    msg.delivered = true;
  });

  // Terima pesan baru
  socket.on('send_message', async (data) => {
    const { toUserId, message } = data;
    if (!message.trim()) return;

    const newMessage = {
      id: Date.now().toString(),
      fromUserId: socket.userId,
      toUserId: toUserId,
      message: message,
      timestamp: Date.now(),
      delivered: false
    };
    messages.push(newMessage);

    // Kirim ke penerima jika online
    const receiverSocketId = onlineUsers.get(toUserId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('new_message', {
        id: newMessage.id,
        fromUserId: socket.userId,
        fromUsername: socket.username,
        message: message,
        timestamp: newMessage.timestamp
      });
      newMessage.delivered = true;
    }
    
    // Konfirmasi ke pengirim
    socket.emit('message_sent', {
      id: newMessage.id,
      toUserId: toUserId,
      message: message,
      timestamp: newMessage.timestamp
    });
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(socket.userId);
    io.emit('online_users', Array.from(onlineUsers.keys()));
    console.log(`User ${socket.username} terputus`);
  });
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});