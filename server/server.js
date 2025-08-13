require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const { registerUser, verifyUser, findById, addContact } = require('./userStore');
const { storeMessage, getMessagesFor } = require('./messageStore');

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('JWT_SECRET environment variable not set');
  process.exit(1);
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization required' });
  }
  try {
    const { id } = jwt.verify(auth.slice(7), JWT_SECRET);
    const user = findById(id);
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await registerUser(username, password);
    res.status(201).json(user);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await verifyUser(username, password);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/contacts/:id', authMiddleware, (req, res) => {
  const contactId = parseInt(req.params.id, 10);
  if (Number.isNaN(contactId)) {
    return res.status(400).json({ error: 'Invalid contact id' });
  }
  try {
    const contacts = addContact(req.user.id, contactId);
    res.json({ contacts });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/messages', authMiddleware, (req, res) => {
  const { toId, content } = req.body;
  const to = parseInt(toId, 10);
  if (Number.isNaN(to) || !content) {
    return res.status(400).json({ error: 'Recipient and content required' });
  }
  if (!findById(to)) {
    return res.status(404).json({ error: 'Recipient not found' });
  }
  try {
    storeMessage(req.user.id, to, content);
    res.json({ message: 'Message sent' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/messages', authMiddleware, (req, res) => {
  const msgs = getMessagesFor(req.user.id);
  res.json({ messages: msgs });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
