const bcrypt = require('bcryptjs');

const users = [];
let nextId = 1;

async function registerUser(username, password) {
  if (!username || !password) {
    throw new Error('Username and password required');
  }
  if (users.find(u => u.username === username)) {
    throw new Error('User already exists');
  }
  const hashed = await bcrypt.hash(password, 10);
  const user = { id: nextId++, username, password: hashed, contacts: [] };
  users.push(user);
  return { id: user.id, username: user.username };
}

async function verifyUser(username, password) {
  const user = users.find(u => u.username === username);
  if (!user) {
    return null;
  }
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return null;
  }
  return user;
}

function findById(id) {
  return users.find(u => u.id === id);
}

function addContact(userId, contactId) {
  const user = findById(userId);
  const contact = findById(contactId);
  if (!user || !contact) {
    throw new Error('User or contact not found');
  }
  if (!user.contacts.includes(contactId)) {
    user.contacts.push(contactId);
  }
  return user.contacts;
}

module.exports = {
  registerUser,
  verifyUser,
  findById,
  addContact,
};

