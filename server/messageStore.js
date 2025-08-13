const crypto = require('crypto');

const SECRET = process.env.MESSAGE_SECRET;
if (!SECRET) {
  console.error('MESSAGE_SECRET environment variable not set');
  process.exit(1);
}

const KEY = crypto.createHash('sha256').update(SECRET).digest();

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-ctr', KEY, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(data) {
  const [ivHex, encryptedHex] = data.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-ctr', KEY, iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

const messages = [];

function storeMessage(fromId, toId, content) {
  if (!fromId || !toId || !content) {
    throw new Error('Invalid message');
  }
  const encrypted = encrypt(content);
  messages.push({ fromId, toId, content: encrypted });
}

function getMessagesFor(userId) {
  return messages
    .filter(m => m.toId === userId)
    .map(m => ({ fromId: m.fromId, content: decrypt(m.content) }));
}

module.exports = {
  storeMessage,
  getMessagesFor,
};

