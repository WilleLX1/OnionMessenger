process.env.MESSAGE_SECRET = 'test-secret';

const { registerUser } = require('../userStore');
const { storeMessage, getMessagesFor } = require('../messageStore');

describe('Message flow', () => {
  test('sends and receives a message', async () => {
    const alice = await registerUser('alice', 'password');
    const bob = await registerUser('bob', 'hunter2');

    storeMessage(alice.id, bob.id, 'hello');
    const messages = getMessagesFor(bob.id);
    expect(messages).toHaveLength(1);
    expect(messages[0]).toEqual({ fromId: alice.id, content: 'hello' });
  });
});
