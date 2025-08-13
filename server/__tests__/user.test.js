const { registerUser, verifyUser } = require('../userStore');

describe('User signup and login', () => {
  test('registers a new user and logs in', async () => {
    const user = await registerUser('alice', 'password');
    expect(user).toEqual({ id: 1, username: 'alice' });

    const verified = await verifyUser('alice', 'password');
    expect(verified.username).toBe('alice');
  });

  test('prevents duplicate usernames', async () => {
    await expect(registerUser('alice', 'password2')).rejects.toThrow('User already exists');
  });
});
