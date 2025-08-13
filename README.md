# OnionMessenger

Hosts encrypted messenger platform on a .onion link, simple user signup and assigned an ID. Add new people with just sending the ID.

## Goals

- Provide anonymous, encrypted messaging over the Tor network.
- Keep setup lightweight and easy to self-host.
- Store minimal metadata while allowing user discovery through shareable IDs.

## Architecture

- **Tor hidden service** exposes the web interface and API via an `.onion` domain.
- **Backend** uses Node.js with Express and WebSocket for real-time communication.
- **Database** (e.g., MongoDB) persists user accounts and messages.
- **Client** is a simple HTML/JavaScript interface communicating over REST and WebSocket endpoints.

## Dependencies

- Node.js 18+
- npm 9+
- Tor (for hosting the hidden service)
- MongoDB 6+ or another compatible datastore
- Optional: `pm2` or similar tool for process management in production

## Development workflow

1. Create a feature branch from `main`.
2. Implement the feature and add accompanying tests.
3. Run `npm test` and ensure all checks pass.
4. Submit a pull request with a clear description of the change.

## Local setup

```bash
git clone https://github.com/<user>/OnionMessenger.git
cd OnionMessenger/server
npm install
```

## Running the service

1. Start Tor locally and configure a hidden service that forwards to the server's port.
2. Launch the application from the `server/` directory:

```bash
JWT_SECRET=your-secret npm start
```

3. Access the service via the generated `.onion` address using the Tor Browser.


## Environment variables

- `JWT_SECRET`: Secret key used to sign authentication tokens. **Required**.
- `PORT`: Port for the HTTP server. Defaults to `3000`.

