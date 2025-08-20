# OnionMessenger

Hosts encrypted messenger platform on a .onion link, simple user signup and assigned an ID. Add new people with just sending the ID.

## Goals

- Provide anonymous, encrypted messaging over the Tor network.
- Keep setup lightweight and easy to self-host.
- Store minimal metadata while allowing user discovery through shareable IDs.

## Architecture

- **Tor hidden service** exposes the web interface and API via an `.onion` domain.
- **Backend** uses WebSocket for real-time encrypted communication.
- **Frontend** is a simple HTML/JavaScript interface communicating over REST and WebSocket endpoints.
