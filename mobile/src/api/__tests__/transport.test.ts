import { describe, expect, it } from 'vitest';

import { TildraClient } from '../client';
import { TildraSocket } from '../socket';

/**
 * docs/THREAT_MODEL.md A2 is about somebody on the network between the device
 * and the server, and everything it claims rests on the transport being
 * encrypted. The rule that enforces it existed — `assertUsableServerUrl`, in
 * crypto/scan.ts — and was applied to the one server address that arrives in a
 * scanned QR code. The address the app actually talks to, from configuration
 * or `EXPO_PUBLIC_TILDRA_SERVER`, went through nothing: a deployment pointed at
 * `http://` would have carried every bearer token, mailbox registration and
 * handle lookup in the clear underneath a threat model that said TLS covered
 * them.
 *
 * The rule is the same one, called from both. These are the cases that reach
 * it through the client and the socket rather than through a camera.
 */
describe('the server the app talks to', () => {
  const noop = { onEnvelope: () => {} };

  it('accepts TLS', () => {
    expect(() => new TildraClient({ baseUrl: 'https://api.tildra.chat' })).not.toThrow();
    expect(() => new TildraSocket('https://api.tildra.chat', 'token', noop)).not.toThrow();
  });

  it('refuses plaintext to anywhere that is not this machine', () => {
    for (const url of [
      'http://api.tildra.chat',
      'http://192.168.1.10:8080',
      // A hostname that merely starts with the loopback name is somebody
      // else's host, and a prefix check is how that gets missed.
      'http://localhost.attacker.example',
      'http://127.0.0.1.attacker.example',
    ]) {
      expect(() => new TildraClient({ baseUrl: url }), url).toThrow(/plaintext/);
      expect(() => new TildraSocket(url, 'token', noop), url).toThrow(/plaintext/);
    }
  });

  it('allows loopback, because a certificate for it would be theatre', () => {
    for (const url of ['http://127.0.0.1:8080', 'http://localhost:3000']) {
      expect(() => new TildraClient({ baseUrl: url }), url).not.toThrow();
      expect(() => new TildraSocket(url, 'token', noop), url).not.toThrow();
    }
  });

  it('refuses what the rule already refused for scanned codes', () => {
    // Credentials `fetch` would use and nothing would mention, a scheme that is
    // neither, and something that is not a URL at all.
    expect(() => new TildraClient({ baseUrl: 'https://user:pw@api.tildra.chat' })).toThrow(
      /credentials/,
    );
    expect(() => new TildraClient({ baseUrl: 'ftp://tildra.example' })).toThrow(/unsupported/);
    expect(() => new TildraClient({ baseUrl: 'api.tildra.chat' })).toThrow(/not a URL/);
  });

  it('gates the socket as well as the client', () => {
    // The socket derives ws:// from http:// and wss:// from https://, so a
    // check on one of them leaves the connection that carries every delivered
    // envelope unchecked.
    expect(() => new TildraSocket('http://api.tildra.chat', 'token', noop)).toThrow(/plaintext/);
  });
});
