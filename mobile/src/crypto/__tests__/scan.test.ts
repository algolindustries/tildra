import { describe, expect, it } from 'vitest';

import {
  MAX_SCAN_LENGTH,
  SCAN_REPEAT_WINDOW_MS,
  ScanError,
  assertUsableServerUrl,
  classifyScan,
  createScanGate,
  describeScanError,
  readDeviceLink,
  readSafetyCode,
} from '../scan';
import {
  ProvisioningError,
  createLinkOffer,
  encodeLinkOffer,
  generateProvisioningKey,
} from '../provisioning';
import { generateSigningKeyPair, toHex } from '../primitives';
import { safetyQrPayload } from '../safety';

function linkCode(serverUrl = 'https://api.tildra.chat'): string {
  const identity = generateSigningKeyPair();
  const ephemeral = generateProvisioningKey();
  return encodeLinkOffer(createLinkOffer('prov-1', identity, ephemeral), serverUrl);
}

function safetyCode(): string {
  return safetyQrPayload(generateSigningKeyPair().publicKey, generateSigningKeyPair().publicKey);
}

describe('classifying what came off the camera', () => {
  it('reads a device-link code', () => {
    const scanned = classifyScan(linkCode());
    expect(scanned.kind).toBe('device-link');
    if (scanned.kind !== 'device-link') throw new Error('unreachable');
    expect(scanned.offer.provisioningId).toBe('prov-1');
    expect(scanned.offer.identityCommitment).toHaveLength(32);
    expect(scanned.serverUrl).toBe('https://api.tildra.chat');
  });

  it('reads a safety-number code', () => {
    const scanned = classifyScan(safetyCode());
    expect(scanned.kind).toBe('safety');
  });

  it('tolerates the whitespace a scanner adds', () => {
    expect(classifyScan(`  ${linkCode()}\n`).kind).toBe('device-link');
  });

  it('refuses anything that is not a Tildra code', () => {
    for (const junk of [
      'https://example.com',
      'WIFI:S:cafe;T:WPA;P:hunter2;;',
      'tildra://something-else?x=1',
      'javascript:alert(1)',
      'tildra:verify',
    ]) {
      expect(() => classifyScan(junk), junk).toThrow(ScanError);
    }
  });

  it('refuses an empty scan', () => {
    expect(() => classifyScan('   ')).toThrow(/nothing was scanned/);
  });

  it('refuses a payload too large to be a QR code', () => {
    expect(() => classifyScan('x'.repeat(MAX_SCAN_LENGTH + 1))).toThrow(/too large/);
  });

  it('still refuses a link code that is malformed past its prefix', () => {
    // The prefix decides which parser runs; the parser still gets to say no.
    expect(() => classifyScan('tildra://link?id=a')).toThrow(ProvisioningError);
    expect(() => classifyScan('tildra://link?id=a&key=!!&commit=!!&server=https://x')).toThrow(
      ProvisioningError,
    );
  });
});

describe('refusing the wrong kind of code', () => {
  it('will not treat a safety code as a device link', () => {
    // The confusion that matters: two flows that both accept "whatever was
    // scanned" is how someone gets talked into pointing at the wrong square.
    expect(() => readDeviceLink(safetyCode())).toThrow(/safety-number code/);
  });

  it('will not treat a device link as a safety code', () => {
    expect(() => readSafetyCode(linkCode())).toThrow(/device-link code/);
  });

  it('passes the right kind through unchanged', () => {
    expect(readDeviceLink(linkCode()).offer.provisioningId).toBe('prov-1');
    const safety = safetyCode();
    expect(readSafetyCode(safety)).toBe(safety);
  });

  it('says which screen the code belongs on', () => {
    // A user pointing a camera at the wrong thing needs to be told where to go,
    // not that something is invalid.
    expect(() => readDeviceLink(safetyCode())).toThrow(/safety number screen/);
    expect(() => readSafetyCode(linkCode())).toThrow(/link device screen/);
  });
});

describe('the server address inside a scanned code', () => {
  it('accepts HTTPS', () => {
    expect(assertUsableServerUrl('https://api.tildra.chat')).toBe('https://api.tildra.chat');
    expect(assertUsableServerUrl('https://tildra.example:8443/base')).toBeTruthy();
  });

  it('accepts plaintext only on loopback, which is what a developer runs', () => {
    expect(assertUsableServerUrl('http://localhost:8080')).toBeTruthy();
    expect(assertUsableServerUrl('http://127.0.0.1:8080')).toBeTruthy();
    expect(assertUsableServerUrl('http://[::1]:8080')).toBeTruthy();
  });

  it('refuses a plaintext server anywhere else', () => {
    // A scanned code that downgrades the transport is the whole attack in one
    // field.
    expect(() => assertUsableServerUrl('http://api.tildra.chat')).toThrow(/plaintext/);
    expect(() => assertUsableServerUrl('http://192.168.1.9:8080')).toThrow(/plaintext/);
    expect(() => assertUsableServerUrl('http://localhost.evil.example')).toThrow(/plaintext/);
  });

  it('refuses a scheme that is not HTTP at all', () => {
    for (const bad of ['ftp://x.example', 'file:///etc/passwd', 'javascript:alert(1)']) {
      expect(() => assertUsableServerUrl(bad), bad).toThrow(/unsupported address/);
    }
  });

  it('refuses embedded credentials', () => {
    // fetch would use them and nothing would say so.
    expect(() => assertUsableServerUrl('https://user:pass@api.tildra.chat')).toThrow(/credentials/);
    expect(() => assertUsableServerUrl('https://user@api.tildra.chat')).toThrow(/credentials/);
  });

  it('refuses a query string or fragment on a base URL', () => {
    expect(() => assertUsableServerUrl('https://api.tildra.chat/?next=x')).toThrow(/malformed/);
    expect(() => assertUsableServerUrl('https://api.tildra.chat/#x')).toThrow(/malformed/);
  });

  it('refuses something that is not a URL', () => {
    expect(() => assertUsableServerUrl('not a url')).toThrow(/not a URL/);
    expect(() => assertUsableServerUrl('')).toThrow(/not a URL/);
  });

  it('rejects a whole link code carrying a downgraded server', () => {
    // The end-to-end path: a poster with a QR that would point the app at a
    // plaintext host must not classify at all.
    expect(() => classifyScan(linkCode('http://evil.example'))).toThrow(/plaintext/);
    expect(() => readDeviceLink(linkCode('http://evil.example'))).toThrow(ScanError);
  });
});

describe('the scan gate', () => {
  const CODE = 'tildra://link?a';
  const OTHER = 'tildra://link?b';

  it('handles a burst of identical scans exactly once', () => {
    // A camera delivers the same code many times a second. Without this, one
    // poster held in frame for two seconds adds fifty devices to an account.
    const gate = createScanGate();
    let handled = 0;
    for (let i = 0; i < 50; i++) {
      if (gate.shouldHandle(CODE, 1000 + i * 30)) handled += 1;
    }
    expect(handled).toBe(1);
  });

  it('lets a different code through immediately', () => {
    // Not a plain debounce: someone who realises they are pointing at the
    // wrong square should not have to wait.
    const gate = createScanGate();
    expect(gate.shouldHandle(CODE, 1000)).toBe(true);
    expect(gate.shouldHandle(OTHER, 1010)).toBe(true);
  });

  it('lets the same code through again once the window has passed', () => {
    const gate = createScanGate();
    expect(gate.shouldHandle(CODE, 1000)).toBe(true);
    expect(gate.shouldHandle(CODE, 1000 + SCAN_REPEAT_WINDOW_MS - 1)).toBe(false);
    expect(gate.shouldHandle(CODE, 1000 + SCAN_REPEAT_WINDOW_MS)).toBe(true);
  });

  it('refuses everything once closed', () => {
    // For a link approval even one extra call is one extra device, so a time
    // window is the wrong tool after a scan has been acted on.
    const gate = createScanGate();
    expect(gate.shouldHandle(CODE, 1000)).toBe(true);
    gate.close();
    expect(gate.shouldHandle(CODE, 9_000_000)).toBe(false);
    expect(gate.shouldHandle(OTHER, 9_000_000)).toBe(false);
  });

  it('comes back to life on reset', () => {
    const gate = createScanGate();
    gate.shouldHandle(CODE, 1000);
    gate.close();
    gate.reset();
    expect(gate.shouldHandle(CODE, 1010)).toBe(true);
  });

  it('honours a custom window', () => {
    const gate = createScanGate({ windowMs: 100 });
    expect(gate.shouldHandle(CODE, 0)).toBe(true);
    expect(gate.shouldHandle(CODE, 99)).toBe(false);
    expect(gate.shouldHandle(CODE, 100)).toBe(true);
  });
});

describe('reporting a bad scan', () => {
  it('passes through the reason a code was refused', () => {
    try {
      classifyScan('WIFI:S:cafe;;');
      throw new Error('should have thrown');
    } catch (err) {
      expect(describeScanError(err)).toMatch(/not a Tildra code/);
    }
  });

  it('passes through a provisioning parse failure', () => {
    try {
      classifyScan('tildra://link?id=a');
      throw new Error('should have thrown');
    } catch (err) {
      expect(describeScanError(err)).toMatch(/missing fields/);
    }
  });

  it('does not leak an unexpected error to the screen', () => {
    expect(describeScanError(new TypeError('undefined is not an object'))).toBe(
      'that code could not be read',
    );
  });
});

describe('safety codes still verify after a round trip through the scanner', () => {
  it('matches only the pair it was made for', () => {
    const alice = generateSigningKeyPair();
    const bob = generateSigningKeyPair();
    const carol = generateSigningKeyPair();

    const scanned = readSafetyCode(safetyQrPayload(alice.publicKey, bob.publicKey));
    expect(scanned).toBe(safetyQrPayload(bob.publicKey, alice.publicKey));
    expect(scanned).not.toBe(safetyQrPayload(alice.publicKey, carol.publicKey));
    expect(scanned).toContain(toHex(alice.publicKey) < toHex(bob.publicKey) ? toHex(alice.publicKey) : toHex(bob.publicKey));
  });
});
