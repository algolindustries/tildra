#!/usr/bin/env node
/**
 * Find behaviour that only the tests call.
 *
 * This project has shipped the same bug four times: something that works, is
 * tested, and cannot be reached from the app. `beginDeviceLink` was called
 * only by tests, so a user could not produce a device-link code.
 * `checkAuditors` was called by nothing, so no auditor could ever be
 * consulted. `safetyQrPayload` had no renderer. The split-view alarm was
 * written to a field the app never displays. Every one was found by hand,
 * late, by somebody going looking.
 *
 * All four share a signature this can look for: an exported function or class
 * whose only callers are under `__tests__`. Green tests, no path from the UI.
 *
 * Deliberately narrow. Types, interfaces and constants are vocabulary rather
 * than behaviour and are not reported, because a check that lists eighty
 * things gets silenced rather than fixed. Matching is by identifier, not by
 * resolved reference — a tool that needed a type checker would not be run.
 *
 * Public methods of exported classes are checked too, because two of the four
 * were methods on SessionManager — a class the app holds a reference to is
 * reachable while any number of its methods are not.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');

/**
 * Behaviour that legitimately has no caller in the app. Every entry is a claim
 * somebody can check, which is the point of writing it down rather than
 * loosening the rule.
 */
const ALLOWED = new Map([
  ['currentRuntime', 'a debugging escape hatch, deliberately not reachable from any screen'],
  [
    'createWebRtcPeer',
    'reached through a dynamic import in state/app.ts, so that only calls need a dev build',
  ],

  // Internal steps of an algorithm, exported so the tests can drive them one
  // at a time rather than only through the whole. Each is called from its own
  // module by the function above it.
  ['hashLeaf', 'a Merkle primitive, called by the tree it builds'],
  ['hashChildren', 'a Merkle primitive, called by the tree it builds'],
  ['encodeEntry', 'the leaf encoding, called by hashLeaf'],
  ['verifyInclusion', 'called by verifyHandleProof'],
  ['verifyTreeHead', 'called by verifyHandleProof and crossCheckTreeHead'],
  ['sdpFingerprint', 'called by signCallSdp and verifyCallSdp'],
  ['formatFingerprint', 'called by the binding transcript'],
  ['parseIceCandidate', 'called by filterIceCandidates'],
  ['classifyScan', 'called by readDeviceLink and readSafetyCode'],
  ['pairingCode', 'called by sealApproval and openApproval'],
  ['dayNumber', 'called by the mailbox derivation'],
  ['encodeProfile', 'called by profileContent'],
  ['deriveSharedHeaderKeys', 'called by the ratchet initialisers'],

  // Content types the protocol defines and this client does not yet send.
  ['rotationContent', 'the group rotation message; the manager rotates by re-distributing keys'],

  // Formatters the current screens do not use. Kept because deleting a
  // correct, tested formatter to satisfy a checker is the wrong trade.
  ['dayLabel', 'date separators are not in the chat list yet'],
  ['previewText', 'the chat list renders its own preview'],

  ['isSupportedLocale', 'called by resolveLocale'],

  // Client and socket surface the app does not need but a caller reasonably
  // would. Kept because a REST client that cannot report its own state is a
  // worse client, not a tidier one.
  ['ApiError.isAuthFailure', 'for callers deciding whether to re-authenticate'],
  ['TildraClient.getCredentials', 'used by the tests to build a socket the way the app does'],
  ['TildraClient.health', 'a liveness probe for whoever is running the thing'],
  ['TildraSocket.currentState', 'the app subscribes to onStateChange instead'],
  ['TildraClient.transparencyHead', 'the client verifies heads through resolveHandle'],

  // Retention helpers with nothing scheduling them yet. Deleting a correct,
  // tested one to satisfy a checker would be the wrong trade; leaving them
  // undeclared would hide that no client-side retention runs.
  ['Database.deleteMessagesOlderThan', 'no client-side retention is scheduled yet'],
  ['Database.deleteSessions', 'used by a full reset the UI does not offer yet'],
  ['Database.acknowledgeIdentityChange', 'markVerified clears the flag through upsertConversation'],
  ['SessionManager.resetSession', 'no screen offers starting a session over yet'],

  // Groups: implemented, tested end to end, and with no user interface at all.
  // Recorded under "Not done" in docs/STATUS.md rather than left to look
  // finished. Remove these entries when the screens exist.
  ['SessionManager.createGroup', 'no group UI; see docs/STATUS.md'],
  ['SessionManager.sendGroupMessage', 'no group UI; see docs/STATUS.md'],
  ['SessionManager.addGroupMember', 'no group UI; see docs/STATUS.md'],
  ['SessionManager.removeGroupMember', 'no group UI; see docs/STATUS.md'],
  ['SessionManager.listGroups', 'no group UI; see docs/STATUS.md'],
  ['groupConversationKey', 'called within manager.ts; the screens that will use it do not exist yet'],

  // Account recovery: the crypto exists and the screens do not. Recorded
  // under "Not done"; remove these when onboarding shows a phrase.
  ['TildraClient.putBackup', 'no recovery screens yet; see docs/STATUS.md'],
  ['TildraClient.getBackup', 'no recovery screens yet; see docs/STATUS.md'],
  ['generateRecoveryPhrase', 'no recovery screens yet; see docs/STATUS.md'],
  ['normalizeRecoveryPhrase', 'called by the rest of recovery.ts'],
  ['isValidRecoveryPhrase', 'for the screen that will check as the user types'],
  ['recoverySeed', 'called by recoveryKeys'],
  ['identityFromSeed', 'called by recoveryKeys'],
  ['backupKeyFromSeed', 'called by recoveryKeys'],
  ['recoveryKeys', 'no recovery screens yet; see docs/STATUS.md'],
  ['sealBackup', 'no recovery screens yet; see docs/STATUS.md'],
  ['openBackup', 'no recovery screens yet; see docs/STATUS.md'],
  ['phraseRows', 'the layout the phrase screen will use'],
  ['recoveryLookupId', 'called by recoveryKeys'],
  ['TildraClient.putRecoveryBlob', 'no recovery screens yet; see docs/STATUS.md'],
  ['TildraClient.getRecoveryBlob', 'no recovery screens yet; see docs/STATUS.md'],
  ['phraseEntropyBits', 'asserted by the tests; a phrase that claims 256 bits should carry them'],

  ['signedPreKeyIsStale', 'called by rotateSignedPreKeysIfStale'],
  ['rotateSignedPreKeys', 'called by rotateSignedPreKeysIfStale'],
  ['encodeSigned', 'called by encodePreKeys'],
  ['decodeSigned', 'called by decodePreKeys'],
]);

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      if (entry !== 'node_modules') walk(path, out);
    } else if (/\.tsx?$/.test(path)) {
      out.push(path);
    }
  }
  return out;
}

const all = walk(join(ROOT, 'src'));
const isTest = (path) => path.includes('__tests__');
const appFiles = [...all.filter((f) => !isTest(f)), join(ROOT, 'App.tsx'), join(ROOT, 'index.ts')];
const testFiles = all.filter(isTest);

const read = new Map([...appFiles, ...testFiles].map((f) => [f, readFileSync(f, 'utf8')]));

// Behaviour only: functions and classes. Not types, not constants.
const PATTERNS = [
  /^export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/gm,
  /^export\s+(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/gm,
];

/**
 * Public method names of every exported class in a file.
 *
 * Brace counting rather than a parser, for the same reason as everything else
 * here. `private` and `protected` members are skipped: they are internal by
 * construction and unreachable is what they are for.
 */
function publicMethods(body) {
  const found = [];
  const classStart = /^export\s+(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/;
  const lines = body.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const opened = classStart.exec(lines[i]);
    if (!opened) continue;

    let depth = 0;
    for (let j = i; j < lines.length; j++) {
      const line = lines[j];
      const before = depth;
      depth += (line.match(/{/g) ?? []).length - (line.match(/}/g) ?? []).length;
      if (j > i && before === 0) break;

      // Members sit at one level of indentation inside the class body.
      const member =
        /^ {2}(?!\/\/)((?:(?:private|protected|public|static|readonly|async|get|set|abstract)\s+)*)([A-Za-z_$][\w$]*)\s*\(/.exec(
          line,
        );
      if (!member) continue;
      const modifiers = member[1] ?? '';
      const name = member[2];
      if (/private|protected/.test(modifiers)) continue;
      if (name === 'constructor' || name === 'if' || name === 'for' || name === 'while') continue;
      found.push({ owner: opened[1], name });
    }
  }
  return found;
}

const findings = [];
for (const file of appFiles.filter((f) => f.startsWith(join(ROOT, 'src')))) {
  const body = read.get(file);
  const names = new Set();
  for (const pattern of PATTERNS) {
    for (const match of body.matchAll(pattern)) names.add(match[1]);
  }

  for (const name of names) {
    if (ALLOWED.has(name)) continue;
    // An error class is reachable by being thrown in the file that defines it.
    // Listing them buries the findings that matter under thirty that do not.
    if (/Error$/.test(name)) continue;
    const word = new RegExp(`\\b${name}\\b`);
    const usedByApp = appFiles.some((other) => other !== file && word.test(read.get(other)));
    if (usedByApp) continue;
    const usedByTests = testFiles.some((other) => word.test(read.get(other)));
    findings.push({ file: relative(ROOT, file), name, tested: usedByTests });
  }

  for (const { owner, name } of publicMethods(body)) {
    const label = `${owner}.${name}`;
    if (ALLOWED.has(label)) continue;
    const word = new RegExp(`\\.${name}\\b`);
    // A method the class calls on itself is reached; internal use is use. Only
    // `this.` counts, so a method that merely shares a name with a local
    // variable does not look reachable.
    if (new RegExp(`this\\.${name}\\b`).test(body)) continue;
    const usedByApp = appFiles.some((other) => other !== file && word.test(read.get(other)));
    if (usedByApp) continue;
    const usedByTests = testFiles.some((other) => word.test(read.get(other)));
    findings.push({ file: relative(ROOT, file), name: label, tested: usedByTests });
  }
}

if (findings.length === 0) {
  console.log('ok        every exported function and class is reachable from the app');
  process.exit(0);
}

console.log('Behaviour the app cannot reach:\n');
for (const { file, name, tested } of findings) {
  console.log(`  ${file}  ${name}${tested ? '  (called only by tests)' : '  (called by nothing)'}`);
}
console.log(
  '\nEither give it a path from the UI, delete it, or add it to ALLOWED with a\n' +
    'reason. "Tested" is not "reachable", and this project has confused the two\n' +
    'four times.',
);
process.exit(1);
