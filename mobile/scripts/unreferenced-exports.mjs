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
 * It cannot see methods, which is a real limit: two of the four were methods
 * on SessionManager. It catches the module-level half of the problem, and
 * nothing here should be read as saying the other half is covered.
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

  // Not reachable, and that is the bug rather than the exception. Rotating the
  // signed prekey needs the previous one retained so a peer that fetched the
  // old bundle can still complete a handshake, which is more than a call site.
  // Recorded under "Not done" in docs/STATUS.md.
  ['signedPreKeyIsStale', 'the rotation it exists for is not implemented; see docs/STATUS.md'],
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
