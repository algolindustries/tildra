import { describe, expect, it } from 'vitest';

import {
  GroupError,
  MAX_GROUP_SKIP,
  ReceiverKeyState,
  SenderKeyState,
  createSenderKey,
  decodeDistribution,
  decodeGroupMessage,
  decryptGroupMessage,
  deserializeReceiverKey,
  deserializeSenderKey,
  encodeDistribution,
  encodeGroupMessage,
  encryptGroupMessage,
  serializeReceiverKey,
  serializeSenderKey,
} from '../group';
import { equal, fromUtf8, utf8 } from '../primitives';

const GROUP = 'group-0123456789';

/** A member: their own sending chain, plus a receiving chain per other member. */
interface Member {
  id: string;
  sender: SenderKeyState;
  receivers: Map<string, ReceiverKeyState>;
}

function member(id: string, groupId = GROUP): Member {
  return { id, sender: createSenderKey(groupId), receivers: new Map() };
}

/** Distribute every member's sender key to every other member. */
function distribute(members: Member[]): void {
  for (const from of members) {
    const blob = encodeDistribution(from.sender);
    for (const to of members) {
      if (to.id === from.id) continue;
      to.receivers.set(from.id, decodeDistribution(from.id, blob));
    }
  }
}

/** Encrypt once, deliver to everyone — what the server fanout does. */
function broadcast(from: Member, to: Member[], text: string): string[] {
  const message = encryptGroupMessage(from.sender, utf8(text));
  const wire = encodeGroupMessage(message);
  return to
    .filter((m) => m.id !== from.id)
    .map((m) => {
      const receiver = m.receivers.get(from.id);
      if (!receiver) throw new Error(`${m.id} has no sender key for ${from.id}`);
      return fromUtf8(decryptGroupMessage(receiver, decodeGroupMessage(wire)));
    });
}

describe('group messaging', () => {
  it('delivers a message to every member', () => {
    const members = [member('alice'), member('bob'), member('carol')];
    distribute(members);

    expect(broadcast(members[0], members, 'herkese merhaba')).toEqual([
      'herkese merhaba',
      'herkese merhaba',
    ]);
  });

  it('lets every member send', () => {
    const members = [member('alice'), member('bob'), member('carol')];
    distribute(members);

    expect(broadcast(members[0], members, 'from alice')).toEqual(['from alice', 'from alice']);
    expect(broadcast(members[1], members, 'from bob')).toEqual(['from bob', 'from bob']);
    expect(broadcast(members[2], members, 'from carol')).toEqual(['from carol', 'from carol']);
  });

  it('carries a long conversation across many senders', () => {
    const members = [member('a'), member('b'), member('c'), member('d')];
    distribute(members);

    for (let round = 0; round < 10; round++) {
      for (const sender of members) {
        const text = `${sender.id} round ${round}`;
        expect(broadcast(sender, members, text)).toEqual(Array(members.length - 1).fill(text));
      }
    }
  });

  it('scales to a large group', () => {
    const members = Array.from({ length: 25 }, (_, i) => member(`m${i}`));
    distribute(members);
    const received = broadcast(members[7], members, 'big group');
    expect(received).toHaveLength(24);
    expect(new Set(received)).toEqual(new Set(['big group']));
  });

  it('handles messages arriving out of order', () => {
    const [alice, bob] = [member('alice'), member('bob')];
    distribute([alice, bob]);

    const wire = ['zero', 'one', 'two', 'three', 'four'].map((text) =>
      encodeGroupMessage(encryptGroupMessage(alice.sender, utf8(text))),
    );
    const receiver = bob.receivers.get('alice')!;

    // Fanout reorders more than a pairwise session does.
    for (const index of [3, 0, 4, 1, 2]) {
      const expected = ['zero', 'one', 'two', 'three', 'four'][index];
      expect(fromUtf8(decryptGroupMessage(receiver, decodeGroupMessage(wire[index])))).toBe(expected);
    }
  });

  it('refuses a message replayed from before the retained window', () => {
    const [alice, bob] = [member('alice'), member('bob')];
    distribute([alice, bob]);
    const receiver = bob.receivers.get('alice')!;

    const first = encryptGroupMessage(alice.sender, utf8('one'));
    const second = encryptGroupMessage(alice.sender, utf8('two'));

    // Consume the second, which caches the first as skipped, then consume the
    // first — legitimate. Replaying it a third time must fail.
    decryptGroupMessage(receiver, second);
    decryptGroupMessage(receiver, first);
    expect(() => decryptGroupMessage(receiver, first)).toThrow(GroupError);
  });

  it('refuses to skip an implausible number of messages', () => {
    const [alice, bob] = [member('alice'), member('bob')];
    distribute([alice, bob]);
    const receiver = bob.receivers.get('alice')!;

    for (let i = 0; i < MAX_GROUP_SKIP + 5; i++) encryptGroupMessage(alice.sender, utf8('x'));
    const farAhead = encryptGroupMessage(alice.sender, utf8('too far'));

    expect(() => decryptGroupMessage(receiver, farAhead)).toThrow(/skip/);
  });
});

describe('group message authenticity', () => {
  it('stops one member forging a message from another', () => {
    // The attack this whole design exists to prevent: Bob holds Alice's chain
    // key, so he can derive her message keys. Without signatures he could
    // produce a message the group would attribute to her.
    const [alice, bob, carol] = [member('alice'), member('bob'), member('carol')];
    distribute([alice, bob, carol]);

    const aliceChainAsBobSeesIt = bob.receivers.get('alice')!;

    // Bob builds a forgery using Alice's chain key but his own signing key.
    const forgery: SenderKeyState = {
      groupId: GROUP,
      chainKey: aliceChainAsBobSeesIt.chainKey.slice(),
      iteration: aliceChainAsBobSeesIt.iteration,
      signing: bob.sender.signing,
    };
    const forged = encryptGroupMessage(forgery, utf8('alice never said this'));

    const carolsViewOfAlice = carol.receivers.get('alice')!;
    expect(() => decryptGroupMessage(carolsViewOfAlice, forged)).toThrow(/signature/);
  });

  it('rejects a tampered ciphertext', () => {
    const [alice, bob] = [member('alice'), member('bob')];
    distribute([alice, bob]);

    const message = encryptGroupMessage(alice.sender, utf8('authentic'));
    message.ciphertext[0] ^= 0xff;
    expect(() => decryptGroupMessage(bob.receivers.get('alice')!, message)).toThrow(/signature/);
  });

  it('rejects a message whose iteration was altered', () => {
    const [alice, bob] = [member('alice'), member('bob')];
    distribute([alice, bob]);

    const first = encryptGroupMessage(alice.sender, utf8('first'));
    encryptGroupMessage(alice.sender, utf8('second'));
    first.iteration = 1;

    expect(() => decryptGroupMessage(bob.receivers.get('alice')!, first)).toThrow(GroupError);
  });

  it('rejects a message replayed into a different group', () => {
    const [alice, bob] = [member('alice'), member('bob')];
    distribute([alice, bob]);
    const message = encryptGroupMessage(alice.sender, utf8('for group one'));

    const otherGroup = { ...bob.receivers.get('alice')!, groupId: 'group-other' };
    expect(() => decryptGroupMessage(otherGroup, message)).toThrow(/different group/);
  });

  it('does not decrypt under another member’s receiving chain', () => {
    const [alice, bob, carol] = [member('alice'), member('bob'), member('carol')];
    distribute([alice, bob, carol]);

    const fromAlice = encryptGroupMessage(alice.sender, utf8('secret'));
    // Bob has a chain for Carol too; it must not open Alice's traffic.
    expect(() => decryptGroupMessage(bob.receivers.get('carol')!, fromAlice)).toThrow(GroupError);
  });
});

describe('group membership changes', () => {
  it('does not let a new member read messages sent before they joined', () => {
    const [alice, bob] = [member('alice'), member('bob')];
    distribute([alice, bob]);

    const before = encryptGroupMessage(alice.sender, utf8('said before dave arrived'));
    expect(fromUtf8(decryptGroupMessage(bob.receivers.get('alice')!, before))).toBe(
      'said before dave arrived',
    );

    // Dave joins and is given the chain from its current position.
    const dave = member('dave');
    dave.receivers.set('alice', decodeDistribution('alice', encodeDistribution(alice.sender)));

    expect(() => decryptGroupMessage(dave.receivers.get('alice')!, before)).toThrow(GroupError);

    const after = encryptGroupMessage(alice.sender, utf8('said after dave arrived'));
    expect(fromUtf8(decryptGroupMessage(dave.receivers.get('alice')!, after))).toBe(
      'said after dave arrived',
    );
  });

  it('locks a removed member out once the group rotates', () => {
    const [alice, bob, mallory] = [member('alice'), member('bob'), member('mallory')];
    distribute([alice, bob, mallory]);

    // Mallory can read while she is a member.
    const whileMember = encryptGroupMessage(alice.sender, utf8('while mallory is here'));
    expect(fromUtf8(decryptGroupMessage(mallory.receivers.get('alice')!, whileMember))).toBe(
      'while mallory is here',
    );

    // Mallory is removed. Every remaining member starts a fresh chain and
    // redistributes only among themselves.
    const mallorysStaleChain = mallory.receivers.get('alice')!;
    alice.sender = createSenderKey(GROUP);
    bob.sender = createSenderKey(GROUP);
    distribute([alice, bob]);

    const afterRemoval = encryptGroupMessage(alice.sender, utf8('mallory must not read this'));
    expect(fromUtf8(decryptGroupMessage(bob.receivers.get('alice')!, afterRemoval))).toBe(
      'mallory must not read this',
    );
    expect(() => decryptGroupMessage(mallorysStaleChain, afterRemoval)).toThrow(GroupError);
  });
});

describe('group key persistence', () => {
  it('round-trips a sender key', () => {
    const [alice, bob] = [member('alice'), member('bob')];
    distribute([alice, bob]);
    encryptGroupMessage(alice.sender, utf8('advance the chain'));

    const revived = deserializeSenderKey(JSON.parse(JSON.stringify(serializeSenderKey(alice.sender))));
    const message = encryptGroupMessage(revived, utf8('after restart'));

    expect(fromUtf8(decryptGroupMessage(bob.receivers.get('alice')!, message))).toBe('after restart');
  });

  it('round-trips a receiver key including skipped keys', () => {
    const [alice, bob] = [member('alice'), member('bob')];
    distribute([alice, bob]);

    const messages = [0, 1, 2, 3].map((i) => encryptGroupMessage(alice.sender, utf8(`m${i}`)));
    const receiver = bob.receivers.get('alice')!;
    decryptGroupMessage(receiver, messages[3]);
    expect(receiver.skipped.size).toBe(3);

    const revived = deserializeReceiverKey(
      JSON.parse(JSON.stringify(serializeReceiverKey(receiver))),
    );
    expect(revived.skipped.size).toBe(3);
    expect(fromUtf8(decryptGroupMessage(revived, messages[0]))).toBe('m0');
    expect(fromUtf8(decryptGroupMessage(revived, messages[2]))).toBe('m2');
  });

  it('rejects an unknown serialization version', () => {
    const state = serializeSenderKey(createSenderKey(GROUP));
    expect(() => deserializeSenderKey({ ...state, v: 9 as unknown as 1 })).toThrow(/version/);
  });
});

describe('sender key distribution', () => {
  it('round-trips through the wire format', () => {
    const alice = createSenderKey(GROUP);
    encryptGroupMessage(alice, utf8('advance'));

    const decoded = decodeDistribution('alice', encodeDistribution(alice));
    expect(decoded.groupId).toBe(GROUP);
    expect(decoded.memberId).toBe('alice');
    expect(decoded.iteration).toBe(alice.iteration);
    expect(equal(decoded.chainKey, alice.chainKey)).toBe(true);
    expect(equal(decoded.signingPublicKey, alice.signing.publicKey)).toBe(true);
  });

  it('never includes the signing secret key', () => {
    // If the private half ever travelled with the chain key, every member
    // could forge messages from every other member and the signature would be
    // decoration.
    const alice = createSenderKey(GROUP);
    const blob = encodeDistribution(alice);

    const needle = alice.signing.secretKey;
    let found = false;
    outer: for (let i = 0; i + needle.length <= blob.length; i++) {
      for (let j = 0; j < needle.length; j++) {
        if (blob[i + j] !== needle[j]) continue outer;
      }
      found = true;
      break;
    }
    expect(found).toBe(false);
  });

  it('rejects a malformed distribution', () => {
    const blob = encodeDistribution(createSenderKey(GROUP));
    expect(() => decodeDistribution('x', blob.slice(0, blob.length - 5))).toThrow();
  });
});
