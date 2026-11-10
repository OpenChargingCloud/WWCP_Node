/**
 * What the NTS page tells the node when a time server is added, edited or
 * deleted, asked directly.
 *
 * Run with `npm test`. The node is sent the whole list every time, so what
 * is pinned here is that the list sent is the list shown with exactly one
 * change in it, what each server is held to included - and that it reads the
 * way the configuration file would.
 */

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';

import type { NTSTimeSource, ServerPins } from '../api/client';


const { correctionText, entryOf, nameTaken, readable, refreshSet, refreshText, sentOf, sshHeldToText, sshText, withServer, withoutServer } = await import('./ntsServers.ts');


const usual = { ntsKE: 4460, ntp: 123 };

/** A server as the node shows it. */
const shown = (hostname: string, more: Partial<NTSTimeSource> = {}): NTSTimeSource =>
    ({ hostname, priority: 0, ntsKEPort: 4460, ntpPort: 123, enabled: true, ...more });

/** What a server is held to as the node shows it: nothing beyond what is given. */
const heldTo = (more: Partial<ServerPins>): ServerPins =>
    ({ certificate: null, root: null, certificates: [], roots: [], onMismatch: 'refuse', trustOnFirstUse: null, ...more });

/** The root ptbtime1.ptb.de and ptbtime2.ptb.de were believed with, and the certificates they showed. */
const root          = '96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6';
const certificate1  = '244656b8f4d6e058c1a34f636d801fc7a92eff126dc98d7adb50cffaeed4d791';
const certificate2  = 'e2a0ad9e30fddb7d5b35b692159723a1aa96dd3062142456b3795b8638636472';


describe('a time server turned back into its entry', () => {

    it('is a bare name when everything else is the usual', () => {

        assert.deepEqual(entryOf(shown('ptbtime1.ptb.de.'), usual),
                         { hostname: 'ptbtime1.ptb.de' });

    });

    it('says what is not the usual, and nothing that is', () => {

        assert.deepEqual(entryOf(shown('time.local.', { priority: 9, ntsKEPort: 4461, enabled: false }), usual),
                         { hostname: 'time.local', priority: 9, ntsKEPort: 4461, enabled: false });

    });

    it('keeps the id it was shown with, or the next save gives it another', () => {

        assert.deepEqual(entryOf(shown('ptbtime2.ptb.de.', { id: 'legal-2' }), usual),
                         { id: 'legal-2', hostname: 'ptbtime2.ptb.de' });

        assert.deepEqual(entryOf(shown('ptbtime2.ptb.de.', { id: null }), usual),
                         { hostname: 'ptbtime2.ptb.de' },
                         'a node that names no id is not sent one');

    });

    it('keeps the AEAD algorithm its entry offers, or the next save offers every one again', () => {

        assert.deepEqual(entryOf(shown('ptbtime1.ptb.de.', { aead: 'AES-SIV-CMAC-256', aeadAlgorithm: 'AES_SIV_CMAC_256' }), usual),
                         { hostname: 'ptbtime1.ptb.de', aead: 'AES-SIV-CMAC-256' });

        assert.deepEqual(entryOf(shown('ptbtime1.ptb.de.', { aead: null, aeadAlgorithm: 'AES_128_GCM_SIV' }), usual),
                         { hostname: 'ptbtime1.ptb.de' },
                         'what the last key exchange agreed on is not what the entry offers');

    });

    it('keeps another server\'s AEAD algorithm when one is saved', () => {

        const list = [ entryOf(shown('ptbtime1.ptb.de.', { aead: 'AES-SIV-CMAC-256' }), usual),
                       entryOf(shown('ptbtime2.ptb.de.'), usual) ];

        assert.deepEqual(withServer(list, 1, { hostname: 'ptbtime2.ptb.de', priority: 1 }),
                         [ { hostname: 'ptbtime1.ptb.de', aead: 'AES-SIV-CMAC-256' },
                           { hostname: 'ptbtime2.ptb.de', priority: 1 } ]);

    });

    it('keeps when its entry has its key exchange made again, or the next save takes it back to the defaults', () => {

        assert.deepEqual(entryOf(shown('ptbtime1.ptb.de.', { minRefreshSeconds: 3600, maxRefreshSeconds: 7200, nextExchange: '2026-11-07T12:00:00Z' }), usual),
                         { hostname: 'ptbtime1.ptb.de', minRefreshSeconds: 3600, maxRefreshSeconds: 7200 });

        assert.deepEqual(entryOf(shown('ptbtime1.ptb.de.', { minRefreshSeconds: null, maxRefreshSeconds: null, nextExchange: '2026-11-07T12:00:00Z' }), usual),
                         { hostname: 'ptbtime1.ptb.de' },
                         'when the next one is due is not what the entry sets');

    });

});


describe('a time server asked for signed responses', () => {

    it('is kept with its entry, or the next save stops asking', () => {

        assert.deepEqual(entryOf(shown('a.example.', { signedResponses: true  }), usual), { hostname: 'a.example', signedResponses: true });
        assert.deepEqual(entryOf(shown('a.example.', { signedResponses: false }), usual), { hostname: 'a.example' });

    });

});


describe('a time server whose key exchange goes over SSH', () => {

    const ssh = { port: 2222, user: 'station', hostKeyPins: [ 'SHA256:' + 'A'.repeat(43) ], onMismatch: 'record' as const };

    it('is kept with its entry, or the next save has it make its key exchange over TLS', () => {

        assert.deepEqual(entryOf(shown('time.lan.', { ssh }), usual), { hostname: 'time.lan', ssh });
        assert.deepEqual(entryOf(shown('time.lan.', { ssh: null }), usual), { hostname: 'time.lan' });

    });

    it('stays with a server when another one is saved', () => {

        const list = [ entryOf(shown('time.lan.', { ssh }), usual), entryOf(shown('b.example.'), usual) ];

        assert.deepEqual(withServer(list, 1, { hostname: 'b.example', priority: 2 })[0], { hostname: 'time.lan', ssh });

    });

    it('says where it goes and what it is held to', () => {

        assert.equal(sshText(ssh, 'time.lan.'),          'ssh://station@time.lan:2222');
        assert.equal(sshText({}, 'time.lan'),            'ssh://ntske@time.lan:22');

        assert.equal(sshHeldToText(ssh),                 `held to SHA256:${'A'.repeat(43)}, another one used and recorded`);
        assert.equal(sshHeldToText({ hostCAs: [ 'SHA256:ca' ] }), 'held to the CA SHA256:ca');
        assert.equal(sshHeldToText({}),                  'held to no host key: refused until it is');
        assert.equal(sshText({ useOCPPConnection: true }, 'csms.lan.'), 'the SSH connection of OCPP to csms.lan');
        assert.equal(sshHeldToText({ useOCPPConnection: true }),        'held to the host key OCPP holds it to');

    });

});


describe('a time server\'s key exchange server', () => {

    it('is kept with its entry, as people read it, or the next save takes it away', () => {

        assert.deepEqual(entryOf(shown('a.example.', { ntsKEHostname: 'ke.example.' }), usual),
                         { hostname: 'a.example', ntsKEHostname: 'ke.example' });

        assert.deepEqual(entryOf(shown('a.example.', { ntsKEHostname: null }), usual),
                         { hostname: 'a.example' });

    });

});


describe('how a time server\'s offsets are corrected', () => {

    it('is kept with its entry, or the next save takes it away', () => {

        assert.deepEqual(entryOf(shown('ptbtime1.ptb.de.', { delayAsymmetryMs: -0.05, delayVarAsymmetry: -0.5 }), usual),
                         { hostname: 'ptbtime1.ptb.de', delayAsymmetryMs: -0.05, delayVarAsymmetry: -0.5 });

        assert.deepEqual(entryOf(shown('ptbtime1.ptb.de.', { delayAsymmetryMs: null, delayVarAsymmetry: null }), usual),
                         { hostname: 'ptbtime1.ptb.de' });

    });

    it('is said as the node says it', () => {

        assert.equal(correctionText({}),                                                  null);
        assert.equal(correctionText({ delayAsymmetryMs: -0.05 }),                         'by -0.05 ms');
        assert.equal(correctionText({ delayVarAsymmetry: -0.5 }),                         'for an asymmetry of -0.5');
        assert.equal(correctionText({ delayAsymmetryMs: 1, delayVarAsymmetry: 0.25 }),    'by 1 ms and for an asymmetry of 0.25');

    });

});


describe('when a time server\'s key exchange is made again, as the page says it', () => {

    it('says the node\'s defaults where the entry sets nothing', () => {

        assert.equal(refreshSet({}), false);
        assert.equal(refreshText({}, { defaultMinRefresh: 43200, defaultMaxRefresh: 86400 }), '12 to 24 hours');

    });

    it('says what the entry sets, in the largest unit both fit', () => {

        assert.equal(refreshSet({ minRefreshSeconds: 5400 }), true);
        assert.equal(refreshText({ minRefreshSeconds: 3600, maxRefreshSeconds: 7200 }, {}), '1 to 2 hours');
        assert.equal(refreshText({ minRefreshSeconds: 5400, maxRefreshSeconds: 5400 }, {}), '90 minutes');
        assert.equal(refreshText({ minRefreshSeconds: 61,   maxRefreshSeconds: 120  }, {}), '61 to 120 seconds');

    });

    it('takes the default for what the entry leaves out, but never a latest before the earliest', () => {

        assert.equal(refreshText({ minRefreshSeconds: 3600 },          {}), '1 to 24 hours');
        assert.equal(refreshText({ minRefreshSeconds: 172800 },        {}), '48 hours');
        assert.equal(refreshText({ maxRefreshSeconds: 7200 },          {}), '2 hours');
        assert.equal(refreshText({ maxRefreshSeconds: 129600 },        {}), '12 to 36 hours');

    });

});


describe('what a time server is held to', () => {

    it('goes back into its entry, or the next save of any server holds it to nothing', () => {

        // What a node said of ptbtime1.ptb.de once it had learned
        // its root on first use, as it said it.
        const learned: ServerPins = { certificate: null, root, certificates: [], roots: [ root ], onMismatch: 'refuse', trustOnFirstUse: 'root' };

        assert.deepEqual(entryOf(shown('ptbtime1.ptb.de.', { heldTo: learned }), usual),
                         { hostname: 'ptbtime1.ptb.de', rootFingerprint: root, trustOnFirstUse: 'root' });

    });

    it('is written the way the file writes it: one under the name a pin always had, several as a list', () => {

        assert.deepEqual(entryOf(shown('time.example.', { heldTo: heldTo({ certificate: certificate1, root, certificates: [ certificate1, certificate2 ], roots: [ root ] }) }), usual),
                         { hostname: 'time.example', certificateFingerprints: [ certificate1, certificate2 ], rootFingerprint: root });

    });

    it('says what a mismatch comes to only where it is not a refusal, which is what a pin means anyway', () => {

        assert.deepEqual(entryOf(shown('time.example.', { heldTo: heldTo({ certificate: certificate1, certificates: [ certificate1 ], onMismatch: 'record' }) }), usual),
                         { hostname: 'time.example', certificateFingerprint: certificate1, onMismatch: 'record' });

    });

    it('is nothing at all for a server held to nothing', () => {

        assert.deepEqual(entryOf(shown('ptbtime2.ptb.de.', { heldTo: null }), usual),
                         { hostname: 'ptbtime2.ptb.de' });

    });

    it('stays with a server when another one is saved', () => {

        // What was measured: the dialog of ptbtime2.ptb.de, its priority
        // changed to 1, took the root ptbtime1.ptb.de had learned out of the
        // file and out of effect - and the instruction to learn it.
        const list = [ entryOf(shown('ptbtime1.ptb.de.', { heldTo: heldTo({ root, roots: [ root ], trustOnFirstUse: 'root' }) }), usual),
                       entryOf(shown('ptbtime2.ptb.de.'), usual) ];

        assert.deepEqual(withServer(list, 1, { hostname: 'ptbtime2.ptb.de', priority: 1 }),
                         [ { hostname: 'ptbtime1.ptb.de', rootFingerprint: root, trustOnFirstUse: 'root' },
                           { hostname: 'ptbtime2.ptb.de', priority: 1 } ]);

    });

    it('stays with every other server when one is deleted, and with the one that is edited', () => {

        // The EV's: the delete of one server is the list without it, told to
        // the node as a whole - and so is an edit of one held to a certificate.
        const list = [ entryOf(shown('ptbtime1.ptb.de.', { heldTo: heldTo({ root, roots: [ root ], trustOnFirstUse: 'root' }) }), usual),
                       entryOf(shown('ptbtime2.ptb.de.', { heldTo: heldTo({ certificate: certificate1, certificates: [ certificate1 ] }) }), usual) ];

        assert.deepEqual(withoutServer(list, 1),
                         [ { hostname: 'ptbtime1.ptb.de', rootFingerprint: root, trustOnFirstUse: 'root' } ]);

        assert.deepEqual(withServer(list, 1, { ...list[1]!, priority: 1 }),
                         [ { hostname: 'ptbtime1.ptb.de', rootFingerprint: root, trustOnFirstUse: 'root' },
                           { hostname: 'ptbtime2.ptb.de', certificateFingerprint: certificate1, priority: 1 } ]);

    });

    it('is not the certificate a server last showed', () => {

        // The meter's: what a key exchange showed is what a pin is written
        // down from, and not a pin until somebody writes it down.
        assert.deepEqual(entryOf(shown('ptbtime3.ptb.de.', { heldTo: null, certificate: certificate2 }), usual),
                         { hostname: 'ptbtime3.ptb.de' });

    });

});


describe('a time server sent back', () => {

    it('goes with what the page showed it held to, so that a root it learned while the page was open is kept', () => {

        // What was measured: ptbtime1.ptb.de learned its root on first use
        // after the page was loaded, and the save of another server's
        // priority took it out of the file and out of effect. The entry says
        // what it is held to as the page shows it; beside it, what the page
        // showed, from which the node can tell that the root was
        // not taken away here.
        assert.deepEqual(sentOf(shown('ptbtime1.ptb.de.', { heldTo: heldTo({ trustOnFirstUse: 'root' }) }), usual),
                         { hostname: 'ptbtime1.ptb.de', trustOnFirstUse: 'root', pinsAsShown: { trustOnFirstUse: 'root' } });

    });

    it('says a server shown held to nothing was shown so', () => {

        assert.deepEqual(sentOf(shown('ptbtime2.ptb.de.', { heldTo: null }), usual),
                         { hostname: 'ptbtime2.ptb.de', pinsAsShown: {} });

    });

    it('keeps the group of roots it is held to, and says it was shown so - or the next save of any server takes it away', () => {

        assert.deepEqual(sentOf(shown('ptbtime1.ptb.de.', { heldTo: heldTo({ rootGroup: 'legalCA' }) }), usual),
                         { hostname: 'ptbtime1.ptb.de', rootGroup: 'legalCA', pinsAsShown: { rootGroup: 'legalCA' } });

    });

    it('is what the NTS page sends every server of its list as', () => {

        const page = readFileSync(new URL('./nts.ts', import.meta.url), 'utf-8');

        assert.match(page, /\.map\(source => sentOf\(source, usual\)\)/,
                     'the NTS page sends its list without what it showed each server held to');

    });

});


describe('the entry the dialog saves', () => {

    // Asked of the page's source, as Node has no browser to open it in, and
    // the views it draws with cannot be loaded here: the dialog's own entry,
    // sent as it was typed, is what took the pins.
    const page = readFileSync(new URL('./nts.ts', import.meta.url), 'utf-8');

    it('shows what the server is held to, in fields of its own', () => {

        assert.match(page, /pinsFieldset\(draftOf\(shown\?\.heldTo\), \{/,
                     'the NTS dialog does not show what the server it edits is held to');

    });

    it('is saved with what those fields say - under the same name or another, where it is to be seen and emptied', () => {

        assert.match(page, /const pins = readPinsFieldset\(form\);/,
                     'the NTS dialog does not read what its pin fields say');

        assert.match(page, /withServer\(list, index, withPins\(entry, pins\.draft\)\)/,
                     'the NTS dialog saves a server without what its pin fields say');

    });

    it('goes with what the dialog showed the server held to, where it edits one the page loaded', () => {

        assert.match(page, /if \(shown !== null\)\s+entry\.pinsAsShown = asShown\(shown\.heldTo\);/,
                     'the NTS dialog saves a server without what it showed it held to');

    });

});


describe('the list a change sends', () => {

    const list = [ { hostname: 'a.example' }, { hostname: 'b.example' }, { hostname: 'c.example' } ];

    it('replaces exactly the one that was edited', () => {

        assert.deepEqual(withServer(list, 1, { hostname: 'b.example', enabled: false }),
                         [ { hostname: 'a.example' }, { hostname: 'b.example', enabled: false }, { hostname: 'c.example' } ]);

    });

    it('adds a new one at the end', () => {

        assert.deepEqual(withServer(list, null, { hostname: 'd.example' }).map(entry => entry.hostname),
                         [ 'a.example', 'b.example', 'c.example', 'd.example' ]);

    });

    it('leaves out exactly the one that was deleted', () => {

        assert.deepEqual(withoutServer(list, 0).map(entry => entry.hostname),
                         [ 'b.example', 'c.example' ]);

    });

    it('keeps the ids of the servers left, which the node would give anew by their places', () => {

        const shownList = [ shown('a.example.', { id: 'legal-1' }), shown('b.example.', { id: 'legal-2' }), shown('c.example.', { id: 'legal-3' }) ];

        assert.deepEqual(withoutServer(shownList.map(source => sentOf(source, usual)), 0).map(entry => entry.id),
                         [ 'legal-2', 'legal-3' ],
                         'given anew, b.example would be "legal-1", and to a CSMS the server it knew as "legal-1" would have a new host name');

    });

    it('leaves the list it was made from alone, which is what the page goes back to when the node says no', () => {

        withServer(list, 0, { hostname: 'x.example' });
        withoutServer(list, 2);

        assert.deepEqual(list.map(entry => entry.hostname), [ 'a.example', 'b.example', 'c.example' ]);

    });

});


describe('a name that is already taken', () => {

    const list = [ { hostname: 'ptbtime1.ptb.de' }, { hostname: 'ptbtime2.ptb.de' } ];

    it('is taken whatever its case and its root dot', () => {

        assert.equal(nameTaken(list, 'PTBTIME2.ptb.de.', null), true);

    });

    it('is not taken by the server being edited itself, or it could not be saved unchanged', () => {

        assert.equal(nameTaken(list, 'ptbtime2.ptb.de', 1), false);

    });

    it('is read without the root dot', () => {

        assert.equal(readable('ptbtime1.ptb.de.'), 'ptbtime1.ptb.de');
        assert.equal(readable('ptbtime1.ptb.de'),  'ptbtime1.ptb.de');

    });

});
