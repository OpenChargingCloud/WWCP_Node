/**
 * The server keys on the "Server identities" page, drawn in a document of
 * happy-dom against a node that is a stand-in for fetch: the key pins of the
 * current and the next key, a listener offered its first key, the next key
 * announced, and the switch that names the next key's pin - and nothing to
 * press for whoever may only read.
 */

import '../test/dom.ts';
import type { Asked } from '../test/node.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { CertificateStore, ListenerServerKeys, ServerKey } from './api/client.ts';

document.head.innerHTML = '<meta name="node-name" content="gateway">';

const { asked, open, until } = await import('../test/node.ts');

const { serverIdentitiesPage }       = await import('./pages/certificates.ts');
const { groupedKeyPin, shownText }   = await import('./serverKeys.ts');


const pinA = 'a1'.repeat(32);
const pinB = 'b2'.repeat(32);

const aKey = (KeyPin: string, State: ServerKey['state']): ServerKey => ({
    id:            KeyPin.slice(0, 16),
    keyPin:        KeyPin,
    keyPinCurl:    'sha256//' + KeyPin.slice(0, 8),
    algorithm:     'ecdsa-p256',
    createdAt:     '2026-11-18T10:00:00Z',
    state:         State,
    currentSince:  State === 'current' ? '2026-11-18T10:00:00Z' : null,
    carrier:       null,
    issued:        []
});

const aStore = (): CertificateStore => ({
    directory:     'certs',
    trustAnchors:  [],
    credentials:   [ 'tlsServerIdentity' ],
    recognised:    [],
    kinds:         { tlsServerIdentity: { description: 'TLS server identities', withArticle: 'a TLS server identity', group: 'credential', page: 'serverIdentities', usages: [ 'web' ], needsPrivateKey: true } },
    usages:        [],
    certificates:  { tlsServerIdentity: [] }
} as unknown as CertificateStore);


describe('what the server keys say', () => {

    it('reads a key pin out in groups of eight', () => {
        assert.equal(groupedKeyPin('0123456789abcdef0123456789abcdef'), '01234567 89abcdef 01234567 89abcdef');
    });

    it('says what a listener shows: nothing, a carrier, or one kept on', () => {
        const keys: ListenerServerKeys = { listener: 'ocpp', keepsServingLast: true, current: null, next: null, shown: null, keys: [] };
        assert.match(shownText(keys), /refused/);
        assert.match(shownText({ ...keys, shown: { id: 'x', label: 'Key pin carrier x', presentedAs: 'carrier',     keptOn: false } }), /carrier of its current key/);
        assert.match(shownText({ ...keys, shown: { id: 'y', label: 'gw.example.org',    presentedAs: 'certificate', keptOn: true  } }), /not valid/);
    });

});


describe('the server keys on the "Server identities" page', () => {

    /** What the stand-in holds of the listener "ocpp". */
    let ocpp: ListenerServerKeys | null = null;

    function node({ method, path, body }: Asked): unknown {

        if (method === 'GET' && path === '/certificates')
            return aStore();

        if (method === 'GET' && path === '/certificates/serverKeys')
            return { listeners: ocpp === null ? [] : [ ocpp ] };

        if (method === 'POST' && path === '/certificates/serverKeys/ocpp') {
            const asNext = (body as { asNext?: boolean }).asNext === true;
            ocpp = asNext
                       ? { ...ocpp!, next: pinB, keys: [ aKey(pinB, 'next'), ...ocpp!.keys ] }
                       : { listener: 'ocpp', keepsServingLast: true, current: pinA, next: null,
                           shown: { id: 'c'.repeat(16), label: 'Key pin carrier a1a1a1a1', presentedAs: 'carrier', keptOn: false },
                           keys: [ aKey(pinA, 'current') ] };
            return { key: ocpp.keys[0], serverKeys: ocpp };
        }

        if (method === 'POST' && path === '/certificates/serverKeys/ocpp/switch') {
            ocpp = { ...ocpp!, current: pinB, next: null, keys: [ aKey(pinB, 'current'), aKey(pinA, 'former') ] };
            return { key: ocpp.keys[0], before: pinA, serverKeys: ocpp };
        }

        return undefined;

    }

    const opened = (permissions: string[], listeners: string[] = [ 'ocpp' ]) =>
        open(serverIdentitiesPage({ serverKeyListeners: listeners, usageNames: { ocpp: 'the station port' } }),
             '/configuration/server-identities', permissions, node,
             root => root.querySelector('#kinds') !== null || root.querySelector('.error-box') !== null);

    const card = (root: HTMLElement) => root.querySelector<HTMLElement>('[data-server-keys="ocpp"]');

    it('offers a listener of the kind its first key, announces the next, and switches to the pin it shows', async () => {

        ocpp = null;

        const root = await opened([ 'certificates:read', 'certificates:edit' ]);

        assert.ok(card(root) !== null, 'the listener the kind offers has no card');
        assert.match(card(root)!.querySelector('h2')!.textContent!, /the station port/);

        card(root)!.querySelector<HTMLButtonElement>('[data-make-server-key]')!.click();
        await until(() => card(root)?.querySelector('[data-current-pin]') !== null, 'the key that was made is not shown');

        assert.equal(card(root)!.querySelector('[data-current-pin]')!.textContent, groupedKeyPin(pinA));
        assert.match(card(root)!.querySelector('[data-shown]')!.textContent!, /carrier/);

        card(root)!.querySelector<HTMLButtonElement>('[data-announce-next-key]')!.click();
        await until(() => card(root)?.querySelector('[data-next-pin]') !== null, 'the next key is not shown');

        assert.deepEqual(asked.filter(one => one.method === 'POST').map(one => one.body), [ {}, { asNext: true } ]);
        assert.equal(card(root)!.querySelectorAll('[data-server-key]').length, 2);

        card(root)!.querySelector<HTMLButtonElement>('[data-switch-to-next-key]')!.click();
        await until(() => card(root)?.querySelector('[data-next-pin]') === null, 'the switch is not shown');

        const switched = asked.find(one => one.path.endsWith('/switch'))!;

        assert.deepEqual(switched.body, { ifNextKeyPinIs: pinB }, 'the switch does not name the pin the page showed');
        assert.equal(card(root)!.querySelector('[data-current-pin]')!.textContent, groupedKeyPin(pinB));
        assert.equal(card(root)!.querySelector('[data-server-key][data-state="former"]')?.getAttribute('data-server-key'), pinA.slice(0, 16));

    });

    it('lets whoever may only read see the key pins and press nothing', async () => {

        ocpp = { listener: 'ocpp', keepsServingLast: false, current: pinA, next: pinB, shown: null,
                 keys: [ aKey(pinB, 'next'), aKey(pinA, 'current') ] };

        const root   = await opened([ 'certificates:read' ]);
        const button = card(root)!.querySelector<HTMLButtonElement>('[data-switch-to-next-key]')!;

        assert.equal(card(root)!.querySelector('[data-next-pin]')!.textContent, groupedKeyPin(pinB));
        assert.ok(button.disabled, 'a reader may switch');

    });

    it('shows no card where no listener has a key and the kind offers none', async () => {

        ocpp = null;

        const root = await opened([ 'certificates:read', 'certificates:edit' ], []);

        assert.equal(card(root), null);
        assert.match(root.querySelector('#kinds')!.textContent!, /TLS server identities|keeps nothing/);

    });

});
