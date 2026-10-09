/**
 * What the certificates page offers a certificate to be told it is for, asked
 * directly.
 *
 * Run with `npm test`. What is pinned is what was wrong: one list for every
 * kind, so that a TLS identity was offered the services a TLS root vouches
 * for - which the store refuses, and which mean nothing for an identity. The
 * EV's test, as five of the kinds had it.
 */

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { CertificateStore } from '../api/client';
import { hasUsages, usageName, usagesOf } from './certificateUsages.ts';


/** A store as most nodes describe it: its TLS roots and server certificates for services, its identities for no listener. */
const store = {
    usages: [ 'dns', 'nts' ],
    kinds: {
        tlsRoot:      { description: '', trustAnchor: true,  needsPrivateKey: false, hasUsages: true,  usages: [ 'dns', 'nts' ] },
        tlsServer:    { description: '', trustAnchor: false, needsPrivateKey: false, hasUsages: true,  usages: [ 'dns', 'nts' ] },
        tlsIdentity:  { description: '', trustAnchor: false, needsPrivateKey: true,  hasUsages: false, usages: [] },
        v2gRoot:      { description: '', trustAnchor: true,  needsPrivateKey: false, hasUsages: false, usages: [] }
    }
} as unknown as CertificateStore;


describe('what a kind may be told it is for', () => {

    it('is what the store says of that kind', () => {
        assert.deepEqual(usagesOf(store, 'tlsRoot'),   [ 'dns', 'nts' ]);
        assert.deepEqual(usagesOf(store, 'tlsServer'), [ 'dns', 'nts' ]);
    });

    it('is nothing for an identity that names no listener - not the services a root vouches for', () => {
        assert.deepEqual(usagesOf(store, 'tlsIdentity'), []);
        assert.equal(hasUsages(store, 'tlsIdentity'), false);
    });

    it('is the listeners for a server identity where a kind of node names some - not the services a root vouches for', () => {

        // The one case that tells what a kind says from what the store says
        // once for all of them: in most stores the two lists are the same,
        // and the page that offered the store's list for every kind passed
        // every other case here.
        const meter = { usages: [ 'dns', 'nts' ],
                        kinds:  { tlsServerIdentity: { description: '', trustAnchor: false, needsPrivateKey: true, hasUsages: true, usages: [ 'modbus', 'web' ] } } } as unknown as CertificateStore;

        assert.deepEqual(usagesOf(meter, 'tlsServerIdentity'), [ 'modbus', 'web' ]);

    });

    it('is nothing for a kind that is for what its kind says, and for a kind the store does not keep', () => {
        assert.deepEqual(usagesOf(store, 'v2gRoot'), []);
        assert.equal(hasUsages(store, 'v2gRoot'), false);
        assert.deepEqual(usagesOf(store, 'nothingOfTheKind'), []);
    });

    it('is called what the pages it is set on call it, or what the kind of node calls it', () => {
        assert.equal(usageName('dns'),                              'name servers (DNS)');
        assert.equal(usageName('web'),                              'web');
        assert.equal(usageName('web', { web: 'the web interface' }), 'the web interface');
    });

});
