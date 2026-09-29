/**
 * What the certificates page says about one certificate without a browser:
 * its state, and what the node has chosen it for - and, asked of its source,
 * that a change of one certificate leaves an import being filled in alone.
 */

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';

import type { Certificate }  from '../api/client.ts';

(globalThis as unknown as { document: unknown }).document = {
    querySelector: (selector: string) => selector === 'meta[name="node-name"]' ? { content: 'local controller' } : null
};

const { marksOf, stateOf } = await import('./certificates.ts');


const now  = Date.parse('2026-09-29T12:00:00Z');
const days = (Days: number) => new Date(now + Days * 86400000).toISOString();

const certificate = (Changes: Partial<Certificate> = {}): Certificate => ({
    id:            '0123456789abcdef',
    kind:          'tlsIdentity',
    label:         'lc001',
    subject:       'CN=lc001',
    thumbprint:    '0123456789abcdef'.repeat(4),
    keyAlgorithm:  'ECDSA P-256',
    hasPrivateKey: true,
    chainLength:   0,
    notAfter:      days(365),
    active:        true,
    expired:       false,
    notYetValid:   false,
    ...Changes
} as Certificate);


describe('the state of a certificate', () => {

    it('is "on" while it is in force and far from its end', () => {
        assert.deepEqual(stateOf(certificate(), 30, now), { text: 'on', tone: '' });
    });

    it('warns how many days are left once they are few', () => {
        assert.deepEqual(stateOf(certificate({ notAfter: days(12.5) }), 30, now), { text: '12 day(s) left', tone: 'warn' });
        assert.deepEqual(stateOf(certificate({ notAfter: days(12.5) }), 7,  now), { text: 'on',             tone: ''     });
    });

    it('says switched off, not yet valid and expired - the worst of them first', () => {
        assert.deepEqual(stateOf(certificate({ active: false }),                   30, now), { text: 'switched off',  tone: ''     });
        assert.deepEqual(stateOf(certificate({ notYetValid: true, active: false }), 30, now), { text: 'not yet valid', tone: 'warn' });
        assert.deepEqual(stateOf(certificate({ expired: true, notYetValid: true }), 30, now), { text: 'expired',       tone: 'bad'  });
    });

});


describe('what the node has chosen a certificate for', () => {

    const chosen = { csmsClientCertificate: '0123456789abcdef', vehicleCertificate: null };

    it('is said in the words of the kind of node', () => {
        assert.deepEqual(marksOf(certificate(), chosen, { csmsClientCertificate: { label: 'signs in to the CSMS', title: 'Chosen on the CSMS page' } }),
                         [ { label: 'signs in to the CSMS', title: 'Chosen on the CSMS page' } ]);
    });

    it('is said in the node\'s own name where the kind has no words for it', () => {
        assert.deepEqual(marksOf(certificate(), chosen),
                         [ { label: 'CSMS client certificate', title: 'Chosen by this local controller; deleted only once another one is' } ]);
    });

    it('is nothing for a certificate nothing has chosen, or where nothing is chosen at all', () => {
        assert.deepEqual(marksOf(certificate({ id: 'fedcba9876543210' }), chosen), []);
        assert.deepEqual(marksOf(certificate(), undefined), []);
    });

});


describe('a change of one certificate', () => {

    const source = readFileSync(new URL('./certificates.ts', import.meta.url), 'utf-8');

    it('redraws the store\'s cards and not the import above them, which may be half filled in', () => {

        const change = source.slice(source.indexOf('async function change('), source.indexOf('async function reloadKinds('));

        assert.doesNotMatch(change, /\bdraw\(\)/, 'a change of one certificate draws the whole page, the import with it');
        assert.match       (change, /reloadKinds\(\)/);

    });

    it('says a refusal on the card of that certificate\'s kind, where the button was', () => {
        assert.match(source, /data-error-of="\$\{kind\}"/);
        assert.match(source, /scrollIntoView\(/);
    });

    it('leaves what was chosen and typed for an import where it was when the import is refused', () => {

        const refused = source.slice(source.indexOf('async function doImport('), source.indexOf('async function toggle('));
        const caught  = refused.slice(refused.indexOf('catch (problem)'), refused.indexOf('if (cancelled)'));

        assert.doesNotMatch(caught, /\bdraw\(\)/, 'a refused import draws the page again, and the form is empty');

    });

});
