/**
 * What the certificates page says about one certificate: its state, and what
 * the node has chosen it for - and, drawn in a document of happy-dom against a
 * node that is a stand-in for fetch, that a change of one certificate leaves
 * an import being filled in alone, and that an import that went through
 * leaves an empty one.
 */

import '../../test/dom.ts';

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';

import type { Certificate, CertificateStore } from '../api/client.ts';

document.head.innerHTML = '<meta name="node-name" content="local controller">';

const { believedHint, certificatesPage, marksOf, stateOf } = await import('./certificates.ts');
const { auth }             = await import('../auth.ts');
const { configureShell }   = await import('../shell.ts');


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


describe('what a node believes, where its kind says nothing of its own', () => {

    it('is said of every kind of root, not of the servers it connects to alone', () => {

        const said = believedHint('electric vehicle', [ 'v2gRoot', 'moRoot', 'oemRoot' ]).value;

        assert.match(said, /the roots a certificate shown to this electric vehicle has to chain to/);
        assert.doesNotMatch(said, /server|this machine/, 'a vehicle\'s V2G, contract and OEM roots are no server\'s');

    });

    it('says that a server may chain to what this machine trusts as well, where there are TLS roots', () => {
        assert.match(believedHint('local controller', [ 'tlsRoot', 'clientRoot' ]).value,
                     /A server's certificate may chain to the roots this machine trusts as well\./);
    });

});


describe('a change of one certificate', () => {

    const source = readFileSync(new URL('./certificates.ts', import.meta.url), 'utf-8');

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


describe('the certificates page, drawn', () => {

    let held:     CertificateStore;
    let refuse  = false;
    const asked = [] as string[];

    const aRoot = certificate({ id: 'aaaaaaaaaaaaaaaa', kind: 'tlsRoot', label: 'Root A', hasPrivateKey: false });

    const aStore = (): CertificateStore => ({
        directory:           'certs',
        trustAnchors:        [ 'tlsRoot' ],
        credentials:         [ 'tlsIdentity' ],
        recognised:          [],
        kinds:               { tlsRoot:      { description: 'TLS roots',    usages: [ 'dns', 'nts' ] },
                               tlsIdentity:  { description: 'TLS identity', usages: [ 'modbus', 'web' ] } },
        usages:              [],
        certificates:        { tlsRoot: [ { ...aRoot } ], tlsIdentity: [] },
        keysAreUnencrypted:  false
    } as unknown as CertificateStore);

    const answer = (body: unknown, status = 200) =>
        new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {

        const url    = String(input);
        const method = init?.method ?? 'GET';

        asked.push(`${method} ${url.replace(/^.*\/api\/v1/, '')}`);

        if (method === 'PATCH') {
            const entry = held.certificates['tlsRoot']![0]!;
            entry.active = JSON.parse(String(init!.body)).active ?? entry.active;
            return answer(entry);
        }

        if (method === 'POST' && url.endsWith('/certificates')) {
            if (refuse)
                return answer({ description: 'That is no certificate.' }, 400);
            const imported = certificate({ id: 'bbbbbbbbbbbbbbbb', kind: 'tlsRoot', label: 'Root B', hasPrivateKey: false });
            held.certificates['tlsRoot']!.push(imported);
            return answer(imported);
        }

        if (url.endsWith('/certificates'))
            return answer(held);

        return answer({}, 404);

    }) as typeof fetch;

    const wait = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));

    async function until(what: () => boolean, said: string): Promise<void> {
        for (let i = 0; i < 200 && !what(); i++)
            await wait(5);
        assert.ok(what(), said);
    }

    async function opened(): Promise<HTMLElement> {

        held         = aStore();
        refuse       = false;
        asked.length = 0;

        configureShell({ name: 'Test node', icon: 'fa-gear', menu: [] });
        auth.set({ username: 'alice', roles: [ 'admin' ], permissions: [ 'certificates:read', 'certificates:edit' ], mayReadTheLog: false } as never);

        const root = document.createElement('div');
        document.body.replaceChildren(root);

        certificatesPage().render({ root, url: new URL('http://127.0.0.1/configuration/certificates'), params: {}, navigate: () => undefined } as never);

        await until(() => root.querySelector('#import-form') !== null, 'the page did not draw its import');

        return root;

    }

    const label = (root: HTMLElement) => root.querySelector<HTMLInputElement>('#import-form [name="label"]')!;
    const kind  = (root: HTMLElement) => root.querySelector<HTMLSelectElement>('#import-kind')!;

    function choose(root: HTMLElement, value: string): void {
        kind(root).value = value;
        kind(root).dispatchEvent(new Event('change', { bubbles: true }));
    }

    function aFile(root: HTMLElement): void {
        Object.defineProperty(root.querySelector('#import-file'), 'files',
                              { value: [ new File([ '-----BEGIN CERTIFICATE-----' ], 'root-b.pem') ], configurable: true });
    }

    const submit = (root: HTMLElement) =>
        root.querySelector<HTMLFormElement>('#import-form')!.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));


    it('keeps what is typed into the import, and the kind chosen, while a certificate below it is switched off', async () => {

        const root = await opened();

        choose(root, 'tlsIdentity');
        const typed = label(root);
        typed.value = 'half filled in';
        typed.focus();

        root.querySelector<HTMLButtonElement>('[data-toggle="aaaaaaaaaaaaaaaa"]')!.click();
        await until(() => root.querySelector('[data-toggle="aaaaaaaaaaaaaaaa"]')?.textContent?.trim() === 'Switch on',
                    'the certificate was not switched off');

        assert.equal(label(root),            typed,            'the field was made anew');
        assert.equal(typed.value,            'half filled in', 'what was typed into the import is gone');
        assert.equal(kind(root).value,       'tlsIdentity',    'the kind chosen for the import is gone');
        assert.equal(document.activeElement, typed,            'the focus went');

    });

    it('offers the usages of the kind chosen, and only its own', async () => {

        const root = await opened();

        const box = (value: string) => root.querySelector<HTMLInputElement>(`#import-usages [value="${value}"]`);

        assert.equal(root.querySelector<HTMLElement>('#import-usages')!.hidden, false, 'a root is told what it is kept for');
        box('dns')!.checked = true;

        choose(root, 'tlsIdentity');
        await wait();
        assert.equal(box('dns'),               null,  'a root\'s usage is offered for an identity');
        assert.equal(box('modbus')!.checked,   false, 'the tick for a root\'s first usage went to the identity\'s first');

        choose(root, 'tlsRoot');
        await wait();
        assert.equal(box('dns')!.checked,      false, 'a usage ticked before another kind was chosen came back ticked');

    });

    it('is an empty import again once an import went through, of the first kind', async () => {

        const root = await opened();

        choose(root, 'tlsIdentity');
        choose(root, 'tlsRoot');
        aFile(root);
        label(root).value = 'Root B';

        submit(root);
        await until(() => (root.querySelector('#import-note')?.textContent ?? '').startsWith('Imported'), 'the import did not go through');

        assert.equal(label(root).value,  '',        'what was typed for the import that went through is still there');
        assert.equal(kind(root).value,   'tlsRoot');
        assert.equal(root.querySelectorAll('[data-toggle]').length, 2, 'the certificate imported is not in the list');

    });

    it('keeps what was chosen and typed for an import the node refused', async () => {

        const root = await opened();

        choose(root, 'tlsIdentity');
        aFile(root);
        label(root).value = 'mistyped';
        refuse = true;

        submit(root);
        await until(() => (root.querySelector('#import-error')?.textContent ?? '') !== '', 'the refusal was not said');

        assert.equal(label(root).value, 'mistyped');
        assert.equal(kind(root).value,  'tlsIdentity');

    });

});
