/**
 * What the certificates page says about one certificate: its state, and what
 * the node has chosen it for - and, drawn in a document of happy-dom against a
 * node that is a stand-in for fetch, that a change of one certificate leaves
 * an import being filled in alone, and that an import that went through
 * leaves an empty one.
 */

import { chromeTakesTheFocus } from '../../test/dom.ts';
import type { Asked }           from '../../test/node.ts';

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';

import type { Certificate, CertificateStore } from '../api/client.ts';

// What the node writes into the page it serves, read as the modules load - the
// stand-in's among them, which load config.ts too.
document.head.innerHTML = '<meta name="node-name" content="local controller">';

const { asked, open, refused, said, type, until } = await import('../../test/node.ts');

const { believedHint, certificatesOf, certificatesPage, fingerprintOf, identitiesPage, marksOf,
        pageOf, serverCertificatesPage, stateOf, withoutPrivateKeys } = await import('./certificates.ts');
const { html, render }     = await import('../view.ts');

/** What a template says, drawn as text: the blanks of its markup taken together. */
function textOf(template: Parameters<typeof render>[1]): string {
    const element = document.createElement('div');
    render(element, template);
    return element.textContent!.replace(/\s+/g, ' ').trim();
}
const { unsaved }          = await import('../unsaved.ts');


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

    it('is said of the kind it was chosen as alone, where the node names the kind', () => {

        const asContract = { contractCertificate: { id: '0123456789abcdef', kind: 'contract' } };

        assert.equal(marksOf(certificate({ kind: 'contract' }), asContract).length, 1);
        assert.deepEqual(marksOf(certificate({ kind: 'vehicle' }), asContract), [], 'the same certificate kept as another kind');

    });

});


describe('what a node believes, where its kind says nothing of its own', () => {

    it('is said of every kind of root, not of the servers it connects to alone', () => {

        const said = textOf(believedHint('electric vehicle', [ 'v2gRoot', 'moRoot', 'oemRoot' ]));

        assert.match(said, /the roots a certificate shown to this electric vehicle has to chain to/);
        assert.doesNotMatch(said, /server|this machine/, 'a vehicle\'s V2G, contract and OEM roots are no server\'s');

    });

    it('says that a server may chain to what this machine trusts as well, where there are TLS roots', () => {
        assert.match(textOf(believedHint('local controller', [ 'tlsRoot', 'clientRoot' ])),
                     /A server's certificate may chain to the roots this machine trusts as well\./);
    });

});


describe('a change of one certificate', () => {

    const source = readFileSync(new URL('./certificates.ts', import.meta.url), 'utf-8');

    it('says a refusal where the button was', () => {
        assert.match(source, /data-error-of="\$\{kind\}"/);
        assert.match(source, /data-error-of-certificate="\$\{id\}"/);
        assert.match(source, /scrollIntoView\(/);
    });

    it('leaves what was pasted, ticked and typed for an upload where it was when the upload is refused', () => {

        const refused = source.slice(source.indexOf('async function doUpload('), source.indexOf('async function toggle('));
        const caught  = refused.slice(refused.indexOf('catch (problem)'), refused.indexOf('if (cancelled)'));

        assert.ok(refused.length > 0 && caught.length > 0, 'doUpload is not where it was');
        assert.doesNotMatch(caught, /box\.value\s*=|form\.reset\(\)/, 'a refused upload empties the box');

    });

});


describe('every certificate once', () => {

    const entry = (Changes: Partial<Certificate>) => certificate({ hasPrivateKey: false, ...Changes });

    const store = {
        trustAnchors:  [ 'tlsRoot', 'clientRoot' ],
        credentials:   [ 'tlsIdentity' ],
        recognised:    [],
        certificates:  {
            tlsRoot:      [ entry({ id: '2222222222222222', kind: 'tlsRoot',    label: 'beta CA',  thumbprint: '22'.repeat(32) }),
                            entry({ id: '1111111111111111', kind: 'tlsRoot',    label: 'Zulu CA',  thumbprint: '11'.repeat(32) }) ],
            clientRoot:   [ entry({ id: '2222222222222222', kind: 'clientRoot', label: 'beta CA',  thumbprint: '22'.repeat(32) }) ],
            tlsIdentity:  [ entry({ id: '3333333333333333', kind: 'tlsIdentity', label: 'Alpha',   thumbprint: '33'.repeat(32), subject: 'CN=alpha.example' }) ]
        }
    } as unknown as CertificateStore;

    it('is one certificate with every kind it is kept as, by name in any case', () => {

        const all = certificatesOf(store);

        assert.deepEqual(all.map(one => one.entries[0]!.label), [ 'Alpha', 'beta CA', 'Zulu CA' ]);
        assert.deepEqual(all[1]!.entries.map(one => one.kind), [ 'tlsRoot', 'clientRoot' ], 'in the order the kinds are shown');

    });

    it('is by fingerprint where that is asked, and narrowed down by name, subject, fingerprint or kind', () => {

        assert.deepEqual(certificatesOf(store, 'fingerprint').map(one => one.id), [ '1111111111111111', '2222222222222222', '3333333333333333' ]);
        assert.deepEqual(certificatesOf(store, 'name', 'ALPHA.example').map(one => one.id), [ '3333333333333333' ]);
        assert.deepEqual(certificatesOf(store, 'name', 'clientroot').map(one => one.id),   [ '2222222222222222' ]);
        assert.deepEqual(certificatesOf(store, 'name', '1111').map(one => one.id),         [ '1111111111111111' ]);

    });

    it('writes a fingerprint as people compare it', () => {
        assert.equal(fingerprintOf('0a1b2c'), '0A:1B:2C');
    });

});


describe('which page a kind is looked after on', () => {

    const store = { kinds: { tlsRoot:            { page: 'certificates' },
                             tlsServerIdentity:  { page: 'serverCertificates', needsPrivateKey: true },
                             vehicle:            { needsPrivateKey: true },
                             tariffVerification: { needsPrivateKey: false } } } as unknown as CertificateStore;

    it('is the page the store says, or by whether one of it carries its private key', () => {
        assert.equal(pageOf(store, 'tlsRoot'),            'certificates');
        assert.equal(pageOf(store, 'tlsServerIdentity'),  'serverCertificates');
        assert.equal(pageOf(store, 'vehicle'),            'identities');
        assert.equal(pageOf(store, 'tariffVerification'), 'certificates');
        assert.equal(pageOf(store, 'unknown'),            'certificates');
    });

    it('sends a text to the certificates without its private keys, of whatever kind', () => {
        const certificate = '-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----';
        assert.equal(withoutPrivateKeys(`${certificate}\n-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n` +
                                        `-----BEGIN EC PRIVATE KEY-----\nE\n-----END EC PRIVATE KEY-----\n` +
                                        `-----BEGIN ENCRYPTED PRIVATE KEY-----\nX\n-----END ENCRYPTED PRIVATE KEY-----\n${certificate}\n`),
                     `${certificate}\n${certificate}`);
    });

});


describe('the certificates page, drawn', () => {

    let held:        CertificateStore;
    let chosen:      CertificateStore['chosen'];
    let unencrypted  = false;
    let selfToo      = false;
    let refuse       = false;
    let inspected    = 0;

    const aRoot  = certificate({ id: 'aaaaaaaaaaaaaaaa', kind: 'tlsRoot',    label: 'Root A', hasPrivateKey: false, thumbprint: 'aa'.repeat(32) });
    const twice  = (kind: string) => certificate({ id: 'dddddddddddddddd', kind, label: 'Both', hasPrivateKey: false, thumbprint: 'dd'.repeat(32) });
    const self   = (kind: string) => certificate({ id: 'eeeeeeeeeeeeeeee', kind, label: 'Self', hasPrivateKey: kind === 'tlsIdentity', thumbprint: 'ee'.repeat(32) });

    const aStore = (): CertificateStore => ({
        directory:           'certs',
        trustAnchors:        [ 'tlsRoot', 'clientRoot' ],
        credentials:         [ 'tlsIdentity' ],
        recognised:          [],
        kinds:               { tlsRoot:      { description: 'TLS roots',    withArticle: 'a TLS root',     group: 'trustAnchor', page: 'certificates', usages: [ 'dns', 'nts' ] },
                               clientRoot:   { description: 'client roots', withArticle: 'a client root',  group: 'trustAnchor', page: 'certificates', usages: [] },
                               tlsIdentity:  { description: 'TLS identity', withArticle: 'a TLS identity', group: 'credential',  page: 'identities',   usages: [], needsPrivateKey: true } },
        usages:              [],
        chosen,
        certificates:        { tlsRoot:      [ { ...aRoot }, twice('tlsRoot'), ...(selfToo ? [ self('tlsRoot') ] : []) ],
                               clientRoot:   [ twice('clientRoot') ],
                               tlsIdentity:  selfToo ? [ self('tlsIdentity') ] : [] },
        keysAreUnencrypted:  unencrypted
    } as unknown as CertificateStore);

    /** What the stand-in finds in a text: one root per BEGIN CERTIFICATE, the second of them unsuitable as an identity. */
    function inspect(text: string) {
        const count = (text.match(/BEGIN CERTIFICATE/g) ?? []).length;
        return {
            certificates: Array.from({ length: count }, (_, at) => ({
                pem: '', id: `${at + 1}`.repeat(16), thumbprint: `${at + 1}`.repeat(64), label: `Found ${at + 1}`, subject: '', issuer: '',
                notBefore: days(-1), notAfter: days(300), keyAlgorithm: 'ECDSA P-256', hasPrivateKey: at === 0 && /PRIVATE KEY/.test(text), chainLength: 0,
                isCA: true, selfSigned: true, inStoreAs: at === 0 ? [] : [ 'tlsRoot' ],
                // As the node says it: a root that comes with a key is refused as every kind of root.
                unsuitable: { tlsIdentity: 'A TLS identity has to carry its private key.',
                              ...(/PRIVATE KEY/.test(text) ? { tlsRoot:     'That file carries a private key, and a trust anchor must not.',
                                                               clientRoot:  'That file carries a private key, and a trust anchor must not.' } : {}) }
            })),
            pem: text
        };
    }

    /** How the stand-in node answers. */
    function node({ method, path, query, body }: Asked): unknown {

        if (method === 'PATCH') {
            const { kind, active } = body as { kind?: string; active?: boolean };
            for (const entry of Object.values(held.certificates).flat())
                if (path.endsWith(entry.id) && (kind === undefined || entry.kind === kind))
                    entry.active = active ?? entry.active;
            return Object.values(held.certificates).flat().find(entry => path.endsWith(entry.id));
        }

        if (method === 'DELETE') {
            const kind = query.get('kind');
            for (const [ name, entries ] of Object.entries(held.certificates))
                held.certificates[name] = entries.filter(entry => !(path.endsWith(entry.id) && (kind === null || entry.kind === kind)));
            return held;
        }

        if (method === 'POST' && path.endsWith('/certificates/inspect')) {
            inspected++;
            const { pem, content } = body as { pem?: string; content?: string };
            if (content !== undefined)
                return content === 'bG9ja2Vk'
                           ? refused(400, 'That file is a PKCS#12 that could not be opened without a password.', { passwordWanted: true })
                           : { certificates: [], pem: '-----BEGIN CERTIFICATE-----\nFROMFILE\n-----END CERTIFICATE-----\n' };
            return inspect(pem ?? '');
        }

        if (method === 'POST' && path.endsWith('/certificates')) {
            if (refuse)
                return refused(400, 'None of the 2 certificates went in.', { imported: [], refused: [ { id: '1111111111111111', label: 'Found 1', error: 'Not today.' } ] });
            const { kinds } = body as { kinds: { kind: string }[] };
            const imported = kinds.map(({ kind }) => certificate({ id: 'bbbbbbbbbbbbbbbb', kind, label: 'Root B', hasPrivateKey: false }));
            for (const one of imported)
                (held.certificates[one.kind] ??= []).push(one);
            return { imported, refused: [] };
        }

        if (path.endsWith('/certificates'))
            return held;

        return undefined;

    }

    const wait = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));

    async function opened(options:  Parameters<typeof certificatesPage>[0] = {},
                          path      = '/configuration/certificates',
                          made      = certificatesPage): Promise<HTMLElement> {

        held       = aStore();
        refuse     = false;
        inspected  = 0;

        return open(made(options), path, [ 'certificates:read', 'certificates:edit' ], node,
                    root => root.querySelector('#import-form') !== null || root.querySelector('.error-box') !== null);

    }

    const box    = (root: HTMLElement) => root.querySelector<HTMLTextAreaElement>('#upload-pem')!;
    const label  = (root: HTMLElement) => root.querySelector<HTMLInputElement>('#import-form [name="label"]')!;
    const kindOf = (root: HTMLElement, kind: string) => root.querySelector<HTMLInputElement>(`#upload-kinds input[name="kind"][value="${kind}"]`)!;

    function tick(root: HTMLElement, kind: string, on = true): void {
        const input = kindOf(root, kind);
        input.checked = on;
        input.dispatchEvent(new Event('change', { bubbles: true }));
    }

    const submit = (root: HTMLElement) =>
        root.querySelector<HTMLFormElement>('#import-form')!.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));

    const twoRoots = '-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----\n';


    it('opens on the tab the address names, shows one tab at a time, and keeps the tab shown in the address', async () => {

        const root = await opened({}, '/configuration/certificates?tab=all');

        const panel = (id: string) => root.querySelector<HTMLElement>(`#panel-${id}`)!;

        assert.equal(panel('all').hidden,     false, 'the tab the address names is not shown');
        assert.equal(panel('usage').hidden,   true);
        assert.equal(panel('upload').hidden,  true);
        assert.equal(root.querySelector('#tab-all')!.getAttribute('aria-selected'), 'true');

        root.querySelector<HTMLButtonElement>('#tab-upload')!.click();

        assert.equal(panel('upload').hidden,  false);
        assert.equal(panel('all').hidden,     true);
        assert.equal(new URL(location.href).searchParams.get('tab'), 'upload', 'the tab shown is not in the address');

        root.querySelector('.tabs')!.dispatchEvent(new KeyboardEvent('keydown', { key: 'Home', bubbles: true }));

        assert.equal(panel('usage').hidden, false, 'Home does not go to the first tab');
        assert.equal(new URL(location.href).searchParams.get('tab'), null, 'the first tab is the page as it opens, and not in the address');

    });

    it('has no button that reads the directory again, and no upload for somebody who may not change the store', async () => {

        const root = await opened();

        assert.ok(root.querySelector('#rescan') === null, 'the button that reads the directory again is still there');

        const reader = await open(certificatesPage(), '/configuration/certificates', [ 'certificates:read' ], node,
                                  root => root.querySelector('#panel-usage') !== null);

        assert.ok(reader.querySelector('#tab-upload') === null && reader.querySelector('#import-form') === null, 'a reader is offered the upload');

    });

    it('keeps what is pasted, ticked and typed for an upload while a certificate is switched off', async () => {

        const root = await opened();

        type(box(root), twoRoots);
        tick(root, 'clientRoot');
        const typed = label(root);
        typed.value = 'half filled in';
        typed.focus();

        root.querySelector<HTMLButtonElement>('#panel-usage [data-toggle="aaaaaaaaaaaaaaaa:tlsRoot"]')!.click();
        await until(() => root.querySelector('#panel-usage [data-toggle="aaaaaaaaaaaaaaaa:tlsRoot"]')?.textContent?.trim() === 'Switch on',
                    'the certificate was not switched off');

        assert.ok(label(root) === typed,             'the field was made anew');
        assert.equal(typed.value, 'half filled in',  'what was typed for the upload is gone');
        assert.equal(box(root).value, twoRoots,      'what was pasted is gone');
        assert.equal(kindOf(root, 'clientRoot').checked, true, 'the kind ticked is gone');
        assert.ok(document.activeElement === typed,  'the focus went');
        assert.equal(unsaved.any(), true,            'an upload half filled in is let go without a question');

    });

    it('gives the focus back to the label typed into once a certificate is switched off, as a browser takes it away', async () => {

        const root    = await opened();
        const browser = chromeTakesTheFocus(root);

        const typed = label(root);
        typed.value = 'half filled in';
        typed.focus();

        root.querySelector<HTMLButtonElement>('#panel-usage [data-toggle="aaaaaaaaaaaaaaaa:tlsRoot"]')!.click();
        await until(() => root.querySelector('#panel-usage [data-toggle="aaaaaaaaaaaaaaaa:tlsRoot"]')?.textContent?.trim() === 'Switch on',
                    'the certificate was not switched off');
        browser.disconnect();

        assert.ok(label(root) === typed,             'the field was made anew');
        assert.ok(document.activeElement === typed,  'the focus went, and was not given back');

    });

    it('says what the box holds, certificate by certificate, once the typing has stopped - and offers no kind none of them can be', async () => {

        const root = await opened({}, '/configuration/identities', identitiesPage);

        type(box(root), twoRoots);
        await until(() => root.querySelectorAll('#upload-found [data-found]').length === 2, 'what the box holds is not said');

        assert.equal(inspected, 1, 'the node was asked more than once for one pause in the typing');
        assert.match(root.querySelector('#upload-found [data-found="2222222222222222"]')!.textContent!, /in the store as tlsRoot/);
        assert.equal(kindOf(root, 'tlsIdentity').disabled, true, 'a kind none of the certificates can be is offered');
        assert.match(root.querySelector('[data-kind-choice="tlsIdentity"] .unsuitable')!.textContent!, /has to carry its private key/);
        assert.equal(label(root).disabled, true, 'a label is offered for two certificates');

    });

    it('offers each ticked kind its usages, and a usage made up, and sends them with it', async () => {

        const root = await opened();

        type(box(root), twoRoots);
        tick(root, 'tlsRoot');

        const usage = (value: string) => root.querySelector<HTMLInputElement>(`[data-usages-of="tlsRoot"] input[value="${value}"]`);

        assert.ok(usage('dns') !== null && usage('nts') !== null, 'a ticked root is not offered its usages');
        assert.ok(root.querySelector('[data-usages-of="clientRoot"]') === null, 'a kind not ticked is offered usages');

        usage('nts')!.checked = true;
        usage('nts')!.dispatchEvent(new Event('change', { bubbles: true }));

        root.querySelector<HTMLInputElement>('[data-new-usage="tlsRoot"]')!.value = 'Our-Backend';
        root.querySelector<HTMLButtonElement>('[data-add-usage="tlsRoot"]')!.click();

        assert.equal(usage('our-backend')?.checked, true, 'the usage made up is not offered, ticked');

        submit(root);
        await until(() => (root.querySelector('#import-note')?.textContent ?? '').startsWith('Imported'), 'the upload did not go through');

        const sent = asked.find(one => one.method === 'POST' && one.path.endsWith('/certificates'))!.body as { kinds: unknown; pem: string };

        assert.deepEqual(sent.kinds, [ { kind: 'tlsRoot', usages: [ 'nts', 'our-backend' ] } ]);
        assert.equal(sent.pem, twoRoots.trim());

    });

    it('adds a usage or a kind made up on Enter, and sends nothing for it', async () => {

        const root = await opened();

        type(box(root), twoRoots);
        tick(root, 'tlsRoot');

        const enter = (input: HTMLInputElement) => {
            const pressed = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true });
            input.dispatchEvent(pressed);
            return pressed.defaultPrevented;
        };

        const usage = root.querySelector<HTMLInputElement>('[data-new-usage="tlsRoot"]')!;
        usage.value = 'by-enter';

        assert.equal(enter(usage), true, 'Enter in the usage made up would send the form');
        assert.equal(root.querySelector<HTMLInputElement>('[data-usages-of="tlsRoot"] input[value="by-enter"]')?.checked, true, 'Enter did not add the usage');

        const name = root.querySelector<HTMLInputElement>('#make-up-name')!;
        name.value = 'enteredRoot';

        assert.equal(enter(name), true, 'Enter in the name of a kind made up would send the form');
        assert.equal(kindOf(root, 'enteredRoot')?.checked, true, 'Enter did not make the kind up');

    });

    it('makes up a kind of its group, ticked, and sends its group with it', async () => {

        const root = await opened();

        type(box(root), twoRoots);
        root.querySelector<HTMLInputElement>('#make-up-name')!.value = 'backendRoot';
        root.querySelector<HTMLSelectElement>('#make-up-group')!.value = 'trustAnchor';
        root.querySelector<HTMLButtonElement>('#make-up-add')!.click();

        assert.equal(kindOf(root, 'backendRoot')?.checked, true, 'the kind made up is not offered, ticked');

        root.querySelector<HTMLInputElement>('#make-up-name')!.value = 'not a name';
        root.querySelector<HTMLButtonElement>('#make-up-add')!.click();
        assert.match(root.querySelector('#make-up-error')!.textContent!, /a letter, then letters/);

        submit(root);
        await until(() => (root.querySelector('#import-note')?.textContent ?? '').startsWith('Imported'), 'the upload did not go through');

        const sent = asked.find(one => one.method === 'POST' && one.path.endsWith('/certificates'))!.body as { kinds: unknown };

        assert.deepEqual(sent.kinds, [ { kind: 'backendRoot', group: 'trustAnchor' } ]);

    });

    it('is an empty upload again once everything went in, and says what went in', async () => {

        const root = await opened();

        type(box(root), twoRoots);
        tick(root, 'clientRoot');
        label(root).value = 'Root B';

        submit(root);
        await until(() => (root.querySelector('#import-note')?.textContent ?? '').startsWith('Imported'), 'the upload did not go through');

        assert.equal(box(root).value, '',               'what was pasted is still in the box - with its keys');
        assert.equal(label(root).value, '',             'what was typed for the upload that went through is still there');
        assert.equal(kindOf(root, 'clientRoot').checked, false, 'the kind stays ticked');
        assert.match(root.querySelector('#upload-result .went-in')!.textContent!, /Root B: kept as a client root$/, 'said as a sentence says it, not as the cards are called');
        assert.equal(unsaved.any(), false, 'the page is held after its upload went through');

    });

    it('keeps what was pasted, ticked and typed for an upload the node refused, and says why certificate by certificate', async () => {

        const root = await opened();

        type(box(root), twoRoots);
        tick(root, 'clientRoot');
        refuse = true;

        submit(root);
        await until(() => (root.querySelector('#import-error')?.textContent ?? '') !== '', 'the refusal was not said');

        assert.equal(box(root).value, twoRoots);
        assert.equal(kindOf(root, 'clientRoot').checked, true);
        assert.match(root.querySelector('#upload-result [data-refused="1111111111111111"]')!.textContent!, /Found 1: Not today\./);

    });

    it('wants something in the box and a kind ticked before it asks the node', async () => {

        const root = await opened();

        submit(root);
        assert.match(root.querySelector('#import-error')!.textContent!, /Paste a certificate/);

        type(box(root), twoRoots);
        submit(root);
        assert.match(root.querySelector('#import-error')!.textContent!, /Tick at least one kind/);

        assert.ok(!asked.some(one => one.method === 'POST' && one.path.endsWith('/certificates')), 'the node was asked anyway');

    });

    it('puts a file dropped on the box into it as the node reads it, and says which file wants its password', async () => {

        const root = await opened();

        const files = [ new File([ 'whatever' ], 'server.der'), new File([ 'locked' ], 'locked.p12') ];
        const drop  = new Event('drop', { bubbles: true, cancelable: true }) as Event & { dataTransfer: unknown };

        Object.defineProperty(drop, 'dataTransfer', { value: { files, getData: () => '' } });
        root.querySelector('.pem-box')!.dispatchEvent(drop);

        await until(() => box(root).value.includes('FROMFILE'), 'the file read is not in the box');
        await until(() => (root.querySelector('#upload-files-note')?.textContent ?? '') !== '', 'the file that wants a password is not said');

        assert.match(root.querySelector('#upload-files-note')!.textContent!, /'locked\.p12' opens only with its password/);
        assert.ok(asked.some(one => one.path.endsWith('/certificates/inspect') && (one.body as { content?: string }).content === 'd2hhdGV2ZXI='),
                  'the file was not sent as base64');

    });

    it('says where the clipboard cannot be read, and puts it into the box where it can', async () => {

        const root      = await opened();
        const clipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');

        try
        {
            Object.defineProperty(navigator, 'clipboard', { value: { readText: async () => { throw new Error('not allowed'); } }, configurable: true });
            root.querySelector<HTMLButtonElement>('[data-paste]')!.click();
            await until(() => /Ctrl\+V/.test(root.querySelector('[data-pem-note]')?.textContent ?? ''), 'the refused clipboard is not said');

            Object.defineProperty(navigator, 'clipboard', { value: { readText: async () => twoRoots }, configurable: true });
            root.querySelector<HTMLButtonElement>('[data-paste]')!.click();
            await until(() => box(root).value === twoRoots, 'the clipboard is not in the box');
        }
        finally
        {
            if (clipboard)
                Object.defineProperty(navigator, 'clipboard', clipboard);
        }

    });

    it('lists a certificate kept as two kinds once, and takes it out as one of them', async () => {

        const root = await opened({}, '/configuration/certificates?tab=all');

        const cards = [ ...root.querySelectorAll<HTMLElement>('#panel-all [data-certificate]') ].map(card => card.dataset['certificate']);

        assert.deepEqual(cards, [ 'dddddddddddddddd', 'aaaaaaaaaaaaaaaa' ], 'not once each, by name');

        const both = root.querySelector<HTMLElement>('#panel-all [data-certificate="dddddddddddddddd"]')!;

        assert.deepEqual([ ...both.querySelectorAll<HTMLElement>('tr[data-kind]') ].map(row => row.dataset['kind']), [ 'tlsRoot', 'clientRoot' ]);
        assert.match(root.querySelector('#panel-usage [data-remove="dddddddddddddddd:tlsRoot"]')!.textContent!, /Remove/, 'taken out as one kind, it is said to be deleted');
        assert.equal(root.querySelector('#panel-usage section[data-kind="tlsRoot"] .also-as .chip')?.textContent, 'also a client root',
                     'the other kind is named as a sentence names it, not by its id');

        both.querySelector<HTMLButtonElement>('[data-remove="dddddddddddddddd:clientRoot"]')!.click();
        await until(() => asked.some(one => one.method === 'DELETE'), 'it was not taken out');

        const deleted = asked.find(one => one.method === 'DELETE')!;

        assert.equal(deleted.query.get('kind'), 'clientRoot', 'taken out as every kind');
        assert.match(said.at(-1)!, /Take Both out as a client root\?\n\nIt stays in the store as a TLS root\./);

        await until(() => root.querySelector('#panel-all [data-certificate="dddddddddddddddd"] tr[data-kind="clientRoot"]') === null, 'the kind taken out is still listed');

    });

    it('asks before a certificate kept as two kinds is deleted, naming both as a sentence names them', async () => {

        const root = await opened({}, '/configuration/certificates?tab=all');

        root.querySelector<HTMLButtonElement>('#panel-all [data-delete-certificate="dddddddddddddddd"]')!.click();
        await until(() => asked.some(one => one.method === 'DELETE'), 'it was not deleted');

        assert.match(said.at(-1)!, /^Delete Both, kept as a TLS root and a client root\?/);
        assert.equal(asked.find(one => one.method === 'DELETE')!.query.get('kind'), null, 'deleted as one kind of the two');

    });

    it('takes a certificate out as this page\'s kind where it is kept as a kind of another page too', async () => {

        selfToo = true;

        try
        {

            const root = await opened({}, '/configuration/identities?tab=all', identitiesPage);
            const card = root.querySelector<HTMLElement>('#panel-all [data-certificate="eeeeeeeeeeeeeeee"]');

            assert.ok(card !== null, 'the identity is not listed');
            assert.equal(card.querySelectorAll('tr[data-kind]').length, 1, 'a kind of another page is listed here');
            assert.ok(card.querySelector('[data-remove="eeeeeeeeeeeeeeee:tlsIdentity"]') !== null,
                      'kept as a root as well, it can be deleted only as a whole here');

        }
        finally
        {
            selfToo = false;
        }

    });

    it('marks a certificate chosen as one kind in that kind\'s row alone, and each choice once on its card', async () => {

        chosen = { forTheTest: { id: 'dddddddddddddddd', kind: 'clientRoot' }, byItsHandle: 'dddddddddddddddd' };

        try
        {

            const root  = await opened({ chosen: { forTheTest: { label: 'used by the test' }, byItsHandle: { label: 'chosen as any' } } });
            const rowOf = (Key: string) => root.querySelector(`#panel-usage [data-remove="${Key}"]`)!.closest('tr')!;

            assert.match       (rowOf('dddddddddddddddd:clientRoot').textContent!, /used by the test/);
            assert.doesNotMatch(rowOf('dddddddddddddddd:tlsRoot').textContent!,    /used by the test/, 'the same certificate kept as another kind');
            assert.match       (rowOf('dddddddddddddddd:tlsRoot').textContent!,    /chosen as any/,    'a handle alone marks every kind');
            assert.deepEqual   ([ ...root.querySelectorAll('#panel-all [data-certificate="dddddddddddddddd"] h3 .chip') ].map(chip => chip.textContent),
                                [ 'chosen as any', 'used by the test' ], 'each once, whichever kinds it is chosen as');

        }
        finally
        {
            chosen = undefined;
        }

    });

    it('keeps each kind on its page: the roots on the certificates, an identity on the identities, nothing on a page with none', async () => {

        unencrypted = true;

        try
        {

            const certificates = await opened();

            assert.equal(certificates.querySelector('h1')!.textContent, 'Certificates');
            assert.ok(certificates.querySelector('section[data-kind="tlsRoot"]') !== null, 'the roots are not on the certificates');
            assert.ok(certificates.querySelector('section[data-kind="tlsIdentity"]') === null, 'an identity is on the certificates');
            assert.ok(kindOf(certificates, 'tlsIdentity') === null, 'an identity is offered for an upload of certificates');
            assert.ok(kindOf(certificates, 'tlsRoot') !== null);
            assert.ok(!/not encrypted/.test(certificates.textContent!), 'the certificates say their keys are not encrypted, and keep none');
            assert.deepEqual([ ...certificates.querySelectorAll<HTMLOptionElement>('#make-up-group option') ].map(option => option.value), [ 'trustAnchor', 'recognised' ]);

            const identities = await opened({}, '/configuration/identities', identitiesPage);

            assert.equal(identities.querySelector('h1')!.textContent, 'Identities');
            assert.equal(identities.querySelector('#tab-all')!.textContent!.trim(), 'All identities');
            assert.ok(identities.querySelector('section[data-kind="tlsIdentity"]') !== null, 'the identity is not on the identities');
            assert.ok(identities.querySelector('section[data-kind="tlsRoot"]') === null, 'a root is on the identities');
            assert.deepEqual([ ...identities.querySelectorAll<HTMLInputElement>('#upload-kinds input[name="kind"]') ].map(input => input.value), [ 'tlsIdentity' ]);
            assert.match(identities.textContent!, /not encrypted/, 'the identities do not say their keys are not encrypted');
            assert.deepEqual([ ...identities.querySelectorAll<HTMLOptionElement>('#make-up-group option') ].map(option => option.value), [ 'credential' ]);
            assert.equal(identities.querySelectorAll('#panel-all [data-certificate]').length, 0, 'a root is listed among all identities');

            const servers = await opened({}, '/configuration/server-certificates', serverCertificatesPage);

            assert.equal(servers.querySelector('h1')!.textContent, 'Server certificates');
            assert.match(servers.querySelector('#kinds')!.textContent!, /keeps nothing of what this page looks after/);
            assert.ok(servers.querySelector('#upload-make-up') === null, 'a server\'s identity is offered to be made up');

        }
        finally
        {
            unencrypted = false;
        }

    });

    it('leaves a private key in the box out on the certificates page, says so, and says where it goes', async () => {

        const root = await opened();
        const key  = '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n';

        type(box(root), twoRoots + key);
        await until(() => root.querySelectorAll('#upload-found [data-found]').length === 2, 'what the box holds is not said');

        const goesTo  = [ ...root.querySelectorAll('#upload-found .keys-left-out a') ].map(link => link.getAttribute('href') ?? '');
        const looked  = asked.filter(one => one.path.endsWith('/certificates/inspect')).map(one => (one.body as { pem: string }).pem);

        assert.equal(goesTo.length, 1, 'a page this node keeps nothing on is named');
        assert.ok(goesTo[0]!.endsWith('/configuration/identities'), 'where a key goes is not said');
        assert.ok(looked.length > 0 && looked.every(pem => !/PRIVATE KEY/.test(pem)), 'the key went to the node to be looked at');
        assert.equal(kindOf(root, 'tlsRoot').disabled, false, 'a root is refused for a key that is left out');

        tick(root, 'tlsRoot');
        submit(root);
        await until(() => (root.querySelector('#import-note')?.textContent ?? '').startsWith('Imported'), 'the upload did not go through');

        const sent = asked.find(one => one.method === 'POST' && one.path.endsWith('/certificates'))!.body as { pem: string };

        assert.equal(sent.pem, twoRoots.trim(), 'the key went to the node');

    });

    it('narrows the list down as it is typed into, and orders it by fingerprint where that is asked', async () => {

        const root = await opened({}, '/configuration/certificates?tab=all');

        const filter = root.querySelector<HTMLInputElement>('#all-filter')!;

        type(filter, 'root a');
        assert.deepEqual([ ...root.querySelectorAll<HTMLElement>('#panel-all [data-certificate]') ].map(card => card.dataset['certificate']), [ 'aaaaaaaaaaaaaaaa' ]);

        type(filter, '');
        const byFingerprint = root.querySelector<HTMLInputElement>('#panel-all input[name="order"][value="fingerprint"]')!;
        byFingerprint.checked = true;
        byFingerprint.dispatchEvent(new Event('change', { bubbles: true }));

        assert.deepEqual([ ...root.querySelectorAll<HTMLElement>('#panel-all [data-certificate]') ].map(card => card.dataset['certificate']), [ 'aaaaaaaaaaaaaaaa', 'dddddddddddddddd' ]);
        assert.equal(unsaved.any(), false, 'narrowing the list down holds the page');

    });

    it('switches a certificate kept as two kinds as the one switched', async () => {

        const root = await opened({}, '/configuration/certificates?tab=all');

        root.querySelector<HTMLButtonElement>('#panel-all [data-toggle="dddddddddddddddd:clientRoot"]')!.click();
        await until(() => asked.some(one => one.method === 'PATCH'), 'it was not switched');

        assert.deepEqual(asked.find(one => one.method === 'PATCH')!.body, { kind: 'clientRoot', active: false });

        await wait();

    });

});


describe('the certificates page, as a kind of node adds to it', () => {

    let held: CertificateStore;
    let loads = 0;
    let refuseTheSection = false;

    const anIdentity = certificate({ id: 'cccccccccccccccc', kind: 'tlsServerIdentity', label: 'Meter A', usages: null });

    const aStore = (): CertificateStore => ({
        directory:           'certs',
        trustAnchors:        [ 'tlsRoot' ],
        credentials:         [ 'tlsServerIdentity' ],
        recognised:          [],
        kinds:               { tlsRoot:            { description: 'TLS roots',           page: 'certificates',        usages: [ 'dns', 'nts' ] },
                               tlsServerIdentity:  { description: 'TLS server identity', page: 'serverCertificates',  usages: [ 'modbus', 'web' ], needsPrivateKey: true } },
        usages:              [],
        certificates:        { tlsRoot: [ certificate({ id: 'aaaaaaaaaaaaaaaa', kind: 'tlsRoot', label: 'Root A', hasPrivateKey: false }) ],
                               tlsServerIdentity: [ { ...anIdentity } ] },
        keysAreUnencrypted:  false,
        // What a meter's store says beyond every node's.
        listeners:           [ 'modbus' ]
    } as unknown as CertificateStore);

    /** How the stand-in node answers. */
    function node({ method, path, body }: Asked): unknown {

        if (method === 'PATCH') {
            const { kind, active } = body as { kind?: string; active?: boolean };
            const entry = held.certificates[kind ?? 'tlsRoot']![0]!;
            entry.active = active ?? entry.active;
            return entry;
        }

        if (path.endsWith('/certificates'))
            return held;

        return undefined;

    }

    async function opened(options:  Parameters<typeof certificatesPage>[0],
                          made      = serverCertificatesPage,
                          path      = '/configuration/server-certificates'): Promise<HTMLElement> {

        held             = aStore();
        loads            = 0;
        refuseTheSection = false;

        return open(made(options), path, [ 'certificates:read', 'certificates:edit' ], node,
                    root => root.querySelector('#import-form') !== null || root.querySelector('.error-box') !== null);

    }

    const card = (root: HTMLElement, kind: string) => root.querySelector<HTMLElement>(`section[data-kind="${kind}"]`)!;


    it('names a kind, with its icon and its hint, as the kind of node calls it, and says in the dialog what one is for', async () => {

        const options = { kinds: { tlsServerIdentity: { title: 'TLS identities', icon: 'fa-id-card',
                                                        hint: html`Shown to <strong>charging stations</strong>.`,
                                                        uses: html`A listener only ever shows an identity that is for it.` } } };

        const root    = await opened(options);
        const heading = card(root, 'tlsServerIdentity').querySelector('h3')!;

        assert.equal(heading.textContent!.trim(), 'TLS identities');
        assert.ok(heading.querySelector('i.fa-id-card') !== null, 'the icon is not in the heading');
        assert.equal(card(root, 'tlsServerIdentity').querySelector('p.hint strong')?.textContent, 'charging stations', 'the hint is not drawn as markup');

        root.querySelector<HTMLButtonElement>('#panel-usage [data-usages="cccccccccccccccc:tlsServerIdentity"]')!.click();
        await until(() => document.querySelector('dialog #usages-form') !== null, 'the dialog did not open');
        assert.match(document.querySelector('dialog')!.textContent!, /A listener only ever shows an identity that is for it\./);
        assert.match(document.querySelector('dialog legend')!.textContent!, /Where it is shown/, 'a server\'s identity is not told the listeners it is shown on');
        document.querySelector('dialog')!.remove();

        const roots = await opened(options, certificatesPage, '/configuration/certificates');

        assert.equal(card(roots, 'tlsRoot').querySelector('h3')!.textContent!.trim(), 'TLS roots', 'a kind not named lost the store\'s description');

    });

    it('says what the kind of node has to say at the top, and beside a certificate\'s name', async () => {

        const options = {
            notices:   (store: CertificateStore) => (store as CertificateStore & { listeners: string[] }).listeners.map(listener => html`The ${listener} listener has nothing to show.`),
            rowChips:  (entry: Certificate) => entry.kind === 'tlsServerIdentity' ? [ html`<span class="chip ok">shown on Modbus/TLS</span>` ] : []
        };

        const root = await opened(options);

        assert.ok([ ...root.querySelectorAll('.notice') ].some(notice => notice.textContent!.trim() === 'The modbus listener has nothing to show.'),
                  'the notice is not at the top');
        assert.equal(card(root, 'tlsServerIdentity').querySelector('.row-chips .chip.ok')?.textContent, 'shown on Modbus/TLS');
        assert.equal(card(root, 'tlsServerIdentity').querySelector('.usages-of .chip')?.textContent, 'on every listener',
                     'an identity for every listener is said to be for every use');

        const roots = await opened(options, certificatesPage, '/configuration/certificates');

        // ok() and not equal(): a message of equal() would print the element, and with it all of happy-dom's window.
        assert.ok(card(roots, 'tlsRoot').querySelector('.row-chips') === null, 'a row with nothing to add has a line for it');
        assert.equal(card(roots, 'tlsRoot').querySelector('.usages-of .chip')?.textContent, 'for every use', 'a root is said to be shown on the listeners');

    });

    it('draws a section at the end of its group, asks for what it needs with the store, and keeps what is typed into it', async () => {

        let shownAt = 0;

        const root = await opened({
            sections: context => [ {
                below:  'presents',
                page:   'serverCertificates',
                load:   async () => { loads++; shownAt = loads; },
                draw:   () => html`
                    <section class="card" id="requests">
                        <h2>Signing requests, loaded ${shownAt} time(s)</h2>
                        <form id="request-form"><input name="subject" /></form>
                        <button type="button" id="again" @click=${() => void context.reload()}>again</button>
                        ${context.mayChange ? html`<span id="may">may</span>` : ''}
                    </section>`
            } ]
        });

        const section = root.querySelector('#requests')!;

        assert.ok(card(root, 'tlsServerIdentity').compareDocumentPosition(section) & Node.DOCUMENT_POSITION_FOLLOWING,
                  'the section is not below what the node presents');
        assert.equal(loads, 1, 'what the section needs was not asked for with the store');
        assert.ok(root.querySelector('#may') !== null, 'the section was not told the person may change the store');

        const subject = root.querySelector<HTMLInputElement>('#request-form [name="subject"]')!;
        subject.value = 'CN=meter7.lan';
        subject.focus();

        root.querySelector<HTMLButtonElement>('#panel-usage [data-toggle="cccccccccccccccc:tlsServerIdentity"]')!.click();
        await until(() => loads === 2 && root.querySelector('#panel-usage [data-toggle="cccccccccccccccc:tlsServerIdentity"]')?.textContent?.trim() === 'Switch on',
                    'the section was not asked again with the store after a change');

        assert.ok(root.querySelector('#request-form [name="subject"]') === subject, 'the section\'s field was made anew');
        assert.equal(subject.value, 'CN=meter7.lan');
        assert.ok(document.activeElement === subject, 'the focus went');
        assert.match(root.querySelector('#requests h2')!.textContent!, /loaded 2 time/);

        root.querySelector<HTMLButtonElement>('#again')!.click();
        await until(() => loads === 3, 'the section could not ask for the store and its own again');

    });

    it('holds what is typed into a section\'s form as a draft, and empties it, and the section\'s choices, on Reload', async () => {

        let chosen: string | undefined;

        const root = await opened({
            sections: context => [ {
                below:  'presents',
                page:   'serverCertificates',
                reset:  () => { chosen = undefined; },
                draw:   () => html`
                    <section class="card" id="requests">
                        <form id="request-form">
                            <select name="listener" @change=${(event: Event) => { chosen = (event.target as HTMLSelectElement).value; context.draw(); }}>
                                <option value="modbus" selected>Modbus/TLS</option>
                                <option value="web">web interface</option>
                            </select>
                            <p class="hint" id="listener-note">${chosen ?? 'modbus'}</p>
                            <input name="subject" />
                        </form>
                    </section>`
            } ]
        });

        assert.equal(unsaved.any(), false, 'a page nobody typed into is held');

        const subject = root.querySelector<HTMLInputElement>('#request-form [name="subject"]')!;
        subject.value = 'CN=meter7.lan';
        const listener = root.querySelector<HTMLSelectElement>('#request-form [name="listener"]')!;
        listener.value = 'web';
        listener.dispatchEvent(new Event('change', { bubbles: true }));

        assert.equal(root.querySelector('#listener-note')!.textContent, 'web');
        assert.equal(unsaved.any(), true, 'what is typed into a section\'s form is let go without a question');

        const confirmed = globalThis.confirm;
        globalThis.confirm = () => true;
        try
        {
            root.querySelector<HTMLButtonElement>('#reload')!.click();
            await until(() => subject.value === '' && root.querySelector('#listener-note')!.textContent === 'modbus',
                        'Reload did not empty the section\'s form, or did not forget its choice');
        }
        finally
        {
            globalThis.confirm = confirmed;
        }

        assert.equal(listener.value, 'modbus');
        assert.equal(unsaved.any(), false, 'the page is still held after Reload');

    });

    it('says a hint from the store where it is given as one, under a group and under the import, and hands a section the page', async () => {

        let page: HTMLElement | undefined;

        const root = await opened({
            hints:     { serves:     store => html`Shown on ${(store as CertificateStore & { listeners: string[] }).listeners.length} listener(s).`,
                         importing:  html`A certificate for a key made here goes in <em>under Signing requests</em>.` },
            sections:  context => { page = context.page; return []; }
        });

        assert.ok([ ...root.querySelectorAll('p.hint') ].some(said => said.textContent!.trim() === 'Shown on 1 listener(s).'),
                  'the hint from the store is not said');
        assert.ok([ ...root.querySelectorAll('#import-form p.hint em') ].some(em => em.textContent === 'under Signing requests'), 'the import\'s hint is not said');
        assert.ok(page !== undefined && page === root.querySelector('#content-body'), 'the section was not handed the element the page draws into');

    });

    it('stands a section on the page it names, and by the group it stands below where it names none', async () => {

        const sections = () => [
            { below: 'presents' as const,                               draw: () => html`<p id="by-presents"></p>` },
            { below: 'presents' as const, page: 'serverCertificates' as const,  draw: () => html`<p id="on-servers"></p>`  },
            { below: 'believes' as const,                               draw: () => html`<p id="by-believes"></p>` }
        ];

        const on = async (made: typeof certificatesPage, path: string) => {
            const root = await opened({ sections }, made, path);
            return [ 'by-presents', 'on-servers', 'by-believes' ].filter(id => root.querySelector(`#${id}`) !== null);
        };

        assert.deepEqual(await on(certificatesPage,       '/configuration/certificates'),        [ 'by-believes' ]);
        assert.deepEqual(await on(identitiesPage,         '/configuration/identities'),          [ 'by-presents' ]);
        assert.deepEqual(await on(serverCertificatesPage, '/configuration/server-certificates'), [ 'on-servers'  ]);

    });

    it('says the page could not be loaded where what a section needs could not be', async () => {

        const root = await opened({
            sections: () => [ { below: 'believes', load: async () => { throw new Error('no requests'); }, draw: () => html`<p id="never"></p>` } ]
        }, certificatesPage, '/configuration/certificates');

        assert.match(root.querySelector('.error-box')?.textContent ?? '', /could not be loaded: no requests/);
        assert.ok(root.querySelector('#never') === null, 'a section whose load failed was drawn');

    });

    it('takes a template of view.ts for what it says under a group, drawn as markup', async () => {

        const root = await opened({ hints: { believes: html`Roots <em>this meter</em> believes.` } }, certificatesPage, '/configuration/certificates');

        assert.ok([ ...root.querySelectorAll('p.hint em') ].some(em => em.textContent === 'this meter'), 'the hint is not drawn as markup');

    });

});
