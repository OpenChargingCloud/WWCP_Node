/**
 * The keys a node makes for itself, on its identities page, drawn in a
 * document of happy-dom against a stand-in node: the page has a tab a key is
 * made on where the node makes keys for a kind of it, and none where it does
 * not; a template that has a role asks for it, a server's for what it is
 * reachable as, and what was ticked is sent with them - but no usage the kind
 * of key cannot have; the keys that wait stand among what the node presents,
 * each with its request to copy, to send to the CSMS where the node can, and
 * to remove; and the upload takes a certificate that comes without its key as
 * the answer to a request.
 *
 * Run with `npm test`.
 */

import '../test/dom.ts';
import type { Asked } from '../test/node.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { Certificate, CertificateRequests, CertificateStore, SigningRequest } from './api/client.ts';

document.head.innerHTML = '<meta name="node-name" content="charging station">';

const { asked, change, field, open, refused, submit, type, until } = await import('../test/node.ts');

const { identitiesPage, serverIdentitiesPage, certificatesPage } = await import('./pages/certificates.ts');


let held:         CertificateStore;
let madeWith:     Record<string, unknown> | null = null;
let csmsRefuses:  string | null                  = null;
let confirmed     = true;

globalThis.confirm = () => confirmed;

const aKey = (id: string, more: Partial<SigningRequest> = {}): SigningRequest => ({
    id,
    kind:               'tlsIdentity',
    algorithm:          'ecdsa-p256',
    algorithmName:      'ECDSA P-256',
    createdAt:          '2026-10-01T10:00:00Z',
    subject:            `CN=${id}`,
    label:              null,
    usages:             null,
    template:           'tls-client',
    templateName:       'TLS client',
    role:               null,
    keyUsages:          [ 'digitalSignature' ],
    extendedKeyUsages:  [ 'clientAuth' ],
    reachableAs:        [],
    csr:                `-----BEGIN CERTIFICATE REQUEST-----\n${id}\n-----END CERTIFICATE REQUEST-----`,
    ...more
});

const requests = (more: Partial<CertificateRequests> = {}): CertificateRequests => ({
    directory:          'certs/requests',
    kinds:              [ 'tlsIdentity' ],
    entries:            [ aKey('aaaa'), aKey('bbbb') ],
    algorithms:         [ { id: 'ecdsa-p256', name: 'ECDSA P-256', remark: 'What every server takes.' },
                          { id: 'ed448',      name: 'Ed448',       remark: 'No key object in .NET today.' } ],
    defaultAlgorithm:   'ecdsa-p256',
    maxSubjectLength:   200,
    templates:          [ { id: 'tls-client', name: 'TLS client',        remark: 'A client certificate and nothing else.', purpose: 'clientAuth', asksForNames: false,
                            page: 'identities', keyUsages: [], extendedKeyUsages: [] },
                          { id: 'modbus-tls', name: 'Modbus/TLS client', remark: 'With the role its holder may play.',     purpose: 'clientAuth', asksForNames: false,
                            page: 'identities', keyUsages: [], extendedKeyUsages: [],
                            role: { label: 'Role', roles: [ 'ReadOnlySunSpec', 'GridServiceSunSpec' ], maxLength: 64 } },
                          { id: 'tls-server', name: 'TLS server',        remark: 'For the names it is reachable as.',      purpose: 'serverAuth', asksForNames: true,
                            page: 'serverIdentities', keyUsages: [], extendedKeyUsages: [] } ],
    keyUsages:          [ { id: 'nonRepudiation', name: 'Non-repudiation', remark: '', algorithms: [ 'ecdsa-p256', 'ed448' ] },
                          { id: 'keyAgreement',   name: 'Key agreement',   remark: '', algorithms: [ 'ecdsa-p256' ] } ],
    extendedKeyUsages:  [ { id: 'clientAuth', name: 'TLS client authentication', remark: '', oid: '1.3.6.1.5.5.7.3.2' },
                          { id: 'serverAuth', name: 'TLS server authentication', remark: '', oid: '1.3.6.1.5.5.7.3.1' } ],
    ...more
});

const aStore = (made?: CertificateRequests): CertificateStore => ({
    directory:           'certs',
    trustAnchors:        [],
    credentials:         [ 'tlsIdentity', 'tlsServerIdentity' ],
    recognised:          [],
    kinds:               { tlsIdentity:        { description: 'TLS identity',        withArticle: 'a TLS identity',        group: 'credential', page: 'identities',
                                                 trustAnchor: false, needsPrivateKey: true, hasUsages: true, usages: [ 'csms', 'meters' ] },
                           tlsServerIdentity:  { description: 'TLS server identity', withArticle: 'a TLS server identity', group: 'credential', page: 'serverIdentities',
                                                 trustAnchor: false, needsPrivateKey: true, hasUsages: false, usages: [] } },
    usages:              [],
    certificates:        { tlsIdentity: [], tlsServerIdentity: [] },
    keysAreUnencrypted:  false,
    ...(made === undefined ? {} : { requests: made })
} as unknown as CertificateStore);

const anIdentity = (): Certificate => ({
    id: '1111111111111111', kind: 'tlsIdentity', label: 'aaaa', subject: 'CN=aaaa', issuer: 'CN=Fleet CA', thumbprint: '11'.repeat(32),
    keyAlgorithm: 'ECDSA P-256', hasPrivateKey: true, chainLength: 1, notBefore: '2026-10-01T00:00:00Z', notAfter: '2027-10-01T00:00:00Z',
    active: true, expired: false, notYetValid: false, usages: null
} as unknown as Certificate);

/** A node that keeps identities, and makes keys for them. */
function node({ method, path, body }: Asked): unknown {

    if (method === 'POST' && path === '/certificates/inspect')
        return {
            certificates: [ { pem: '', id: '1'.repeat(16), thumbprint: '1'.repeat(64), label: 'CN=aaaa', subject: 'CN=aaaa', issuer: 'CN=Fleet CA',
                              notBefore: '2026-10-01T00:00:00Z', notAfter: '2027-10-01T00:00:00Z', keyAlgorithm: 'ECDSA P-256',
                              hasPrivateKey: /PRIVATE KEY/.test((body as { pem: string }).pem), chainLength: 0, isCA: false, selfSigned: false, inStoreAs: [],
                              unsuitable: /PRIVATE KEY/.test((body as { pem: string }).pem) ? {} : { tlsIdentity: 'A TLS identity has to carry its private key.' } } ],
            pem: (body as { pem: string }).pem
        };

    if (method === 'POST' && path === '/certificates/requests') {
        madeWith = body as Record<string, unknown>;
        if ((body as { subject: string }).subject === '')
            return refused(400, 'A certificate has to say who this charging station is.');
        const made = aKey('cccc', { subject: `CN=${(body as { subject: string }).subject}`, kind: (body as { kind: string }).kind });
        held = { ...held, requests: { ...held.requests!, entries: [ made, ...held.requests!.entries ] } };
        return { request: made, store: held };
    }

    if (method === 'POST' && path === '/certificates/requests/answer') {
        if (/REFUSE/.test((body as { pem: string }).pem))
            return refused(400, 'None of the certificates in this belongs to a key of this charging station.');
        held = { ...held,
                 certificates:  { ...held.certificates, tlsIdentity: [ anIdentity() ] },
                 requests:      { ...held.requests!, entries: held.requests!.entries.filter(entry => entry.id !== 'aaaa') } };
        return { entry: anIdentity(), requestId: 'aaaa', warnings: [ 'It runs out in 20 day(s).' ], store: held };
    }

    if (method === 'POST' && /^\/certificates\/requests\/[^/]+\/sign$/.test(path)) {
        if (csmsRefuses !== null)
            return refused(502, csmsRefuses);
        const id = path.split('/')[3]!;
        held = { ...held, requests: { ...held.requests!, entries: held.requests!.entries.map(entry => entry.id === id ? { ...entry, sentToCSMSAt: '2026-10-04T12:00:01Z' } : entry) } };
        return { said: 'The CSMS accepted the request.', store: held };
    }

    if (method === 'DELETE' && path.startsWith('/certificates/requests/')) {
        const id = path.split('/')[3]!;
        held = { ...held, requests: { ...held.requests!, entries: held.requests!.entries.filter(entry => entry.id !== id) } };
        return held;
    }

    if (path === '/certificates')
        return held;

    return undefined;

}

async function opened(made:         CertificateRequests | null       = requests(),
                      path          = '/configuration/identities',
                      permissions   = [ 'certificates:read', 'certificates:edit', 'certificates:run' ],
                      page          = identitiesPage): Promise<HTMLElement> {

    held         = aStore(made ?? undefined);
    madeWith     = null;
    csmsRefuses  = null;
    confirmed    = true;

    return open(page(), path, permissions, node, root => root.querySelector('#panel-usage') !== null);

}

const tabs     = (root: HTMLElement) => [ ...root.querySelectorAll('[role="tab"]') ].map(tab => tab.id);
const panel    = (root: HTMLElement, id: string) => root.querySelector<HTMLElement>(`#panel-${id}`)!;
const waiting  = (root: HTMLElement) => [ ...root.querySelectorAll('#waiting-keys [data-request]') ].map(key => key.getAttribute('data-request'));
const subject  = (root: HTMLElement) => field(root, '#request-form', 'subject');
const kind     = (root: HTMLElement) => field<HTMLSelectElement>(root, '#request-form', 'algorithm');
const ticked   = (root: HTMLElement, name: string, value: string) => root.querySelector<HTMLInputElement>(`#request-form [name="${name}"][value="${value}"]`)!;


describe('the keys a node makes for itself, on its identities page', () => {

    it('have a tab they are made on where the node makes keys for a kind of the page - and none where it makes none, or for another page, or for somebody who may not', async () => {

        assert.deepEqual(tabs(await opened()), [ 'tab-usage', 'tab-all', 'tab-request', 'tab-upload' ]);

        const none = await opened(null);

        assert.deepEqual(tabs(none), [ 'tab-usage', 'tab-all', 'tab-upload' ], 'a node that makes no keys offers to make one');
        assert.equal(none.querySelector('#waiting-keys'), null);

        const servers = await opened(requests(), '/configuration/server-identities', undefined, serverIdentitiesPage);

        assert.deepEqual(tabs(servers), [ 'tab-usage', 'tab-all', 'tab-upload' ], 'a key is offered for a kind the node makes none for');

        const roots = await opened(requests(), '/configuration/certificates', undefined, certificatesPage);

        assert.equal(roots.querySelector('#tab-request'), null, 'a key is offered on the page of the roots');

        const reader = await opened(requests(), '/configuration/identities?tab=request', [ 'certificates:read' ]);

        assert.deepEqual(tabs(reader), [ 'tab-usage', 'tab-all' ], 'somebody who may not change the store is offered to make a key');
        assert.equal(panel(reader, 'usage').hidden, false, 'a tab this person does not have is shown');
        assert.deepEqual(waiting(reader), [ 'aaaa', 'bbbb' ], 'somebody who may read the store is not shown the keys that wait');
        assert.equal(reader.querySelector<HTMLButtonElement>('[data-remove-request="aaaa"]')!.disabled, true);

    });

    it('lets whoever may run the store make, send and remove a key, and nothing else: no upload, and no identity changed', async () => {

        const root = await opened(requests({ canBeSentToCSMS: true }), '/configuration/identities?tab=request', [ 'certificates:read', 'certificates:run' ]);

        assert.deepEqual(tabs(root), [ 'tab-usage', 'tab-all', 'tab-request' ], 'whoever may make keys is not offered to, or is offered the upload');
        assert.equal(panel(root, 'request').hidden, false, 'the tab a key is made on is not shown');
        assert.equal(root.querySelector('#panel-upload'), null);

        assert.equal(root.querySelector<HTMLButtonElement>(`#panel-${'request'} button[type="submit"]`)!.disabled, false, 'the key cannot be made');
        assert.equal(root.querySelector<HTMLButtonElement>('[data-send-csr="aaaa"]')!.disabled,       false, 'the request cannot be sent');
        assert.equal(root.querySelector<HTMLButtonElement>('[data-remove-request="aaaa"]')!.disabled, false, 'the key cannot be taken back');
        assert.ok(root.querySelector('#make-a-key') !== null);

        assert.match(root.textContent!, /may look at the store, make keys for it and bring their certificates but not change what else is in it/);

        // The certificate that came back is brought beside its key, where there is no upload to bring it on.
        const error = () => root.querySelector('[data-request="aaaa"] [data-request-error]')!.textContent;
        const box   = root.querySelector<HTMLTextAreaElement>('[data-answer="aaaa"]')!;

        root.querySelector<HTMLButtonElement>('[data-bring-answer="aaaa"]')!.click();
        await until(() => error() !== '', 'nothing is said of a box that is empty');

        assert.equal(asked.some(one => one.path === '/certificates/requests/answer'), false, 'an empty box was sent');

        box.value = 'REFUSE';
        root.querySelector<HTMLButtonElement>('[data-bring-answer="aaaa"]')!.click();
        await until(() => /belongs to a key/.test(error()!), 'what the node refused it with is not said beside the key');

        assert.equal(box.value, 'REFUSE', 'what was pasted is gone after a refusal');

        box.value = '-----BEGIN CERTIFICATE-----';
        root.querySelector<HTMLButtonElement>('[data-bring-answer="aaaa"]')!.click();
        await until(() => waiting(root).length === 1, 'the key still waits after its certificate came');

        assert.match(root.querySelector('#waiting-note')!.textContent!, /Taken in: .* is an identity .* It runs out in 20 day\(s\)\./);

        // And the other way around: changing the store is not making keys.
        const editor = await opened(requests({ canBeSentToCSMS: true }), '/configuration/identities', [ 'certificates:read', 'certificates:edit' ]);

        assert.deepEqual(tabs(editor), [ 'tab-usage', 'tab-all', 'tab-upload' ]);
        assert.equal(editor.querySelector<HTMLButtonElement>('[data-send-csr="aaaa"]')!.disabled, true);
        assert.equal(editor.querySelector('[data-bring-answer]'), null, 'somebody who may not make keys is offered to bring a certificate beside one');

        // Whoever has the upload brings it there, and is offered no second place for it.
        assert.equal((await opened(requests())).querySelector('[data-bring-answer]'), null);

    });

    it('opens on the tab a key is made on by the address, and makes one with a subject alone', async () => {

        const root = await opened(requests(), '/configuration/identities?tab=request');

        assert.equal(panel(root, 'request').hidden, false, 'the tab the address names is not shown');
        assert.equal(root.querySelector('#request-role'), null);
        assert.equal(root.querySelector('#request-names'), null, 'a client is asked what it is reachable as');
        assert.equal(root.querySelector('#request-kind'), null, 'the kind is asked for where there is one');

        subject(root).value = 'cs001.example.org';
        submit(root, '#request-form');
        await until(() => root.querySelector('#just-made') !== null, 'the request is not shown');

        assert.deepEqual(madeWith, { kind: 'tlsIdentity', subject: 'cs001.example.org', algorithm: 'ecdsa-p256', template: 'tls-client', keyUsages: [], extendedKeyUsages: [] });
        assert.equal(root.querySelector<HTMLTextAreaElement>('#just-made')!.value, held.requests!.entries[0]!.csr);
        assert.equal(subject(root).value, '', 'the form still holds what was made');
        assert.deepEqual(waiting(root), [ 'cccc', 'aaaa', 'bbbb' ], 'the key made does not wait with the others');

    });

    it('asks for a role where the template has one, and sends the template, the role, what it is for and what was ticked - but no usage the kind of key cannot have', async () => {

        const root     = await opened(requests(), '/configuration/identities?tab=request');
        const template = () => field<HTMLSelectElement>(root, '#request-form', 'template');

        assert.deepEqual([ ...template().options ].map(option => option.value), [ 'tls-client', 'modbus-tls' ], 'a server\'s template is offered for a client');
        assert.equal(root.querySelector('#request-template-remark')!.textContent!.trim(), 'A client certificate and nothing else.');

        const typed = subject(root);
        typed.value = 'cs001.example.org';

        change(template(), 'modbus-tls');
        await until(() => root.querySelector('#request-role') !== null, 'the role the template has is not asked for');

        assert.equal(root.querySelector('#request-template-remark')!.textContent!.trim(), 'With the role its holder may play.');
        assert.ok(subject(root) === typed, 'the subject was made anew');
        assert.equal(typed.value, 'cs001.example.org', 'the subject typed went with the template chosen');

        field(root, '#request-form', 'role').value  = 'ReadOnlySunSpec';
        field(root, '#request-form', 'label').value = 'The meters\' reader';

        change(ticked(root, 'usage', 'meters'),                 true);
        change(ticked(root, 'keyUsage', 'nonRepudiation'),      true);
        change(ticked(root, 'keyUsage', 'keyAgreement'),        true);
        change(ticked(root, 'extendedKeyUsage', 'serverAuth'),  true);
        field(root, '#request-form', 'otherExtendedKeyUsages').value = '1.2.3.4, 1.2.3.5';

        assert.equal(root.querySelector('#request-form [name="extendedKeyUsage"][value="clientAuth"]'), null, 'what the template is for is on offer beside itself');

        // An Ed448 key agrees on nothing: the usage is off, ticked or not.
        change(kind(root), 'ed448');
        await until(() => ticked(root, 'keyUsage', 'keyAgreement').disabled, 'a usage the kind of key cannot have is still on offer');

        assert.equal(template().value, 'modbus-tls', 'the template chosen went with the kind of key');

        submit(root, '#request-form');
        await until(() => root.querySelector('#just-made') !== null, 'the request is not shown');

        assert.deepEqual(madeWith, {
            kind:               'tlsIdentity',
            subject:            'cs001.example.org',
            algorithm:          'ed448',
            template:           'modbus-tls',
            role:               'ReadOnlySunSpec',
            keyUsages:          [ 'nonRepudiation' ],
            extendedKeyUsages:  [ 'serverAuth', '1.2.3.4', '1.2.3.5' ],
            usages:             [ 'meters' ],
            label:              'The meters\' reader'
        });

        assert.equal(template().value, 'tls-client', 'the template is still the one chosen');
        assert.equal(root.querySelector('#request-role'), null, 'the role of the template before is still asked for');

    });

    it('asks a server what it is reachable as, and keeps what was typed where the node refuses', async () => {

        const root = await opened(requests({ kinds: [ 'tlsServerIdentity' ], entries: [] }), '/configuration/server-identities?tab=request', undefined, serverIdentitiesPage);

        assert.equal(root.querySelector('#request-template'), null, 'one template is a choice');
        assert.equal(root.querySelector('#request-usages'), null, 'a kind without usages is asked what it is for');

        field(root, '#request-form', 'reachableAs').value = 'meter7.example.org, 192.0.2.7';

        submit(root, '#request-form');
        await until(() => root.querySelector('#request-error')?.textContent !== '', 'the refusal was not said');

        assert.equal(root.querySelector('#request-error')!.textContent, 'A certificate has to say who this charging station is.');
        assert.equal(field(root, '#request-form', 'reachableAs').value, 'meter7.example.org, 192.0.2.7', 'what was typed went');
        assert.deepEqual(madeWith, { kind: 'tlsServerIdentity', subject: '', algorithm: 'ecdsa-p256', keyUsages: [], extendedKeyUsages: [],
                                     reachableAs: [ 'meter7.example.org', '192.0.2.7' ] });

    });

    it('shows the keys that wait among what the node presents, each to copy, to remove - and to send to the CSMS where the node can', async () => {

        const without = await opened();
        const buttons = (root: HTMLElement, id: string) => [ ...root.querySelectorAll(`#waiting-keys [data-request="${id}"] button`) ].map(button => button.textContent!.trim());

        assert.ok(panel(without, 'usage').querySelector('#waiting-keys') !== null, 'the keys that wait are not among what the node presents');
        assert.deepEqual(waiting(without), [ 'aaaa', 'bbbb' ]);
        assert.deepEqual(buttons(without, 'aaaa'), [ 'Copy CSR', 'Remove' ], 'a node that cannot send a request offers to');

        const root   = await opened(requests({ canBeSentToCSMS: true }));
        const note   = () => root.querySelector('[data-request="aaaa"] [data-request-note]')!.textContent;
        const error  = () => root.querySelector('[data-request="aaaa"] [data-request-error]')!.textContent;
        const card   = (id: string) => root.querySelector(`[data-request-card="${id}"]`)!;
        const first  = card('aaaa');
        const second = card('bbbb');

        assert.deepEqual(buttons(root, 'aaaa'), [ 'Copy CSR', 'Send to CSMS', 'Remove' ]);

        csmsRefuses = 'The CSMS answered Rejected to SignCertificate.';

        root.querySelector<HTMLButtonElement>('[data-send-csr="aaaa"]')!.click();
        await until(() => error() === csmsRefuses, 'what the CSMS refused it with is not said beside the key');

        assert.match(first.querySelector('.request-head')!.textContent!, /request out/);

        csmsRefuses = null;

        root.querySelector<HTMLButtonElement>('[data-send-csr="aaaa"]')!.click();
        await until(() => note() === 'The CSMS accepted the request.', 'what the CSMS said is not said beside the key');

        assert.equal(error(), '', 'the refusal before is still said');
        assert.ok(card('aaaa') === first && card('bbbb') === second, 'a card was made anew');
        assert.match(first.querySelector('.request-head')!.textContent!,  /request sent to the CSMS/);
        assert.match(second.querySelector('.request-head')!.textContent!, /request out/);

        // Removed only once it was asked, and said yes to.
        confirmed = false;
        root.querySelector<HTMLButtonElement>('[data-remove-request="aaaa"]')!.click();

        assert.equal(asked.some(one => one.method === 'DELETE'), false, 'a key was removed without a yes');

        confirmed = true;
        root.querySelector<HTMLButtonElement>('[data-remove-request="aaaa"]')!.click();
        await until(() => waiting(root).length === 1, 'the key was not removed');

        assert.ok(card('bbbb') === second, 'the card of the key that stays was made anew');

        // And from there to where one is made.
        assert.equal(panel(root, 'request').hidden, true);

        root.querySelector<HTMLButtonElement>('#make-a-key')!.click();
        await until(() => !panel(root, 'request').hidden, 'the tab a key is made on is not shown');

    });

    it('says of a certificate that came back and cannot be held up that it is kept beside its key, and why', async () => {

        const root = await opened(requests({ entries: [ aKey('aaaa', { algorithm: 'ed448', algorithmName: 'Ed448',
                                                                       certificate: { subject: 'CN=aaaa', issuer: 'CN=Fleet CA', notAfter: '2027-10-01T00:00:00Z',
                                                                                      cannotBeHeldUp: 'This runtime cannot load a certificate together with a key of this kind.' } }) ] }));

        const card = root.querySelector('[data-request-card="aaaa"]')!;

        assert.match(card.querySelector('.request-head')!.textContent!, /cannot be held up/);
        assert.match(card.querySelector('.notice')!.textContent!, /issued by CN=Fleet CA[\s\S]*kept beside this key[\s\S]*This runtime cannot load/);

    });

    it('takes a certificate uploaded without its key as the answer to a request, which is an identity then and no key that waits', async () => {

        const root = await opened(requests(), '/configuration/identities?tab=upload');
        const box  = root.querySelector<HTMLTextAreaElement>('#upload-pem')!;

        // With its key it is an identity, as ever.
        type(box, '-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n');
        await until(() => root.querySelectorAll('#upload-found [data-found]').length === 1, 'what the box holds is not said');

        assert.equal(root.querySelector('#upload-found .an-answer'), null, 'a certificate with its key is taken for an answer');

        // Refused, it stays pasted, with why.
        type(box, '-----BEGIN CERTIFICATE-----\nREFUSE\n-----END CERTIFICATE-----');
        await until(() => root.querySelector('#upload-found .an-answer') !== null, 'the upload does not say the box holds an answer');

        submit(root, '#import-form');
        await until(() => root.querySelector('#import-error')?.textContent !== '', 'the refusal was not said');

        assert.match(root.querySelector('#import-error')!.textContent!, /belongs to a key of this charging station/);
        assert.match(box.value, /REFUSE/, 'what was pasted went');

        type(box, '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----');
        await until(() => root.querySelector('#upload-found .an-answer') !== null, 'the upload does not say the box holds an answer');

        submit(root, '#import-form');
        await until(() => /^Taken in/.test(root.querySelector('#import-note')?.textContent ?? ''), 'the certificate was not taken in');

        assert.equal(root.querySelector('#import-note')!.textContent,
                     'Taken in: aaaa is a TLS identity of this charging station now. It runs out in 20 day(s).');
        assert.equal(box.value, '', 'the certificate taken in is still pasted');
        assert.deepEqual(waiting(root), [ 'bbbb' ], 'the key whose certificate came still waits');
        assert.ok(panel(root, 'usage').querySelector('section[data-kind="tlsIdentity"] [data-toggle^="1111111111111111"]') !== null
               || /aaaa/.test(panel(root, 'usage').querySelector('section[data-kind="tlsIdentity"]')!.textContent!),
                  'the identity it became is not among the identities');

        // A node that makes no keys takes no answers: a certificate without its key is no identity.
        const none = await opened(null, '/configuration/identities?tab=upload');

        type(none.querySelector<HTMLTextAreaElement>('#upload-pem')!, '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----');
        await until(() => none.querySelectorAll('#upload-found [data-found]').length === 1, 'what the box holds is not said');

        assert.equal(none.querySelector('#upload-found .an-answer'), null, 'a node that makes no keys takes a certificate for an answer');

    });

});
