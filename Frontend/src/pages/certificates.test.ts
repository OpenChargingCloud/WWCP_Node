/**
 * What the certificates page says about one certificate: its state, and what
 * the node has chosen it for - and, drawn in a document of happy-dom against a
 * node that is a stand-in for fetch, that a change of one certificate leaves
 * an import being filled in alone, and that an import that went through
 * leaves an empty one.
 */

import { chromeTakesTheFocus } from '../../test/dom.ts';

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';

import type { Certificate, CertificateStore } from '../api/client.ts';

document.head.innerHTML = '<meta name="node-name" content="local controller">';

const { believedHint, certificatesPage, marksOf, stateOf } = await import('./certificates.ts');
const { auth }             = await import('../auth.ts');
const { configureShell }   = await import('../shell.ts');
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

    async function opened(options:  Parameters<typeof certificatesPage>[0] = {},
                          shape:    (store: CertificateStore) => void = () => undefined): Promise<HTMLElement> {

        held         = aStore();
        shape(held);
        refuse       = false;
        asked.length = 0;

        configureShell({ name: 'Test node', icon: 'fa-gear', menu: [] });
        auth.set({ username: 'alice', roles: [ 'admin' ], permissions: [ 'certificates:read', 'certificates:edit' ], mayReadTheLog: false } as never);

        const root = document.createElement('div');
        document.body.replaceChildren(root);

        certificatesPage(options).render({ root, url: new URL('http://127.0.0.1/configuration/certificates'), params: {}, navigate: () => undefined } as never);

        await until(() => root.querySelector('#import-form') !== null || root.querySelector('.error-box') !== null, 'the page did not draw');

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

        assert.ok(label(root) === typed,                       'the field was made anew');
        assert.equal(typed.value,            'half filled in', 'what was typed into the import is gone');
        assert.equal(kind(root).value,       'tlsIdentity',    'the kind chosen for the import is gone');
        assert.ok(document.activeElement === typed, 'the focus went');

    });

    it('gives the focus back to the label typed into once a certificate is switched off, as a browser takes it away', async () => {

        const root    = await opened();
        const browser = chromeTakesTheFocus(root);

        choose(root, 'tlsIdentity');
        const typed = label(root);
        typed.value = 'half filled in';
        typed.focus();

        root.querySelector<HTMLButtonElement>('[data-toggle="aaaaaaaaaaaaaaaa"]')!.click();
        await until(() => root.querySelector('[data-toggle="aaaaaaaaaaaaaaaa"]')?.textContent?.trim() === 'Switch on',
                    'the certificate was not switched off');
        browser.disconnect();

        assert.ok(label(root) === typed,             'the field was made anew');
        assert.equal(typed.value, 'half filled in');
        assert.ok(document.activeElement === typed,  'the focus went, and was not given back');

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


describe('the certificates page, as a kind of node adds to it', () => {

    let held: CertificateStore;
    let loads = 0;
    let refuseTheSection = false;

    const anIdentity = certificate({ id: 'cccccccccccccccc', kind: 'tlsIdentity', label: 'Meter A', usages: null });

    const aStore = (): CertificateStore => ({
        directory:           'certs',
        trustAnchors:        [ 'tlsRoot' ],
        credentials:         [ 'tlsIdentity' ],
        recognised:          [],
        kinds:               { tlsRoot:      { description: 'TLS roots',    usages: [ 'dns', 'nts' ] },
                               tlsIdentity:  { description: 'TLS identity', usages: [ 'modbus', 'web' ] } },
        usages:              [],
        certificates:        { tlsRoot: [ certificate({ id: 'aaaaaaaaaaaaaaaa', kind: 'tlsRoot', label: 'Root A', hasPrivateKey: false }) ],
                               tlsIdentity: [ { ...anIdentity } ] },
        keysAreUnencrypted:  false,
        // What a meter's store says beyond every node's.
        listeners:           [ 'modbus' ]
    } as unknown as CertificateStore);

    const answer = (body: unknown, status = 200) =>
        new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

    const wait = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));

    async function until(what: () => boolean, said: string): Promise<void> {
        for (let i = 0; i < 200 && !what(); i++)
            await wait(5);
        assert.ok(what(), said);
    }

    async function opened(options: Parameters<typeof certificatesPage>[0]): Promise<HTMLElement> {

        held             = aStore();
        loads            = 0;
        refuseTheSection = false;

        globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
            if ((init?.method ?? 'GET') === 'PATCH') {
                const entry = held.certificates['tlsRoot']![0]!;
                entry.active = JSON.parse(String(init!.body)).active ?? entry.active;
                return answer(entry);
            }
            if (String(input).endsWith('/certificates') || String(input).endsWith('/certificates/reload'))
                return answer(held);
            return answer({}, 404);
        }) as typeof fetch;

        configureShell({ name: 'Test node', icon: 'fa-gear', menu: [] });
        auth.set({ username: 'alice', roles: [ 'admin' ], permissions: [ 'certificates:read', 'certificates:edit' ], mayReadTheLog: false } as never);

        const root = document.createElement('div');
        document.body.replaceChildren(root);

        certificatesPage(options).render({ root, url: new URL('http://127.0.0.1/configuration/certificates'), params: {}, navigate: () => undefined } as never);

        await until(() => root.querySelector('#import-form') !== null || root.querySelector('.error-box') !== null, 'the page did not draw');

        return root;

    }

    const card = (root: HTMLElement, kind: string) => root.querySelector<HTMLElement>(`section[data-kind="${kind}"]`)!;


    it('names a kind, with its icon and its hint, as the kind of node calls it, and says in the dialog what one is for', async () => {

        const root = await opened({ kinds: { tlsIdentity: { title: 'TLS identities', icon: 'fa-id-card',
                                                            hint: html`Shown to <strong>charging stations</strong>.`,
                                                            uses: html`A listener only ever shows an identity that is for it.` } } });

        const heading = card(root, 'tlsIdentity').querySelector('h3')!;

        assert.equal(heading.textContent!.trim(), 'TLS identities');
        assert.ok(heading.querySelector('i.fa-id-card') !== null, 'the icon is not in the heading');
        assert.equal(card(root, 'tlsIdentity').querySelector('p.hint strong')?.textContent, 'charging stations', 'the hint is not drawn as markup');
        assert.equal(card(root, 'tlsRoot').querySelector('h3')!.textContent!.trim(), 'TLS roots', 'a kind not named lost the store\'s description');

        root.querySelector<HTMLButtonElement>('[data-usages="cccccccccccccccc"]')!.click();
        await until(() => document.querySelector('dialog #usages-form') !== null, 'the dialog did not open');
        assert.match(document.querySelector('dialog')!.textContent!, /A listener only ever shows an identity that is for it\./);
        document.querySelector('dialog')!.remove();

    });

    it('says what the kind of node has to say at the top, and beside a certificate\'s name', async () => {

        const root = await opened({
            notices:   store => (store as CertificateStore & { listeners: string[] }).listeners.map(listener => html`The ${listener} listener has nothing to show.`),
            rowChips:  entry => entry.kind === 'tlsIdentity' ? [ html`<span class="chip ok">shown on Modbus/TLS</span>` ] : []
        });

        assert.ok([ ...root.querySelectorAll('.notice') ].some(notice => notice.textContent!.trim() === 'The modbus listener has nothing to show.'),
                  'the notice is not at the top');
        assert.equal(card(root, 'tlsIdentity').querySelector('.row-chips .chip.ok')?.textContent, 'shown on Modbus/TLS');
        assert.equal(card(root, 'tlsRoot').querySelector('.row-chips'), null, 'a row with nothing to add has a line for it');
        assert.equal(card(root, 'tlsIdentity').querySelector('.usages-of .chip')?.textContent, 'on every listener',
                     'an identity for every listener is said to be for every use');

    });

    it('draws a section at the end of its group, asks for what it needs with the store, and keeps what is typed into it', async () => {

        let shownAt = 0;

        const root = await opened({
            sections: context => [ {
                below:  'presents',
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

        assert.ok(card(root, 'tlsIdentity').compareDocumentPosition(section) & Node.DOCUMENT_POSITION_FOLLOWING,
                  'the section is not below what the node presents');
        assert.equal(loads, 1, 'what the section needs was not asked for with the store');
        assert.ok(root.querySelector('#may') !== null, 'the section was not told the person may change the store');

        const subject = root.querySelector<HTMLInputElement>('#request-form [name="subject"]')!;
        subject.value = 'CN=meter7.lan';
        subject.focus();

        root.querySelector<HTMLButtonElement>('[data-toggle="aaaaaaaaaaaaaaaa"]')!.click();
        await until(() => loads === 2 && root.querySelector('[data-toggle="aaaaaaaaaaaaaaaa"]')?.textContent?.trim() === 'Switch on',
                    'the section was not asked again with the store after a change');

        assert.ok(root.querySelector('#request-form [name="subject"]') === subject, 'the section\'s field was made anew');
        assert.equal(subject.value, 'CN=meter7.lan');
        assert.ok(document.activeElement === subject, 'the focus went');
        assert.match(root.querySelector('#requests h2')!.textContent!, /loaded 2 time/);

        root.querySelector<HTMLButtonElement>('#again')!.click();
        await until(() => loads === 3, 'the section could not ask for the store and its own again');

        root.querySelector<HTMLButtonElement>('#rescan')!.click();
        await until(() => loads === 4 && (root.querySelector('#store-note')?.textContent ?? '').startsWith('The directory was read again'),
                    'the section was not asked again when the directory was read again');

    });

    it('holds what is typed into a section\'s form as a draft, and empties it, and the section\'s choices, on Reload', async () => {

        let chosen: string | undefined;

        const root = await opened({
            sections: context => [ {
                below:  'presents',
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
            hints:     { presents:   store => html`Shown on ${(store as CertificateStore & { listeners: string[] }).listeners.length} listener(s).`,
                         importing:  html`A certificate for a key made here goes in <em>under Signing requests</em>.` },
            sections:  context => { page = context.page; return []; }
        });

        assert.ok([ ...root.querySelectorAll('p.hint') ].some(said => said.textContent!.trim() === 'Shown on 1 listener(s).'),
                  'the hint from the store is not said');
        assert.ok([ ...root.querySelectorAll('#import-form p.hint em') ].some(em => em.textContent === 'under Signing requests'), 'the import\'s hint is not said');
        assert.ok(page !== undefined && page === root.querySelector('#content-body'), 'the section was not handed the element the page draws into');

    });

    it('says the page could not be loaded where what a section needs could not be', async () => {

        const root = await opened({
            sections: () => [ { below: 'believes', load: async () => { throw new Error('no requests'); }, draw: () => html`<p id="never"></p>` } ]
        });

        assert.match(root.querySelector('.error-box')?.textContent ?? '', /could not be loaded: no requests/);
        assert.equal(root.querySelector('#never'), null);

    });

    it('takes a template of view.ts for what it says under a group, as well as a fragment of html.ts', async () => {

        const root = await opened({ hints: { believes: html`Roots <em>this meter</em> believes.` } });

        assert.ok([ ...root.querySelectorAll('p.hint em') ].some(em => em.textContent === 'this meter'), 'the hint is not drawn as markup');

    });

});
