/**
 * The DNS page drawn, in a document of happy-dom, against a node that is a
 * stand-in for fetch: what somebody typed and has not saved is still there
 * after something else on the page was saved, and what was saved shows what
 * the node took.
 */

import { chromeTakesTheFocus } from '../../test/dom.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { DNSConfiguration, DNSUpdate } from '../api/client.ts';

const { auth }             = await import('../auth.ts');
const { configureShell }   = await import('../shell.ts');
const { dnsPage }          = await import('./dns.ts');


/** What the stand-in node has, and what it was told. */
let held: DNSConfiguration;
const told: DNSUpdate[] = [];

function aConfiguration(): DNSConfiguration {
    return {
        enabled:   true,
        servers:   [ { address: '192.0.2.53', port: 53, transport: 'UDP', queryTimeoutSeconds: null } ],
        settings:  { useCache: true, dnssecOK: false, followCNAMEs: true, recursionDesired: null,
                     queryTimeoutSeconds: 2, maxCNAMEFollows: 8, maxRetries: 2 },
        fixed:     { cacheSize: 1000 },
        limits:    { maxServers: 4, maxQueryTimeout: 30, transports: [ 'UDP', 'TCP', 'TLS', 'HTTPS' ], recordTypes: [ 'A', 'AAAA' ] },
        file:      'dns.json'
    } as unknown as DNSConfiguration;
}

globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {

    const url     = String(input);
    const method  = init?.method ?? 'GET';

    if (url.endsWith('/configuration/dns') && method === 'PUT') {
        const update = JSON.parse(String(init!.body)) as DNSUpdate;
        told.push(update);
        // A node takes what it takes: no more than five retries.
        if (update.maxRetries !== undefined)
            update.maxRetries = Math.min(update.maxRetries, 5);
        held = { ...held, ...(update.enabled !== undefined ? { enabled: update.enabled } : {}),
                          ...(update.servers !== undefined ? { servers: update.servers as DNSConfiguration['servers'] } : {}),
                          settings: { ...held.settings,
                                      ...Object.fromEntries(Object.entries(update).filter(([ key ]) => key in held.settings)) } };
    }

    if (url.endsWith('/configuration/dns'))
        return new Response(JSON.stringify(held), { status: 200, headers: { 'Content-Type': 'application/json' } });

    return new Response('{}', { status: 404, headers: { 'Content-Type': 'application/json' } });

}) as typeof fetch;


const wait = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));

async function until(what: () => boolean, said: string): Promise<void> {
    for (let i = 0; i < 200 && !what(); i++)
        await wait(5);
    assert.ok(what(), said);
}

/** The DNS page, drawn and loaded, for somebody who may change and test it. */
async function opened(): Promise<HTMLElement> {

    held        = aConfiguration();
    told.length = 0;

    configureShell({ name: 'Test node', icon: 'fa-gear', menu: [] });
    auth.set({ username: 'alice', roles: [ 'admin' ], permissions: [ 'dns:edit', 'dns:run' ], mayReadTheLog: false } as never);

    const root = document.createElement('div');
    document.body.replaceChildren(root);

    dnsPage.render({ root, url: new URL('http://127.0.0.1/configuration/dns'), params: {}, navigate: () => undefined } as never);

    await until(() => root.querySelector('#dns-form') !== null, 'the page did not draw its settings');

    return root;

}

const field   = (root: HTMLElement, name: string) => root.querySelector<HTMLInputElement>(`#dns-form [name="${name}"]`)!;
const address = (root: HTMLElement) => root.querySelector<HTMLInputElement>('[data-field="address"]')!;


describe('the DNS page', () => {

    it('keeps what is typed into the settings and into the list when name resolution is switched off', async () => {

        const root = await opened();

        const retries = field(root, 'maxRetries');
        retries.value = '7';
        retries.dispatchEvent(new Event('input', { bubbles: true }));

        address(root).value = '198.51.100.1';
        address(root).dispatchEvent(new Event('input', { bubbles: true }));

        const enabled = root.querySelector<HTMLInputElement>('#enabled')!;
        enabled.checked = false;
        enabled.dispatchEvent(new Event('change', { bubbles: true }));

        await until(() => root.querySelector('label.switch span')?.textContent === 'switched off', 'the switch was not saved');

        assert.deepEqual(told, [ { enabled: false } ], 'the switch saves only itself');
        assert.equal(field(root, 'maxRetries').value, '7',            'what was typed into the settings is gone');
        assert.equal(address(root).value,             '198.51.100.1', 'what was typed into the list of servers is gone');

    });

    it('gives the focus back to the field typed into once name resolution is switched, as a browser takes it away', async () => {

        const root    = await opened();
        const retries = field(root, 'maxRetries');

        const browser = chromeTakesTheFocus(root);

        retries.value = '7';
        retries.focus();

        const enabled = root.querySelector<HTMLInputElement>('#enabled')!;
        enabled.checked = false;
        enabled.dispatchEvent(new Event('change', { bubbles: true }));

        await until(() => root.querySelector('label.switch span')?.textContent === 'switched off', 'the switch was not saved');
        browser.disconnect();

        // ok() and not equal(): a message of equal() would print the two
        // elements, and with them all of happy-dom's window.
        assert.ok(field(root, 'maxRetries') === retries,  'the field was made anew');
        assert.ok(document.activeElement === retries,     'the focus went, and was not given back');

    });

    it('keeps the field that has the focus, where it is, when a server is added above it', async () => {

        const root    = await opened();
        const retries = field(root, 'maxRetries');

        retries.value = '7';
        retries.focus();

        root.querySelector<HTMLButtonElement>('#add-server')!.click();
        await wait();

        assert.equal(root.querySelectorAll('[data-field="address"]').length, 2, 'no server was added');
        assert.ok(field(root, 'maxRetries') === retries, 'the field was made anew');
        assert.ok(document.activeElement === retries, 'the focus went');
        assert.equal(retries.value,             '7');

    });

    it('keeps what is typed into a row with its row, when a row above it is removed', async () => {

        const root = await opened();

        root.querySelector<HTMLButtonElement>('#add-server')!.click();
        await wait();

        const [ first, second ] = [ ...root.querySelectorAll<HTMLInputElement>('[data-field="address"]') ];
        first!.value = '198.51.100.1';
        first!.dispatchEvent(new Event('input', { bubbles: true }));
        second!.value = '203.0.113.9';
        second!.dispatchEvent(new Event('input', { bubbles: true }));

        root.querySelector<HTMLButtonElement>('[data-remove="0"]')!.click();
        await wait();

        const rows = root.querySelectorAll<HTMLInputElement>('[data-field="address"]');

        assert.equal(rows.length,     1);
        assert.equal(rows[0]!.value,  '203.0.113.9', 'what was typed into the second row went with the first');
        assert.ok(rows[0] === second, 'the second row was not kept, but the first given its values');

    });

    it('shows the settings as the node took them once they are saved, with nothing left to save', async () => {

        const root = await opened();

        const retries = field(root, 'maxRetries');
        retries.value = '7';
        retries.dispatchEvent(new Event('input', { bubbles: true }));

        // Sent as the browser sends it once the form is valid: happy-dom finds
        // 2 a step mismatch for min 0.1 and step 0.1, which a browser, which
        // counts the steps in decimals, does not - and then sends nothing.
        root.querySelector<HTMLFormElement>('#dns-form')!.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));

        await until(() => root.querySelector('#form-note')?.textContent === 'Saved, and in effect.', 'the settings were not saved');

        assert.equal(told.length, 1);
        assert.equal(told[0]!.maxRetries, 5, 'the stand-in node took five, not the seven typed');
        assert.equal(field(root, 'maxRetries').value,         '5', 'the field says what was typed, not what the node took');
        assert.equal(field(root, 'maxRetries').defaultValue,  '5', 'the field still counts as typed into, as if not saved');

    });


    it('reloads what the node has with the Reload beside its heading, once it has asked about what is typed', async () => {

        const root = await opened();

        const retries = field(root, 'maxRetries');
        retries.value = '7';
        retries.dispatchEvent(new Event('input', { bubbles: true }));

        // Changed on the node meanwhile.
        held = { ...held, settings: { ...held.settings, maxRetries: 4 } };

        const asked = [] as string[];
        window.confirm = (text?: string) => { asked.push(String(text)); return true; };

        root.querySelector<HTMLButtonElement>('.page-actions #reload')!.click();

        await until(() => field(root, 'maxRetries').value === '4', 'the page did not reload what the node has');

        assert.equal(asked.length, 1, 'what was typed was thrown away without a question');

    });

});
