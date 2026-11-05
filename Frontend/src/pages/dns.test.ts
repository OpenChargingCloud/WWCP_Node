/**
 * The DNS page drawn, in a document of happy-dom, against a node that is a
 * stand-in for fetch: what somebody typed and has not saved is still there
 * after something else on the page was saved, and what was saved shows what
 * the node took.
 */

import { open, refused, said, until, type Asked } from '../../test/node.ts';
import { chromeTakesTheFocus }           from '../../test/dom.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { DNSConfiguration, DNSUpdate } from '../api/client.ts';

const { dnsPage } = await import('./dns.ts');


/** What the stand-in node has, and what it was told. */
let held: DNSConfiguration;
const told: DNSUpdate[] = [];

/** Why the stand-in node would not go back to the servers it was started with, where it would not. */
let refusing: string | null = null;

/** The servers the stand-in node was started with. */
const startedWith = (): DNSConfiguration['servers'] =>
    [ { address: '10.0.0.53', port: 53, transport: 'UDP', queryTimeoutSeconds: null } ] as DNSConfiguration['servers'];

function aConfiguration(): DNSConfiguration {
    return {
        enabled:   true,
        servers:   [ { address: '192.0.2.53', port: 53, transport: 'UDP', queryTimeoutSeconds: null } ],
        serversFrom:  'file',
        settings:  { useCache: true, dnssecOK: false, followCNAMEs: true, recursionDesired: null,
                     queryTimeoutSeconds: 2, maxCNAMEFollows: 8, maxRetries: 2, encryptedOnly: false },
        fixed:     { cacheSize: 1000 },
        limits:    { maxServers: 4, maxQueryTimeout: 30, transports: [ 'UDP', 'TCP', 'TLS', 'HTTPS' ], recordTypes: [ 'A', 'AAAA' ] },
        file:      'dns.json'
    } as unknown as DNSConfiguration;
}

/** How the stand-in node answers. */
function node({ method, path, body }: Asked): unknown {

    if (path === '/configuration/dns' && method === 'PUT') {
        const update = body as DNSUpdate;
        told.push(update);
        if (update.servers === null && refusing !== null)
            return refused(400, refusing);
        // A node takes what it takes: no more than five retries.
        if (update.maxRetries !== undefined)
            update.maxRetries = Math.min(update.maxRetries, 5);
        held = { ...held, ...(update.enabled !== undefined ? { enabled: update.enabled } : {}),
                          ...(update.servers === null      ? { servers: startedWith(), serversFrom: 'start' as const } :
                              update.servers !== undefined ? { servers: update.servers as DNSConfiguration['servers'], serversFrom: 'file' as const } : {}),
                          settings: { ...held.settings,
                                      ...Object.fromEntries(Object.entries(update).filter(([ key ]) => key in held.settings)) } };
    }

    if (path === '/configuration/dns')
        return held;

    return undefined;

}

const wait = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * The DNS page, drawn and loaded, for somebody who may change and test it.
 *
 * @param given  what to change about the configuration the node has first.
 */
async function opened(given?: (configuration: DNSConfiguration) => void): Promise<HTMLElement> {

    held        = aConfiguration();
    told.length = 0;
    refusing    = null;

    given?.(held);

    return open(dnsPage, '/configuration/dns', [ 'dns:edit', 'dns:run' ], node, root => root.querySelector('#dns-form') !== null);

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


    it('sends with the settings whether only encrypted name servers are asked', async () => {

        const root = await opened();

        field(root, 'encryptedOnly').checked = true;

        root.querySelector<HTMLFormElement>('#dns-form')!.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));

        await until(() => root.querySelector('#form-note')?.textContent === 'Saved, and in effect.', 'the settings were not saved');

        assert.equal(told.length,                         1);
        assert.equal(told[0]!.encryptedOnly,              true,  'the switch was not sent');
        assert.equal(field(root, 'encryptedOnly').checked, true, 'the switch does not show what the node took');

    });

    it('warns of a server in clear text beside encrypted ones, and says it is not asked where only encrypted ones are', async () => {

        const servers = (configuration: DNSConfiguration) => {
            configuration.servers = [ { address: '192.0.2.53', port: 53,  transport: 'UDP', queryTimeoutSeconds: null },
                                      { address: '192.0.2.54', port: 853, transport: 'TLS', queryTimeoutSeconds: null } ] as DNSConfiguration['servers'];
        };

        const mixed = await opened(servers);

        assert.match(mixed.querySelector('#mixed-transports')?.textContent ?? '', /192\.0\.2\.53\s+is asked in clear text/,
                     'a server in clear text beside an encrypted one was not warned about');
        assert.equal(mixed.querySelector('[data-not-asked]'), null, 'a server is said not to be asked, which is');

        const encryptedOnly = await opened(configuration => { servers(configuration); configuration.settings.encryptedOnly = true; });

        assert.equal(encryptedOnly.querySelector('#mixed-transports'), null, 'warned about a server that is not asked');
        assert.ok   (encryptedOnly.querySelector('[data-not-asked="0"]') !== null, 'the server in clear text is not said to be not asked');
        assert.equal(encryptedOnly.querySelector('[data-not-asked="1"]'), null, 'the encrypted server is said not to be asked');

    });

    it('goes back to the servers the node was started with, after asking, and keeps what is typed into the settings', async () => {

        const root = await opened();

        const retries = field(root, 'maxRetries');
        retries.value = '7';
        retries.dispatchEvent(new Event('input', { bubbles: true }));

        address(root).value = '198.51.100.1';
        address(root).dispatchEvent(new Event('input', { bubbles: true }));

        root.querySelector<HTMLButtonElement>('#back-to-start')!.click();

        await until(() => root.querySelector('#servers-note')?.textContent === 'Saved, and in effect.', 'going back was not saved, or not said under the servers');

        assert.equal(said.length, 1, 'the list went without a question');
        assert.match(said[0]!, /held to no certificate/, 'the question does not say what goes with the list');
        assert.deepEqual(told, [ { servers: null } ], 'not only the way back was sent');

        const rows = root.querySelectorAll<HTMLInputElement>('[data-field="address"]');
        assert.equal(rows.length,     1);
        assert.equal(rows[0]!.value,  '10.0.0.53', 'the list does not show the servers the node was started with');

        // ok() and not equal(): a message of equal() would print the button,
        // and with it all of happy-dom's window.
        assert.ok(root.querySelector('#back-to-start') === null, 'there is a way back to where the servers are');
        assert.match(root.querySelector('#servers-from')?.textContent ?? '', /These are the ones .* was started with/,
                     'it is not said where the servers are from');
        assert.equal(field(root, 'maxRetries').value, '7', 'what was typed into the settings is gone');
        assert.equal(root.querySelector('#form-note')?.textContent, '', 'said under the settings, which were not saved');

    });

    it('sends nothing, and keeps the list, where going back is not wanted', async () => {

        const root = await opened();

        address(root).value = '198.51.100.1';
        address(root).dispatchEvent(new Event('input', { bubbles: true }));

        const yes = window.confirm;
        window.confirm = (text?: string) => { said.push(String(text)); return false; };

        try
        {
            root.querySelector<HTMLButtonElement>('#back-to-start')!.click();
            await wait(20);
        }
        finally
        {
            window.confirm = yes;
        }

        assert.equal(said.length, 1, 'nothing was asked');
        assert.deepEqual(told, [], 'went back all the same');
        assert.equal(address(root).value, '198.51.100.1', 'what was typed into the list is gone');

    });

    it('says the servers are the ones the node was started with, with no way back to where they are', async () => {

        const root = await opened(configuration => { configuration.serversFrom = 'start'; });

        assert.ok(root.querySelector('#back-to-start') === null, 'there is a way back to where the servers are');
        assert.match(root.querySelector('#servers-from')?.textContent ?? '', /These are the ones .* was started with/,
                     'it is not said where the servers are from');

    });

    it('says under the servers why the node would not go back, and keeps the list', async () => {

        const root = await opened();

        refusing = "'dns.servers': the name servers this node was started with are asked in clear text";

        root.querySelector<HTMLButtonElement>('#back-to-start')!.click();

        await until(() => /in clear text/.test(root.querySelector('#servers-error')?.textContent ?? ''), 'the refusal was not said under the servers');

        assert.equal(root.querySelector('#form-error')?.textContent, '', 'the refusal was said under the settings');
        assert.equal(address(root).value, '192.0.2.53', 'the list is not the one the node still has');
        assert.ok(root.querySelector('#back-to-start') !== null, 'the way back went, which was not taken');

    });

    it('reloads what the node has with the Reload beside its heading, once it has asked about what is typed', async () => {

        const root = await opened();

        const retries = field(root, 'maxRetries');
        retries.value = '7';
        retries.dispatchEvent(new Event('input', { bubbles: true }));

        // Changed on the node meanwhile.
        held = { ...held, settings: { ...held.settings, maxRetries: 4 } };

        root.querySelector<HTMLButtonElement>('.page-actions #reload')!.click();

        await until(() => field(root, 'maxRetries').value === '4', 'the page did not reload what the node has');

        assert.equal(said.length, 1, 'what was typed was thrown away without a question');

    });

});
