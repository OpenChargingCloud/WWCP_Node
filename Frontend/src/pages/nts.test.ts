/**
 * The NTS page drawn, in a document of happy-dom, against a node that is a
 * stand-in for fetch: what is typed into one of its two forms outlives the
 * other being saved and "Sync now" being answered, and the form saved shows
 * what the node took.
 */

import '../../test/dom.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { Clock, NTSConfiguration, NTSUpdate } from '../api/client.ts';

const { auth }             = await import('../auth.ts');
const { configureShell }   = await import('../shell.ts');
const { ntsPage }          = await import('./nts.ts');


let held: NTSConfiguration;
const told: NTSUpdate[] = [];
let synced = 0;

function aConfiguration(): NTSConfiguration {
    return {
        enabled:      true,
        timeSources:  [ { hostname: 'ptbtime1.ptb.de', priority: 0, ntsKEPort: 4460, ntpPort: 123, enabled: true },
                        { hostname: 'ptbtime2.ptb.de', priority: 0, ntsKEPort: 4460, ntpPort: 123, enabled: true } ],
        group:        { name: 'ptb', minServers: 2, maxDeviationSeconds: 0.5 },
        settings:     { timeoutSeconds: null, checkEverySeconds: 900, minServers: 2, maxDeviationSeconds: 0.5,
                        legalTimeAuthority: null, legalTimeToleranceSeconds: 1, legalTimeMaxAgeSeconds: 3600 },
        policy:       {},
        lastSync:     null,
        limits:       { maxTimeout: 30, minCheckEvery: 60, maxCheckEvery: 86400, minDeviation: 0.001, maxDeviation: 60,
                        minTolerance: 0.001, maxTolerance: 60, minMaxAge: 60, maxMaxAge: 86400, maxAuthorityLength: 100,
                        defaultNTSKEPort: 4460, defaultNTPPort: 123 },
        file:         'nts.json'
    } as unknown as NTSConfiguration;
}

const aClock = (): Clock => ({
    now: '2026-10-04T12:00:00Z', source: 'system',
    nts: { enabled: true, group: 'ptb', server: null, servers: null, minServers: 2, lastServer: null, asked: null, answered: null,
           checkedAt: null, ageSeconds: null, offset_ms: null, everySeconds: 900 },
    legal: false, authority: null, why: 'notClaimed', toleranceSeconds: 1, maxAgeSeconds: 3600
}) as unknown as Clock;

const answer = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {

    const url     = String(input);
    const method  = init?.method ?? 'GET';

    if (url.endsWith('/clock'))
        return answer(aClock());

    if (url.endsWith('/configuration/nts/sync')) {
        synced++;
        return answer({ ...held, result: { ok: true, at: '2026-10-04T12:00:01Z', servers: [],
                                           group: { answered: 2, required: 2, offset_ms: 0.4, spread_ms: 0.1 } } });
    }

    if (url.endsWith('/configuration/nts') && method === 'PUT') {
        const update = JSON.parse(String(init!.body)) as NTSUpdate;
        told.push(update);
        // A node takes what it takes: a check every minute at the most often.
        if (update.checkEverySeconds !== undefined)
            update.checkEverySeconds = Math.max(update.checkEverySeconds, 60);
        held = { ...held, settings: { ...held.settings,
                                      ...Object.fromEntries(Object.entries(update).filter(([ key ]) => key in held.settings)) } };
    }

    if (url.endsWith('/configuration/nts'))
        return answer(held);

    return new Response('{}', { status: 404, headers: { 'Content-Type': 'application/json' } });

}) as typeof fetch;


const wait = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));

async function until(what: () => boolean, said: string): Promise<void> {
    for (let i = 0; i < 200 && !what(); i++)
        await wait(5);
    assert.ok(what(), said);
}

async function opened(): Promise<HTMLElement> {

    held        = aConfiguration();
    told.length = 0;
    synced      = 0;

    configureShell({ name: 'Test node', icon: 'fa-gear', menu: [] });
    auth.set({ username: 'alice', roles: [ 'admin' ], permissions: [ 'nts:edit', 'nts:run' ], mayReadTheLog: false } as never);

    const root = document.createElement('div');
    document.body.replaceChildren(root);

    ntsPage.render({ root, url: new URL('http://127.0.0.1/configuration/nts'), params: {}, navigate: () => undefined } as never);

    await until(() => root.querySelector('#legal-form') !== null, 'the page did not draw its forms');

    return root;

}

const field = (root: HTMLElement, form: string, name: string) => root.querySelector<HTMLInputElement>(`#${form} [name="${name}"]`)!;

/** Sent as the browser sends it once the form is valid; happy-dom's step check is not a browser's. */
const submit = (root: HTMLElement, form: string) =>
    root.querySelector<HTMLFormElement>(`#${form}`)!.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));


describe('the NTS page', () => {

    it('keeps what is typed into what counts as legal time, and its focus, while the group policy is saved and "Sync now" answers', async () => {

        const root      = await opened();
        const authority = field(root, 'legal-form', 'legalTimeAuthority');

        authority.value = 'PTB';
        authority.focus();

        submit(root, 'policy-form');
        await until(() => root.querySelector('#policy-note')?.textContent === 'Saved, and in effect.', 'the policy was not saved');

        root.querySelector<HTMLButtonElement>('#sync')!.click();
        await until(() => synced === 1 && root.querySelector('.sync-verdict') !== null, '"Sync now" was not answered');

        assert.equal(field(root, 'legal-form', 'legalTimeAuthority'), authority, 'the field was made anew');
        assert.equal(authority.value,           'PTB',     'what was typed is gone');
        assert.equal(document.activeElement,    authority, 'the focus went');
        assert.deepEqual(told.map(update => Object.keys(update).includes('legalTimeAuthority')), [ false ],
                         'the policy carried what is typed into the other form');

    });

    it('shows the group policy as the node took it once it is saved, with nothing left to save', async () => {

        const root  = await opened();
        const every = field(root, 'policy-form', 'checkEverySeconds');

        every.value = '30';

        submit(root, 'policy-form');
        await until(() => root.querySelector('#policy-note')?.textContent === 'Saved, and in effect.', 'the policy was not saved');

        assert.equal(told[0]!.checkEverySeconds, 60, 'the stand-in node took sixty, not the thirty typed');
        assert.equal(field(root, 'policy-form', 'checkEverySeconds').value,         '60', 'the field says what was typed, not what the node took');
        assert.equal(field(root, 'policy-form', 'checkEverySeconds').defaultValue,  '60', 'the field still counts as typed into');

    });

});
