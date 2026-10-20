/**
 * The NTS page drawn, in a document of happy-dom, against a node that is a
 * stand-in for fetch: what is typed into one of its two forms outlives the
 * other being saved and "Sync now" being answered, and the form saved shows
 * what the node took - and its groups of time servers, a tab each, made in
 * the "+" tab and taken away switched off.
 */

import { open, refused, said, until, type Asked } from '../../test/node.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { Clock, NTSConfiguration, NTSGroups, NTSGroupSummary, NTSUpdate } from '../api/client.ts';

const { ntsPage } = await import('./nts.ts');


/** The legal group, which every test but the ones without it has first. */
let held: NTSConfiguration;

/** Every group of the stand-in node, in its order: the legal one, and whatever a test gives it. */
let groupsHeld: NTSConfiguration[] = [];

/** What the page told a group, by PUT; made by POST; and taken away by DELETE. */
const told:     NTSUpdate[] = [];
const made:     unknown[]   = [];
const removed:  string[]    = [];

/** What the stand-in node says of its clock, over aClock(). */
let clockSays: Partial<Clock> = {};

/** The certificate the first server showed, and a root the store keeps for NTS: 64 digits each. */
const shownPrint = 'ab'.repeat(32);
const rootPrint  = 'cd'.repeat(32);
let synced = 0;

function aConfiguration(): NTSConfiguration {
    return {
        id:           'legal',
        displayName:  null,
        legal:        true,
        enabled:      true,
        timeSources:  [ { hostname: 'ptbtime1.ptb.de', priority: 0, ntsKEPort: 4460, ntpPort: 123, enabled: true },
                        { hostname: 'ptbtime2.ptb.de', priority: 0, ntsKEPort: 4460, ntpPort: 123, enabled: true } ],
        group:        { name: 'ptb', minServers: 2, maxDeviationSeconds: 0.5 },
        settings:     { timeoutSeconds: null, checkEverySeconds: 900, minServers: 2, maxDeviationSeconds: 0.5,
                        legalTimeAuthority: null, legalTimeToleranceSeconds: 1, legalTimeMaxAgeSeconds: 3600,
                        errorLogging: 5, maxErrors: 10 },
        policy:       {},
        lastSync:     null,
        limits:       { maxTimeout: 30, minCheckEvery: 60, maxCheckEvery: 86400, minDeviation: 0.001, maxDeviation: 60,
                        minTolerance: 0.001, maxTolerance: 60, minMaxAge: 60, maxMaxAge: 86400, maxAuthorityLength: 100,
                        minErrorCount: 1, maxErrorCount: 65535, defaultNTSKEPort: 4460, defaultNTPPort: 123 },
        file:         'nts.json'
    } as unknown as NTSConfiguration;
}

/** A group other than the legal one, as the node makes it: switched off, naming nobody. */
function aGroup(id: string, more: Partial<NTSConfiguration> = {}): NTSConfiguration {
    return { ...aConfiguration(), id, legal: false, enabled: false, timeSources: [], ...more } as NTSConfiguration;
}

const aClock = (): Clock => ({
    now: '2026-10-04T12:00:00Z', source: 'system',
    nts: { enabled: true, group: 'ptb', server: null, servers: null, minServers: 2, lastServer: null, asked: null, answered: null,
           checkedAt: null, ageSeconds: null, offset_ms: null, everySeconds: 900 },
    legal: false, authority: null, why: 'notClaimed', toleranceSeconds: 1, maxAgeSeconds: 3600, groups: []
}) as unknown as Clock;

/** A group in a few words, as the list of groups and the clock say it. */
function summaryOf(group: NTSConfiguration): NTSGroupSummary {
    return { id: group.id, displayName: group.displayName, legal: group.legal, enabled: group.enabled, checking: group.enabled,
             servers: group.timeSources.map(source => source.hostname), minServers: group.settings.minServers,
             everySeconds: group.settings.checkEverySeconds, checkedAt: null, ageSeconds: null, offset_ms: null,
             asked: null, answered: null };
}

function theGroups(): NTSGroups {
    return { groups:     groupsHeld.map(summaryOf),
             suggested:  [ 'legal', 'local', 'grid' ].filter(id => !groupsHeld.some(group => group.id === id)),
             limits:     { maxIdLength: 32, maxDisplayNameLength: 80 },
             file:       'nts.json' };
}

/** How the stand-in node answers. */
function node({ method, path, body }: Asked): unknown {

    if (path.endsWith('/clock'))
        return { ...aClock(), groups: groupsHeld.map(summaryOf), ...clockSays };

    if (path.endsWith('/certificates'))
        return { certificates: { tlsRoot: [ { id: rootPrint.slice(0, 16), label: 'PTB Root', thumbprint: rootPrint,
                                              usable: true, usages: [ 'nts' ] } ],
                                 tlsServer: [] } };

    if (path === '/configuration/nts/groups' && method === 'GET')
        return theGroups();

    if (path === '/configuration/nts/groups' && method === 'POST') {

        const { id, displayName } = body as { id: string; displayName?: NTSConfiguration['displayName'] };

        made.push(body);

        if (groupsHeld.some(group => group.id === id))
            return refused(409, `This Test node has an NTS group '${id}' already.`);

        const group = aGroup(id, { displayName: displayName ?? null });

        groupsHeld.push(group);

        return group;

    }

    const at = /^\/configuration\/nts\/groups\/([^/]+)(\/sync|\/test)?$/.exec(path);

    if (at === null)
        return undefined;

    const id    = decodeURIComponent(at[1]!);
    const group = groupsHeld.find(one => one.id === id);

    if (group === undefined)
        return refused(404, `This Test node has no NTS group '${id}'.`);

    if (at[2] === '/sync') {
        synced++;
        return { ...group, result: { ok: true, at: '2026-10-04T12:00:01Z', servers: [],
                                     group: { answered: 2, required: 2, offset_ms: 0.4, spread_ms: 0.1 } } };
    }

    if (at[2] === '/test')
        return { host: 'ptbtime1.ptb.de', ok: true, runtime_ms: 1, steps: [] };

    if (method === 'PUT') {

        const update = body as NTSUpdate;

        told.push(update);

        // A node takes what it takes: a check every minute at the most often.
        if (update.checkEverySeconds !== undefined)
            update.checkEverySeconds = Math.max(update.checkEverySeconds, 60);

        group.settings = { ...group.settings,
                           ...Object.fromEntries(Object.entries(update).filter(([ key ]) => key in group.settings)) };

        if (update.enabled !== undefined)
            group.enabled = update.enabled;

        return group;

    }

    if (method === 'DELETE') {

        if (group.enabled)
            return refused(409, `NTS group '${id}' is switched on: switch it off before removing it.`);

        removed.push(id);
        groupsHeld = groupsHeld.filter(one => one !== group);

        return theGroups();

    }

    return group;

}

/**
 * The page opened at the legal group, or at the tab the address names; the
 * node's groups shaped by the test, and drawn once what the test waits for is.
 */
async function opened(clock:   Partial<Clock> = {},
                      shape:   (configuration: NTSConfiguration) => void = () => undefined,
                      others:  NTSConfiguration[] = [],
                      path     = '/configuration/nts',
                      drawn:   (root: HTMLElement) => boolean = root => root.querySelector('#legal-form') !== null,
                      legal    = true): Promise<HTMLElement> {

    clockSays     = clock;
    held          = aConfiguration();
    shape(held);
    groupsHeld    = [ ...(legal ? [ held ] : []), ...others ];
    told.length   = 0;
    made.length   = 0;
    removed.length = 0;
    synced        = 0;

    // The address the tab is remembered in, as a browser has it.
    history.replaceState(null, '', path);

    return open(ntsPage, path, [ 'nts:edit', 'nts:run', 'certificates:read' ], node, drawn);

}

const field = (root: HTMLElement, form: string, name: string) => root.querySelector<HTMLInputElement>(`#${form} [name="${name}"]`)!;

/** Sent as the browser sends it once the form is valid; happy-dom's step check is not a browser's. */
const submit = (root: HTMLElement, form: string) =>
    root.querySelector<HTMLFormElement>(`#${form}`)!.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));

/** The tabs as they read: their text, or the name of one that is an icon. */
const tabsOf = (root: HTMLElement) => [ ...root.querySelectorAll<HTMLButtonElement>('[role="tab"]') ]
                                          .map(tab => tab.getAttribute('aria-label') ?? tab.textContent!.replace(/\s+/g, ' ').trim());

const shownTab = (root: HTMLElement) => root.querySelector<HTMLButtonElement>('[role="tab"][aria-selected="true"]')?.id;


describe('the NTS page', () => {

    const verdict = (root: HTMLElement) => root.querySelector('#nts-clock p.hint')!.textContent!.replace(/\s+/g, ' ').trim();

    it('adds what the dialog offers to what a server is held to, once each, and saves it', async () => {

        const root = await opened({}, configuration => {
            const first = configuration.timeSources![0]!;
            first.certificate = shownPrint;
            first.heldTo      = { certificate: null, root: null, certificates: [], roots: [], onMismatch: 'record', trustOnFirstUse: null };
        });

        root.querySelector<HTMLButtonElement>('[data-edit="0"]')!.click();
        await until(() => document.querySelector('dialog #server-form') !== null, 'the server\'s dialog did not open');

        const dialog        = document.querySelector('dialog')!;
        const certificates  = dialog.querySelector<HTMLTextAreaElement>('textarea[name="pinCertificates"]')!;
        const roots         = dialog.querySelector<HTMLTextAreaElement>('textarea[name="pinRoots"]')!;
        const shown         = dialog.querySelector<HTMLButtonElement>('[data-pin-add="pinCertificates"]')!;
        const kept          = dialog.querySelector<HTMLSelectElement>('[data-pin-pick="pinRoots"]')!;

        assert.equal(dialog.querySelector<HTMLSelectElement>('select[name="pinMismatch"]')!.value, 'record', 'what a mismatch comes to is not what it is held to');

        shown.click();
        assert.equal(certificates.value, shownPrint, 'the certificate the server showed was not added');
        assert.equal(shown.hidden, true, 'the offer of what is added already is still there');

        kept.value = rootPrint;
        kept.dispatchEvent(new Event('change', { bubbles: true }));
        kept.value = rootPrint;
        kept.dispatchEvent(new Event('change', { bubbles: true }));
        assert.equal(roots.value, rootPrint, 'the root the store keeps was not added, or added twice');
        assert.equal(kept.value, '', 'the chooser does not ask again');

        dialog.querySelector<HTMLFormElement>('#server-form')!.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));
        await until(() => told.some(update => update.servers !== undefined), 'the server was not saved');

        const saved = JSON.stringify(told.find(update => update.servers !== undefined)!.servers![0]);
        assert.match(saved, new RegExp(shownPrint), 'the certificate added was not saved');
        assert.match(saved, new RegExp(rootPrint),  'the root added was not saved');
        assert.match(saved, /"onMismatch":"record"/);

        document.querySelector('dialog')?.remove();

    });

    it('says whose time a legal clock carries, as the node names it', async () => {

        const root = await opened({ legal: true, authority: 'PTB', why: null, nts: { ...aClock().nts, checkedAt: '2026-10-04T11:59:00Z', offset_ms: 0.4 } });

        await until(() => root.querySelector('#nts-clock .chip')?.textContent?.trim() === 'legal time', 'the clock was not drawn as legal');

        assert.match(verdict(root), /of them, and the operator says they carry the time of PTB\.$/);

    });

    it('says no half sentence where a node calls its clock legal and names nobody', async () => {

        const root = await opened({ legal: true, authority: null, why: null, nts: { ...aClock().nts, checkedAt: '2026-10-04T11:59:00Z', offset_ms: 0.4 } });

        await until(() => root.querySelector('#nts-clock .chip')?.textContent?.trim() === 'legal time', 'the clock was not drawn as legal');

        assert.doesNotMatch(verdict(root), /time of/, 'it says whose time it carries, and names nobody');
        assert.match(verdict(root), /of them\.$/);

    });

    it('keeps what is typed into what counts as legal time, and its focus, while the group policy is saved and "Sync now" answers', async () => {

        const root      = await opened();
        const authority = field(root, 'legal-form', 'legalTimeAuthority');

        authority.value = 'PTB';
        authority.focus();

        submit(root, 'policy-form');
        await until(() => root.querySelector('#policy-note')?.textContent === 'Saved, and in effect.', 'the policy was not saved');

        root.querySelector<HTMLButtonElement>('#sync')!.click();
        await until(() => synced === 1 && root.querySelector('.sync-verdict') !== null, '"Sync now" was not answered');

        assert.ok(field(root, 'legal-form', 'legalTimeAuthority') === authority, 'the field was made anew');
        assert.equal(authority.value,           'PTB',     'what was typed is gone');
        assert.ok(document.activeElement === authority, 'the focus went');
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

    it('saves how many failed checks in a row are written down and limit what rests on the group', async () => {

        const root = await opened();

        assert.equal(field(root, 'policy-form', 'errorLogging').value, '5');
        assert.equal(field(root, 'policy-form', 'maxErrors').value,    '10');

        field(root, 'policy-form', 'maxErrors').value = '20';

        submit(root, 'policy-form');
        await until(() => told.length === 1, 'the policy was not saved');

        assert.equal(told[0]!.errorLogging, 5);
        assert.equal(told[0]!.maxErrors,    20);
        assert.equal(held.settings.maxErrors, 20, 'the group was not told');

    });

    it('says how many checks in a row produced no time, and when that limits legal time', async () => {

        const errors = (root: HTMLElement) => root.querySelector('#nts-errors .v')!.textContent!.replace(/s+/g, ' ').trim();

        const none     = await opened();
        assert.equal(errors(none), 'none');

        const running  = await opened({ nts: { ...aClock().nts, errorsInARow: 3, maxErrors: 10, limited: false } });
        assert.equal(errors(running), '3 - limited after 10');

        const limited  = await opened({ nts: { ...aClock().nts, errorsInARow: 12, maxErrors: 10, limited: true } });
        assert.equal(errors(limited), '12 limited');
        assert.ok(limited.querySelector('#nts-errors .chip.bad') !== null, 'a limited group is not marked as one');

    });

});


describe('the groups of the NTS page', () => {

    it('shows a tab per group, the legal one first, and a "+" tab that makes one more', async () => {

        const root = await opened({}, () => undefined, [ aGroup('local', { displayName: { en: 'Site clock' } }) ]);

        assert.deepEqual(tabsOf(root), [ 'Legal time', 'Site clock (off)', 'Add an NTS group' ]);
        assert.equal(shownTab(root), 'tab-legal');
        assert.equal(root.querySelector('[role="tabpanel"]')?.id, 'panel-legal');

    });

    it('opens the tab the address names, asks that group, and draws no legal time for it', async () => {

        const root = await opened({}, () => undefined, [ aGroup('local', { enabled: true, timeSources: aConfiguration().timeSources }) ],
                                  '/configuration/nts?tab=local',
                                  root => root.querySelector('#policy-form') !== null);

        const clock = root.querySelector('#nts-clock h2')!.textContent!.replace(/\s+/g, ' ').trim();

        assert.equal(shownTab(root), 'tab-local');
        assert.ok(root.querySelector('#nts-legal') === null, 'what counts as legal time is the legal group\'s alone');
        assert.match(clock, /^The clock against Local time/);
        assert.doesNotMatch(clock, /legal/);
        assert.ok(root.querySelector('#nts-remove') === null, 'a group switched on cannot be taken away');

    });

    it('says how many checks of a group in a row produced no time, and writes its run into the log and not the metrological log', async () => {

        const local = aGroup('local', { enabled: true, timeSources: aConfiguration().timeSources });
        const root  = await opened({ groups: [ { ...summaryOf(local), errorsInARow: 4, maxErrors: 50, limited: false } ] },
                                   () => undefined, [ local ], '/configuration/nts?tab=local',
                                   root => root.querySelector('#policy-form') !== null);

        const hint  = field(root, 'policy-form', 'errorLogging').closest('label')!.textContent!.replace(/s+/g, ' ');

        assert.equal(root.querySelector('#nts-errors .v')!.textContent!.replace(/s+/g, ' ').trim(), '4 - limited after 50');
        assert.match(hint, /Into the log,/);
        assert.match(field(root, 'policy-form', 'maxErrors').closest('label')!.textContent!, /load management/);

    });

    it('saves, syncs and tests the group of the tab shown', async () => {

        const root = await opened({}, () => undefined, [ aGroup('local', { enabled: true, timeSources: aConfiguration().timeSources }) ],
                                  '/configuration/nts?tab=local',
                                  root => root.querySelector('#policy-form') !== null);

        field(root, 'policy-form', 'checkEverySeconds').value = '120';
        submit(root, 'policy-form');
        await until(() => told.length === 1, 'the policy was not saved');

        root.querySelector<HTMLButtonElement>('#sync')!.click();
        await until(() => synced === 1, '"Sync now" did not ask');

        assert.equal(groupsHeld.find(group => group.id === 'local')!.settings.checkEverySeconds, 120);
        assert.equal(held.settings.checkEverySeconds, 900, 'the legal group was told');

    });

    it('makes a group switched off in the "+" tab, and shows its tab', async () => {

        const root = await opened({}, () => undefined, [], `/configuration/nts?tab=_new`,
                                  root => root.querySelector('#add-group-form') !== null);

        assert.deepEqual([ ...root.querySelectorAll<HTMLOptionElement>('#nts-group-names option') ].map(option => option.value),
                         [ 'local', 'grid' ], 'the names not taken yet are offered');

        field(root, 'add-group-form', 'id').value          = 'grid';
        field(root, 'add-group-form', 'language-0').value  = 'de';
        field(root, 'add-group-form', 'text-0').value      = 'Netzzeit';

        root.querySelector<HTMLButtonElement>('#add-language')!.click();
        await until(() => root.querySelector('[name="text-1"]') !== null, 'no second language');

        assert.equal(field(root, 'add-group-form', 'text-0').value, 'Netzzeit', 'the line typed into was drawn anew');

        field(root, 'add-group-form', 'language-1').value  = 'en';
        field(root, 'add-group-form', 'text-1').value      = 'Grid time';

        submit(root, 'add-group-form');
        await until(() => shownTab(root) === 'tab-grid' && root.querySelector('#nts-remove') !== null, 'the new group\'s tab was not shown');

        assert.deepEqual(made, [ { id: 'grid', displayName: { de: 'Netzzeit', en: 'Grid time' } } ]);
        assert.match(location.search, /tab=grid/, 'its tab is not the one the address remembers');
        assert.equal(root.querySelector<HTMLInputElement>('#enabled')!.checked, false, 'made switched on');

    });

    it('says a name that cannot be a group\'s, and asks the node nothing', async () => {

        const root = await opened({}, () => undefined, [], `/configuration/nts?tab=_new`,
                                  root => root.querySelector('#add-group-form') !== null);

        field(root, 'add-group-form', 'id').value = 'Grid';
        submit(root, 'add-group-form');

        await until(() => root.querySelector('#add-group-error')!.textContent !== '', 'nothing was said');

        assert.match(root.querySelector('#add-group-error')!.textContent!, /"Grid" cannot be the name of a group/);
        assert.deepEqual(made, []);

    });

    it('says what the node refuses, in the "+" tab', async () => {

        const root = await opened({}, () => undefined, [ aGroup('local') ], `/configuration/nts?tab=_new`,
                                  root => root.querySelector('#add-group-form') !== null);

        field(root, 'add-group-form', 'id').value = 'local';
        submit(root, 'add-group-form');

        await until(() => root.querySelector('#add-group-error')!.textContent !== '', 'the refusal was not said');

        assert.match(root.querySelector('#add-group-error')!.textContent!, /has an NTS group 'local' already/);
        assert.equal(shownTab(root), 'tab-_new');

    });

    it('takes a group switched off away once asked, and shows the first tab left', async () => {

        const root = await opened({}, () => undefined, [ aGroup('local') ], '/configuration/nts?tab=local',
                                  root => root.querySelector('#nts-remove') !== null);

        root.querySelector<HTMLButtonElement>('#remove-group')!.click();
        await until(() => shownTab(root) === 'tab-legal' && root.querySelector('#legal-form') !== null, 'the first tab left was not shown');

        assert.deepEqual(removed, [ 'local' ]);
        assert.match(said.find(text => text.startsWith('Remove Local time?')) ?? '', /taken out of nts\.json/);
        assert.deepEqual(tabsOf(root), [ 'Legal time', 'Add an NTS group' ]);

    });

    it('says what taking the legal group away ends, and leaves the "+" tab where nothing is left', async () => {

        const root = await opened({}, held => { held.enabled = false; }, [], '/configuration/nts',
                                  root => root.querySelector('#nts-remove') !== null);

        assert.match(root.querySelector('#nts-remove p.hint')!.textContent!, /no legal time from then on/);

        root.querySelector<HTMLButtonElement>('#remove-group')!.click();
        await until(() => shownTab(root) === 'tab-_new' && root.querySelector('#add-group-form') !== null, 'the "+" tab was not shown');

        assert.deepEqual(removed, [ 'legal' ]);
        assert.match(said.find(text => text.startsWith('Remove Legal time?')) ?? '', /no legal time from then on/);
        assert.deepEqual([ ...root.querySelectorAll<HTMLOptionElement>('#nts-group-names option') ].map(option => option.value),
                         [ 'legal', 'local', 'grid' ], 'the legal group is offered again');

    });

    it('asks before another tab leaves what is typed behind, and stays where it is told to', async () => {

        const root   = await opened({}, () => undefined, [ aGroup('local') ]);
        const every  = field(root, 'policy-form', 'checkEverySeconds');
        const asked  = window.confirm;

        every.value  = '600';

        window.confirm = (text?: unknown) => { said.push(String(text)); return false; };

        try
        {
            root.querySelector<HTMLButtonElement>('#tab-local')!.click();
        }
        finally
        {
            window.confirm = asked;
        }

        assert.equal(shownTab(root), 'tab-legal', 'the tab was left all the same');
        assert.ok(said.some(text => text.includes('has not been told about')), 'nobody was asked');
        assert.equal(field(root, 'policy-form', 'checkEverySeconds').value, '600', 'what was typed is gone');

    });

    it('shows a node without a group of time servers its "+" tab alone', async () => {

        const root = await opened({}, () => undefined, [], '/configuration/nts',
                                  root => root.querySelector('#add-group-form') !== null, false);

        assert.deepEqual(tabsOf(root), [ 'Add an NTS group' ]);

    });

});
