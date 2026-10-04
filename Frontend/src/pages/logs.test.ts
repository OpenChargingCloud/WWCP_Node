/**
 * What the Logs page decides: which entries its filters let through, how one
 * line is made, what it says about the stream and about how much of the log
 * it holds - and, drawn in a document of happy-dom, that its tag buttons keep
 * the focus.
 *
 * What it does with a browser - the line somebody is reading staying where it
 * is while lines go in above it - is measured in one, with a filter on: the
 * newest line hidden, the list scrolled down, a matching entry arriving, and
 * the line being read moving by less than a pixel.
 */

import '../../test/dom.ts';

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';

import type { LogEntry }     from '../api/client.ts';

// What the node writes into the page it serves, read by config.ts as it loads.
const nodeName = document.createElement('meta');
nodeName.name     = 'node-name';
nodeName.content  = 'roaming hub';
document.head.append(nodeName);

const { open, standIn }                                       = await import('../../test/node.ts');
const { logs }                                                = await import('../logs/store.ts');
const { countsText, lineElement, logsPage, matches, streamState } = await import('./logs.ts');


const entry = (Changes: Partial<LogEntry> = {}): LogEntry => ({
    id:         7,
    timestamp:  '2026-09-29T01:02:03.456Z',
    level:      'info',
    message:    'The peer DE-GEF signed in.',
    tags:       [ 'ocpi', 'peer' ],
    ...Changes
});

const everything = { level: 'debug' as const, tags: new Set<string>(), search: '' };


describe('what the filters let through', () => {

    it('is every level from the one chosen up', () => {
        assert.equal(matches(entry({ level: 'warning' }), { ...everything, level: 'info'    }), true);
        assert.equal(matches(entry({ level: 'info'    }), { ...everything, level: 'warning' }), false);
    });

    it('is an entry with any of the chosen tags, not only one with all of them', () => {

        // Somebody who picks two conversations wants to watch both, not the
        // lines that are about both at once.
        assert.equal(matches(entry({ tags: [ 'ocpi' ] }),  { ...everything, tags: new Set([ 'ocpi', '15118' ]) }), true);
        assert.equal(matches(entry({ tags: [ 'dns'  ] }),  { ...everything, tags: new Set([ 'ocpi', '15118' ]) }), false);

    });

    it('counts the level as one of the tags', () => {
        assert.equal(matches(entry({ level: 'critical', tags: [] }), { ...everything, tags: new Set([ 'critical' ]) }), true);
    });

    it('finds what was typed anywhere in the message, whatever the case and the spaces around it', () => {
        assert.equal(matches(entry(), { ...everything, search: '  de-gef ' }), true);
        assert.equal(matches(entry(), { ...everything, search: 'DE-XYZ'    }), false);
    });

});


describe('one line of the log', () => {

    it('is made with what the entry says as text, not as markup', () => {

        const line = lineElement(entry({ message: '<script>alert(1)</script>', tags: [ 'a"b', '<i>x</i>' ] }));

        assert.ok(line.querySelector('script, i') === null, 'what the entry says was taken as markup');
        assert.equal(line.querySelector('.message')!.textContent, '<script>alert(1)</script>');
        assert.deepEqual([ ...line.querySelectorAll('.chip.tag') ].map(tag => tag.textContent), [ 'a"b', '<i>x</i>' ]);

    });

    it('says when it was, to the second, and the whole time where the pointer rests', () => {

        const time = lineElement(entry()).querySelector('time')!;

        assert.equal(time.getAttribute('datetime'), '2026-09-29T01:02:03.456Z');
        assert.ok(time.textContent!.length > 0 && time.title.length > time.textContent!.length,
                  `the time "${time.textContent}" and the whole time "${time.title}"`);

    });

    it('carries its level and its id, which is how a notice line is drawn as one', () => {

        const line = lineElement(entry({ level: 'notice' }));

        assert.equal(line.className, 'line notice');
        assert.equal(line.dataset.id, '7');
        assert.equal(line.querySelector('.chip.level.notice')!.textContent, 'notice');

    });

    it('goes in already filtered out where a filter does not want it, so that it never takes up room it would give back', () => {
        assert.equal(lineElement(entry(), true).className, 'line info filtered-out');
        assert.equal(lineElement(entry()).className,       'line info');
    });

});


describe('the Logs page', () => {

    /** Entries as the stream delivers them, through the store's own way in. */
    const delivered = (...Entries: LogEntry[]) => (logs as unknown as { apply(Entries: LogEntry[]): void }).apply(Entries);

    const tagButton = (root: HTMLElement, tag: string) =>
                          [ ...root.querySelectorAll<HTMLButtonElement>('#tags .tag-button') ].find(button => button.textContent === tag);

    standIn({ name: 'Test node', icon: 'fa-gear', user: { mayReadTheLog: true } });

    /**
     * The page drawn, with the store holding the entries given, for somebody
     * who may read the log. The page drawn before stops listening to the
     * store, as the router has it stop once the page is left.
     */
    async function opened(...Entries: LogEntry[]): Promise<HTMLElement> {

        logs.entries.length = 0;
        logs.tags.clear();
        logs.lastId = 0;
        delivered(...Entries);

        return open(logsPage(), '/logs', [], () => undefined, root => root.querySelector('#log-lines') !== null);

    }

    it('draws the newest entry on top, and a burst newest first as well', async () => {

        const root = await opened(entry({ id: 1, message: 'first' }), entry({ id: 2, message: 'second' }));

        delivered(entry({ id: 3, message: 'third' }), entry({ id: 4, message: 'fourth' }));

        assert.deepEqual([ ...root.querySelectorAll('#log-lines .message') ].map(line => line.textContent),
                         [ 'fourth', 'third', 'second', 'first' ]);

    });

    it('keeps the focus on a tag button that is switched', async () => {

        const root = await opened(entry({ id: 1, tags: [ 'ocpi' ] }));
        const ocpi = tagButton(root, 'ocpi')!;

        ocpi.focus();
        ocpi.click();

        assert.equal(tagButton(root, 'ocpi')!.getAttribute('aria-pressed'), 'true', 'the tag was not switched on');
        assert.ok(document.activeElement === tagButton(root, 'ocpi'),
                  `the focus is on ${document.activeElement?.tagName} "${document.activeElement?.textContent}", not on the tag switched`);

    });

    it('keeps the focus on a tag button while the node learns a tag that goes in before it', async () => {

        const root = await opened(entry({ id: 1, tags: [ 'ocpi' ] }));

        tagButton(root, 'ocpi')!.focus();

        delivered(entry({ id: 2, tags: [ '15118' ] }));

        assert.ok(tagButton(root, '15118') !== undefined, 'the new tag has no button');
        assert.ok(document.activeElement === tagButton(root, 'ocpi'),
                  `the focus is on ${document.activeElement?.tagName} "${document.activeElement?.textContent}", not on the tag it was on`);

    });

    it('hides the lines a tag does not want, and shows them all again with "all tags"', async () => {

        const root = await opened(entry({ id: 1, tags: [ 'ocpi' ], message: 'roaming' }), entry({ id: 2, tags: [ 'ocpp' ], message: 'charging' }));

        tagButton(root, 'ocpp')!.click();

        assert.deepEqual([ ...root.querySelectorAll('#log-lines .line:not(.filtered-out) .message') ].map(line => line.textContent), [ 'charging' ]);

        tagButton(root, 'all tags')!.click();

        assert.equal(root.querySelectorAll('#log-lines .line.filtered-out').length, 0);
        assert.ok(tagButton(root, 'all tags') === undefined, '"all tags" is still offered with no tag switched on');

    });

    it('puts a line that a tag switched on does not want in already hidden', async () => {

        const root = await opened(entry({ id: 1, tags: [ 'ocpp' ], message: 'charging' }));

        tagButton(root, 'ocpp')!.click();

        delivered(entry({ id: 2, tags: [ 'ocpi' ], message: 'roaming' }), entry({ id: 3, tags: [ 'ocpp' ], message: 'charging again' }));

        assert.deepEqual([ ...root.querySelectorAll('#log-lines .line') ].map(line => `${line.querySelector('.message')!.textContent}${line.classList.contains('filtered-out') ? ' (hidden)' : ''}`),
                         [ 'charging again', 'roaming (hidden)', 'charging' ]);

    });

    it('clears what it shows with "Clear view", and the store with it, not the node', async () => {

        const root = await opened(entry({ id: 1, message: 'first' }), entry({ id: 2, message: 'second' }));

        root.querySelector<HTMLButtonElement>('.page-actions #clear')!.click();

        assert.equal(root.querySelectorAll('#log-lines .line').length, 0);
        assert.equal(logs.entries.length, 0);

    });

    it('says why the log could not be loaded as text, not as markup', async () => {

        const root = await opened();

        (logs as unknown as { emit(Event: unknown): void }).emit({ type: 'error', text: 'Could not load the log: <b>refused</b>' });

        const note = root.querySelector<HTMLElement>('#log-error')!;

        assert.equal(note.hidden, false);
        assert.ok(note.querySelector('b') === null, 'the reason was taken as markup');
        assert.equal(note.textContent, 'Could not load the log: <b>refused</b>');

    });

});


describe('what the page says about the stream', () => {

    it('is "live" while it is open', () => {
        assert.deepEqual(streamState(true, false), { text: 'live', tone: 'live' });
    });

    it('is "reconnecting ..." while the browser is still trying', () => {
        assert.deepEqual(streamState(false, false), { text: 'reconnecting ...', tone: 'down' });
    });

    it('is "stopped" once the node has refused it for good - not "reconnecting ...", beside a line saying the opposite', () => {
        assert.deepEqual(streamState(false, true), { text: 'stopped', tone: 'down' });
    });

});


describe('how much of the log the page holds', () => {

    it('says how many entries the filters let through, of how many', () => {
        assert.equal(countsText(3, 40, 0), '3 of 40 entries');
    });

    it('says how many the node keeps in memory, as the node names itself - its files keep more', () => {
        assert.equal(countsText(3, 40, 2000), '3 of 40 entries (the roaming hub keeps the last 2000 in memory)');
    });

});


describe('the source of the page', () => {

    it('holds no NUL byte, which would make it binary to git and to grep', () => {

        const source = readFileSync(new URL('./logs.ts', import.meta.url));

        assert.equal(source.includes(0), false);

    });

});
