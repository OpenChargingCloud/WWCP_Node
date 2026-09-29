/**
 * What the Logs page decides without a browser: which entries its filters
 * let through, how one line is written, what it says about the stream and
 * about how much of the log it holds.
 *
 * What it does with a browser - the line somebody is reading staying where it
 * is while lines go in above it - is measured in one, with a filter on: the
 * newest line hidden, the list scrolled down, a matching entry arriving, and
 * the line being read moving by less than a pixel.
 */

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';

import type { LogEntry }     from '../api/client.ts';

(globalThis as unknown as { document: unknown }).document = {
    querySelector: (selector: string) => selector === 'meta[name="node-name"]' ? { content: 'roaming hub' } : null
};

const { countsText, lineHTML, matches, streamState } = await import('./logs.ts');


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

    it('is written with what the entry says as text, not as markup', () => {

        const line = lineHTML(entry({ message: '<script>alert(1)</script>', tags: [ 'a"b' ] }));

        assert.doesNotMatch(line, /<script>/);
        assert.match       (line, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
        assert.match       (line, /<span class="chip tag">a&quot;b<\/span>/);

    });

    it('carries its level, which is how a notice line is drawn as one', () => {
        assert.match(lineHTML(entry({ level: 'notice' })), /^<div class="line notice" data-id="7">/);
    });

    it('goes in already filtered out where a filter does not want it, so that it never takes up room it would give back', () => {
        assert.match       (lineHTML(entry(), true),  /^<div class="line info filtered-out"/);
        assert.doesNotMatch(lineHTML(entry()),        /filtered-out/);
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
