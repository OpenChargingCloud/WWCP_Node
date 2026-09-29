/**
 * The rules the web interface's pages share, asked directly.
 *
 * Run with `npm test`, which is Node's own runner reading the TypeScript as it
 * stands - no bundler, no browser, no dependency that is not already here.
 *
 * What is pinned is what was measured to be wrong: a page that threw away
 * everything typed while a save was on its way, and said "Saved, and in
 * effect." over the hole it had just made; a number field left empty that was
 * read as 0; and a "next" after signing in that could lead off the node.
 */

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import { beingSaved, formatTimestamp, humanizeKey, isChecked, numberField, numberFrom, safeNext, whileSaving } from './ui.ts';


/** Something on a page that can be switched off; all whileSaving cares about. */
const control = (disabled = false) => ({ disabled });

/** A page holding exactly those controls. */
const page = (controls: { disabled: boolean }[]) =>
    ({ querySelectorAll: () => controls }) as unknown as HTMLElement;

/** Somewhere for it to say what is happening. */
const saying = () => ({ textContent: 'whatever was there before' }) as HTMLElement;


describe('a page while the node is being told', () => {

    it('cannot be typed into, which is what makes losing the typing impossible', async () => {

        const live = [control(), control(), control()];
        let whileItRan: boolean[] = [];

        await whileSaving(page(live), null, async () => {
            whileItRan = live.map(one => one.disabled);
        });

        assert.deepEqual(whileItRan, [true, true, true]);

    });

    it('says so, because a page that does not react is one people press again', async () => {

        const note = saying();
        let said   = '';

        await whileSaving(page([control()]), note, async () => { said = note.textContent ?? ''; });

        assert.equal(said, beingSaved);

    });

    it('comes back afterwards', async () => {

        const live = [control(), control()];
        const note = saying();

        await whileSaving(page(live), note, async () => undefined);

        assert.deepEqual(live.map(one => one.disabled), [false, false]);

        // And what is happening is no longer happening; what it turned into is
        // the page's to say.
        assert.equal(note.textContent, '');

    });

    it('comes back when it failed as well, or the page would be dead', async () => {

        const live = [control(), control()];
        const note = saying();

        await assert.rejects(() =>
            whileSaving(page(live), note, () => Promise.reject(new Error('the node said no'))));

        assert.deepEqual(live.map(one => one.disabled), [false, false]);
        assert.equal(note.textContent, '');

    });

    it('leaves what was already switched off switched off', async () => {

        // A role that may look but not change must not be handed a live form
        // by a save that failed.
        const notAllowed       = control(true);
        const nothingToDiscard = control(true);
        const ordinary         = control();

        await assert.rejects(() =>
            whileSaving(page([notAllowed, nothingToDiscard, ordinary]), null,
                        () => Promise.reject(new Error('no'))));

        assert.equal(notAllowed.disabled,       true);
        assert.equal(nothingToDiscard.disabled, true);
        assert.equal(ordinary.disabled,         false);

    });

    it('hands back what the node answered, untouched', async () => {

        const answer = await whileSaving(page([control()]), null,
                                         () => Promise.resolve({ minServers: 2 }));

        assert.deepEqual(answer, { minServers: 2 });

    });

    it('and hands on what it refused, so the page can say why', async () => {

        await assert.rejects(
            () => whileSaving(page([control()]), null,
                              () => Promise.reject(new Error("'nts.minServers' must be at least 1."))),
            /minServers/
        );

    });

});


/** A form, as far as reading it goes. */
class FormOf {
    readonly fields: Record<string, string>;
    constructor(fields: Record<string, string>) {
        this.fields = fields;
    }
}

// The browser's FormData reads a form; Node's takes none.
(globalThis as unknown as { FormData: unknown }).FormData = class {
    readonly form: FormOf;
    constructor(form: FormOf) {
        this.form = form;
    }
    get(name: string): string | null {
        return this.form.fields[name] ?? null;
    }
};

const form = (fields: Record<string, string>) => new FormOf(fields) as unknown as HTMLFormElement;


describe('a number field', () => {

    it('is not a number when it is empty - which goes to the node as null, and null is not given', () => {

        const read = numberField(form({ maxRetries: '' }), 'maxRetries');

        assert.ok(Number.isNaN(read), `read as ${read}`);
        assert.equal(JSON.stringify({ maxRetries: read }), '{"maxRetries":null}');

    });

    it('is not a number when it holds nothing but blanks, or is not there at all', () => {

        assert.ok(Number.isNaN(numberField(form({ maxRetries: '   ' }), 'maxRetries')));
        assert.ok(Number.isNaN(numberField(form({}),                    'maxRetries')));

    });

    it('is the number it holds, 0 among them', () => {

        assert.equal(numberField(form({ maxRetries: '0' }),               'maxRetries'),          0);
        assert.equal(numberField(form({ queryTimeoutSeconds: ' 2.5 ' }),  'queryTimeoutSeconds'), 2.5);

    });

});


describe('a number typed into an input outside a form', () => {

    it('is not a number when it is emptied, or holds nothing but blanks', () => {

        assert.ok(Number.isNaN(numberFrom('')));
        assert.ok(Number.isNaN(numberFrom('  ')));

        assert.equal(JSON.stringify({ port: numberFrom('') }), '{"port":null}');

    });

    it('is the number it holds, 0 among them', () => {
        assert.equal(numberFrom('0'),     0);
        assert.equal(numberFrom(' 853 '), 853);
    });

});


describe('a box of a form', () => {

    it('is ticked where the form sends it, whatever it sends, and not where it does not', () => {

        assert.equal(isChecked(form({ useCache: 'on' }), 'useCache'), true);
        assert.equal(isChecked(form({ useCache: '' }),   'useCache'), true, 'an empty value is still a ticked box');
        assert.equal(isChecked(form({}),                 'useCache'), false);

    });

});


describe('a key as a label', () => {

    it('says the words of every kind of node the way people write them', () => {

        assert.equal(humanizeKey('queryTimeoutSeconds'), 'Query timeout seconds');
        assert.equal(humanizeKey('seccId'),              'SECC ID');
        assert.equal(humanizeKey('cdrs'),                'CDRs');
        assert.equal(humanizeKey('evseSoc'),             'EVSE SoC');
        assert.equal(humanizeKey('maxPowerKw'),          'Max power kW');
        assert.equal(humanizeKey('energy_kwh'),          'Energy kWh');

    });

    it('writes a mobility operator as MO, and leaves a word that begins with "mo" alone', () => {

        assert.equal(humanizeKey('moRoot'),          'MO root');
        assert.equal(humanizeKey('moRootNotAfter'),  'MO root not after');
        assert.equal(humanizeKey('modbusPort'),      'Modbus port');

    });

});


describe('where somebody is sent after signing in', () => {

    it('is the page they were going to, below this node', () => {

        assert.equal(safeNext('/configuration/nts'), '/configuration/nts');
        assert.equal(safeNext('/logs?level=warning'), '/logs?level=warning');
        assert.equal(safeNext('/'), '/');

    });

    it('is nowhere for what is not a path of this node', () => {

        assert.equal(safeNext(null),                     null);
        assert.equal(safeNext('logs'),                   null);
        assert.equal(safeNext('https://evil.example/'),  null);
        assert.equal(safeNext('//evil.example/'),        null);

    });

    it('is nowhere for what a browser reads as another host, however it is spelt', () => {

        // A browser reads a backslash in a URL as a slash, and drops a tab or
        // a line break before it reads it at all: each of these is
        // "//evil.example" to it, and none of them began with "//".
        assert.equal(safeNext('/\\evil.example/'),   null, 'a backslash');
        assert.equal(safeNext('/\t/evil.example/'),  null, 'a tab');
        assert.equal(safeNext('/\n/evil.example/'),  null, 'a line break');

    });

});


describe('the whole moment', () => {

    const inUTC = (Locale: string) => new Intl.DateTimeFormat(Locale, { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' });

    /** One space for every kind a locale writes, as the narrow one before "PM". */
    const spaced = (Text: string) => Text.replace(/\s/g, ' ');

    it('has its milliseconds after the seconds, before the "PM" of a twelve-hour clock', () => {
        assert.equal(spaced(formatTimestamp('2026-09-29T15:52:17.123Z', inUTC('en-US'))), 'Sep 29, 2026, 3:52:17.123 PM');
    });

    it('has them after the seconds on a twenty-four-hour clock as well, set off as the locale sets them off', () => {
        assert.equal(spaced(formatTimestamp('2026-09-29T15:52:07.004Z', inUTC('de-DE'))), '29.09.2026, 15:52:07,004');
    });

    it('is what it was given, where that is no moment', () => {
        assert.equal(formatTimestamp('not a moment'), 'not a moment');
    });

});
