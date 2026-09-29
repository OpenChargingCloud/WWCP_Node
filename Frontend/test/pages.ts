/*
 * What every page of every kind of node is held to, asked of its source.
 *
 * Node's runner has no browser to open a page in, so what is asked here is the
 * pages' source:
 *
 * - that each page with a form says, for as long as it is open, whether it is
 *   holding anything; that it holds every form it has; and that its Reload
 *   asks first - five pages of the local controller threw a typed address,
 *   port, station, subject or authority away on one click of Reload or of the
 *   menu, without a word;
 * - that a number is read as one - an emptied field is not given, where
 *   Number("") made it 0, which the node refuses for a timeout, the whole save
 *   with it (found on the energy meter, and on the local controller's DNS and
 *   NTS pages too);
 * - that a link goes through toURL - a path of its own leads past the base the
 *   node may be served under, in a new tab or a copied link (found on the
 *   charging station's V2G and power pages);
 * - that a page's look comes from the stylesheet - a style attribute is
 *   dropped by the policy every node serves its pages with (found on the
 *   partner pages of the CSMS, the e-mobility provider and the hub).
 *
 * The pages every kind shares are asked in src/pages/pages.test.ts. A kind of
 * node asks its own the same way, in its own src/pages/pages.test.ts -
 * "@node/.." is WWCP_Node/Frontend, where this file is:
 *
 *     import { everyPageIn } from '@node/../test/pages.ts';
 *
 *     everyPageIn(new URL('./', import.meta.url), {
 *         withForms: [ 'csms.ts', 'ocppServer.ts' ]
 *     });
 */

import { strict as assert }           from 'node:assert';
import { readdirSync, readFileSync }  from 'node:fs';
import { describe, it }               from 'node:test';
import { fileURLToPath }              from 'node:url';


/** A page: its file's name, and its source. */
export interface Page {
    readonly name:    string;
    readonly source:  string;
}

/** What a directory of pages says of itself, where the source cannot say it. */
export interface Expected {

    /**
     * The pages with a form, by file name - said, so that the rules are not
     * said of nothing: a reading that found no form anywhere would pass every
     * one of them.
     */
    readonly withForms:     readonly string[];

    /**
     * The forms, by id, that are a dialog's. A dialog's form lives and dies
     * with its dialog, which asks for itself when it is closed.
     */
    readonly dialogForms?:  readonly string[];

    /** The pages whose form is not a draft, each with why. */
    readonly notDrafts?:    Readonly<Record<string, string>>;

}


/** The pages in a directory: every TypeScript file in it but the tests. */
export function pagesIn(Directory: URL): Page[] {
    return readdirSync(Directory).
               filter(name => name.endsWith('.ts') && !name.endsWith('.test.ts')).
               sort().
               map(name => ({ name, source: readFileSync(new URL(name, Directory), 'utf-8') }));
}

/** The forms of a page, by id - null for one that has none, and a data-id is none. */
export function formsOf(Page: Page): (string | null)[] {
    return [ ...Page.source.matchAll(/<form(\s[^>]*)?>/g) ].
               map(match => /\sid="([^"]+)"/.exec(match[1] ?? '')?.[1] ?? null);
}

/** Whether a page says, for as long as it is open, whether it is holding anything. */
export function saysWhetherItHolds(Page: Page): boolean {
    return Page.source.includes('unsaved.heldBy(');
}

/** Whether a page's Reload, where it has one, asks before it throws a draft away. */
export function asksBeforeItsReload(Page: Page): boolean {
    return !Page.source.includes('id="reload"') || Page.source.includes('unsaved.mayBeLost()');
}

/**
 * The forms of a page that it does not hold - "#<id>", or "a form without an
 * id" - but a dialog's.
 *
 * A page holds a form by naming it, typedSinceDrawn(content.querySelector('#<id>')),
 * or every form it has at once, with anyFormTypedSinceDrawn(content). A flag
 * of its own holds none: what is typed into a form and not yet added to its
 * list is in no flag.
 */
export function formsNotHeld(Page: Page, DialogForms: readonly string[] = []): string[] {

    if (Page.source.includes('anyFormTypedSinceDrawn(content)'))
        return [];

    return formsOf(Page).
               filter(id => id === null || !DialogForms.includes(id)).
               filter(id => id === null || !Page.source.includes(`typedSinceDrawn(content.querySelector('#${id}'))`)).
               map(id => id === null ? 'a form without an id' : `#${id}`);

}

/**
 * The styles a page writes into itself - a style attribute, a style element, a
 * style set as an attribute - which the policy every node serves its pages
 * with, style-src 'self', drops: what they say never shows. Three kinds'
 * partner pages had three, a button that never moved to the right of its card
 * and a country code and party ID never shown in capitals. What a page looks
 * like is the stylesheet's to say, by a class.
 */
export function inlineStylesOf(Page: Page): string[] {
    return [ ...Page.source.matchAll(/\sstyle\s*=\s*("[^"]*"|'[^']*')|<style\b|setAttribute\(\s*['"]style['"]/g) ].
               map(match => match[0].trim());
}

/**
 * The links a page writes with a path of its own - href="/…" - past the base
 * the node may be served under. The router makes a click on one work, as it
 * takes the base off whatever it is given; a new tab, a middle click or a copied
 * link leads out of the web interface. toURL puts the base in front:
 * href="${toURL('/logs')}" - found by the charging station, whose V2G page
 * linked its log three times without it.
 */
export function linksPastTheBase(Page: Page): string[] {
    return [ ...Page.source.matchAll(/\shref\s*=\s*["'](\/(?!\/)[^"']*)["']/g) ].
               map(match => match[1]!);
}

/**
 * What a page reads with Number() of what was typed - a form's field, by
 * data.get or by field(), or an input's value - which makes an emptied field
 * 0. But a priority, where empty means 0, the priority every server has unless
 * it is given another; and a read after "=== '' ? … :", where the page says
 * itself what empty means (the station's V2G port: empty lets the system
 * choose). numberField and numberFrom read the rest: an emptied field is NaN
 * there, which JSON.stringify sends as null, and null is "not said".
 */
export function numbersReadAsZeroWhenEmptied(Page: Page): string[] {
    return [ ...Page.source.matchAll(/(=== ''\s*\?[^:]*:\s*)?Number\((?:data\.get\('([^']+)'\)|field\(\w+,\s*'([^']+)'\)|(\w+)\.value\))/g) ].
               filter(match => match[1] === undefined).
               map(match => match[2] ?? match[3] ?? `${match[4]}.value`).
               filter(name => name !== 'priority');
}


/**
 * Asks every page in a directory what is above, as tests of the runner that
 * reads the caller: one for each page and each rule, named for the page.
 */
export function everyPageIn(Directory: URL, Expected: Expected): void {

    const pages        = pagesIn(Directory);
    const notDrafts    = Expected.notDrafts   ?? {};
    const dialogForms  = Expected.dialogForms ?? [];
    const withForms    = pages.filter(page => page.source.includes('<form') && !Object.hasOwn(notDrafts, page.name));

    describe('every page with a form', () => {

        it('is found at all, so that what follows is not said of nothing', () => {

            assert.ok(pages.length > 0, `no page was found in ${fileURLToPath(Directory)}`);

            assert.deepEqual(withForms.map(page => page.name), [ ...Expected.withForms ].sort(),
                             'the pages with a form are not the ones said to have one');

        });

        for (const [ name, why ] of Object.entries(notDrafts))
            it(`${name} is none of them: ${why}`, () => {
                assert.ok(pages.some(page => page.name === name && page.source.includes('<form')),
                          `${name} is said to have a form that is no draft, and has no form - or is not there`);
            });

        if (dialogForms.length > 0)
            it('has the dialogs\' forms it is said to have', () => {
                const there = new Set(pages.flatMap(formsOf));
                assert.deepEqual(dialogForms.filter(id => !there.has(id)), [], 'said to be a dialog\'s form, and no form at all');
            });

        for (const page of withForms) {

            it(`${page.name} says whether it is holding anything`, () => {
                assert.ok(saysWhetherItHolds(page),
                          `${page.name} has a form and never says when it is holding a draft, so leaving it asks nothing`);
            });

            it(`${page.name} holds every form it has, not only the first one`, () => {
                const notHeld = formsNotHeld(page, dialogForms);
                assert.deepEqual(notHeld, [],
                                 `${page.name}: what is typed into ${notHeld.join(', ')} is thrown away without a question - ` +
                                 `name it, typedSinceDrawn(content.querySelector('#<id>')), or hold every form with ` +
                                 `anyFormTypedSinceDrawn(content)`);
            });

            if (page.source.includes('id="reload"'))
                it(`${page.name} asks before its Reload throws a draft away`, () => {
                    assert.ok(asksBeforeItsReload(page), `${page.name} has a form and a Reload that redraws it without asking`);
                });

        }

    });

    describe('a number on a page', () => {

        for (const page of pages.filter(page => page.source.includes('<form')))
            it(`${page.name} reads its numbers with numberField, so that an emptied field is not 0`, () => {
                const read = numbersReadAsZeroWhenEmptied(page);
                assert.deepEqual(read, [], `${page.name} reads ${read.join(', ')} with Number(), which makes an emptied field 0`);
            });

    });

    describe('a link on a page', () => {

        for (const page of pages)
            it(`${page.name} links through toURL, so that a link stays below the base the node is served under`, () => {
                const links = linksPastTheBase(page);
                assert.deepEqual(links, [], `${page.name} links ${links.join(', ')} past the base - href="\${toURL('…')}" keeps it below`);
            });

    });

    describe('the look of a page', () => {

        for (const page of pages)
            it(`${page.name} takes its look from the stylesheet, not from a style the policy drops`, () => {
                const styles = inlineStylesOf(page);
                assert.deepEqual(styles, [], `${page.name} writes ${styles.join(', ')} into itself - style-src 'self' lets no style through that is not in the stylesheet; say it by a class`);
            });

    });

}
