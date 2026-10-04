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
 *   menu, without a word; and that it draws itself anew through keepDrafts,
 *   which puts back what was typed into its other forms (the vehicle's pages
 *   did, the local controller's threw it away);
 * - that a number is read as one - an emptied field is not given, where
 *   Number("") made it 0, which the node refuses for a timeout, the whole save
 *   with it (found on the energy meter, and on the local controller's DNS and
 *   NTS pages too) - on every page, with a form or without: the charging
 *   station's power fields are inputs of their own, and an emptied one was
 *   0 kW;
 * - that a link goes through toURL - a path of its own leads past the base the
 *   node may be served under, in a new tab or a copied link (found on the
 *   charging station's V2G and power pages);
 * - that a page's look comes from the stylesheet - a style attribute is
 *   dropped by the policy every node serves its pages with (found on the
 *   partner pages of the CSMS, the e-mobility provider and the hub);
 * - that a table scrolls in a .table-scroll - outside one, a table wider than
 *   its card stood past it on a phone, and the page scrolled sideways (found
 *   on the local controller's logins, once its cards kept to the page);
 * - that a page says what somebody may not do through mayButNot, and names no
 *   role that would do - said by hand, the DNS and NTS pages told an account
 *   with no role "Signed in as , which may …", and the kinds' own pages named
 *   roles only a configuration file knows.
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
 * The tables a page draws outside a .table-scroll, which scrolls a table
 * wider than its card inside the card. Outside one, on a phone, the table
 * stood past its card and the page scrolled sideways with it: the local
 * controller's logins, 360 and 591 pixels wide in a card of 304.
 */
export function tablesOutsideAScroll(Page: Page): string[] {
    return [ ...Page.source.matchAll(/<table\b[^>]*>/g) ].
               filter(match => !/<div class="[^"]*\btable-scroll\b[^"]*"[^>]*>\s*$/.test(Page.source.slice(0, match.index))).
               map(match => match[0]);
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
 * How often a page with a form draws itself anew with draw() - the whole of
 * it, from what the node said - beyond the first time: every form on it
 * drawn again as the node has it, and what somebody had typed into one and
 * not saved yet gone, without a word, as the page itself threw it away.
 * Saving the connection took the credentials typed below it with it, and
 * removing an entry the address typed beside the list (on the local
 * controller). keepDrafts(content, the form saved or null, draw) draws the
 * page anew and puts back what was typed into every other form, as the
 * vehicle's pages did first. Asked of the code, not of what a comment says.
 */
export function drawnAnewWithoutItsDrafts(Page: Page): number {

    if (drawsByComparing(Page))
        return 0;

    const code = Page.source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

    return Math.max(0, (code.match(/(?<![\w.])draw\(\);/g) ?? []).length - 1);

}

/**
 * Whether a page draws through view.ts - lit-html, which compares a draw with
 * what is on the page and leaves what a draw does not change, typed text and
 * focus and all - rather than through html.ts's innerHTML. Such a page needs
 * no keepDrafts, and is held to the rules of its own below instead.
 */
export function drawsByComparing(Page: Page): boolean {
    return /\bfrom\s+'(@node|\.\.?)\/view'/.test(Page.source);
}

/**
 * Where a page drawn by view.ts says an attribute as text inside a tag -
 * ${may ? '' : html`disabled`} - where lit-html wants it bound:
 * ?disabled=${!may}. lit-html refuses one at the moment the page is drawn,
 * which no test that only reads the source would see. Asked of the code: a
 * ${...} that stands where an attribute would, outside quotes, in a tag.
 */
export function attributesSaidAsText(Page: Page): string[] {

    const code  = Page.source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    const found = [] as string[];

    for (const match of code.matchAll(/\s\$\{/g)) {

        const before = code.slice(0, match.index);
        const opened = before.lastIndexOf('<');

        if (opened < 0 || before.lastIndexOf('>') > opened || !/^<[a-zA-Z]/.test(before.slice(opened)))
            continue;

        const inTag = before.slice(opened);

        if ((inTag.match(/"/g) ?? []).length % 2 === 1)
            continue;

        found.push(code.slice(match.index + 1, code.indexOf('}', match.index) + 1).replace(/\s+/g, ' '));

    }

    return found;

}

/**
 * Where a page drawn by view.ts says what a textarea holds as an expression
 * between its tags - <textarea>${lines}</textarea> - which lit-html does not
 * support: its development build warns of it, the build a page is bundled
 * with says nothing, and that it still drew in happy-dom is no promise.
 * .defaultValue=${lines} is the binding lit-html says to use instead (the
 * charging station server's names it is reachable as, on the local
 * controller). Asked of the code: a ${ between a textarea's tag and its end.
 */
export function expressionsInATextarea(Page: Page): string[] {

    const code = Page.source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

    return [ ...code.matchAll(/<textarea\b[\s\S]*?<\/textarea>/g) ].
               map(match => match[0]).
               filter(area => area.slice(endOfTag(area)).includes('${')).
               map(area => area.replace(/\s+/g, ' '));

}

/**
 * Where the tag a piece of a template begins with ends: after the first >
 * that is outside a ${...} - the arrow of a listener bound in the tag is
 * inside one.
 */
function endOfTag(Text: string): number {

    let depth = 0;

    for (let i = 0; i < Text.length; i++) {
        if (Text.startsWith('${', i))   { depth++; i++; }
        else if (depth > 0 && Text[i] === '{')   depth++;
        else if (depth > 0 && Text[i] === '}')   depth--;
        else if (depth === 0 && Text[i] === '>') return i + 1;
    }

    return Text.length;

}

/**
 * The patterns of a page that a browser refuses, and with them every check
 * of what is typed into their fields: Chrome reads a pattern as a regular
 * expression with the v flag, in which a hyphen in a class is escaped
 * wherever it stands - [a-z0-9-]+ is no expression at all there, and the
 * group's id on the local controller was asked nothing (found in Chrome's
 * console). Asked of each pattern="..." written out, as the template hands
 * it on: a \\ in the source is one \ in the attribute.
 */
export function patternsABrowserRefuses(Page: Page): string[] {

    return [ ...Page.source.matchAll(/\spattern="([^"]*)"/g) ].
               map(match => match[1]!).
               filter(pattern => !pattern.includes('${')).
               map(pattern => pattern.replace(/\\\\/g, '\\')).
               filter(pattern => {
                   try {
                       new RegExp(`^(?:${pattern})$`, 'v');
                       return false;
                   }
                   catch {
                       return true;
                   }
               });

}

/**
 * How many forms of a page have neither an id nor a data-id: keepDrafts cannot
 * tell such a form from its neighbours after a drawing anew, and drops what
 * was typed into it without a word - the forms drawn for each login and each
 * connection on the charging station's pages, which said only data-edit.
 */
export function formsKnownByNothing(Page: Page): number {
    return [ ...Page.source.matchAll(/<form(\s[^>]*)?>/g) ].
               filter(match => !/\s(id|data-id)="[^"]+"/.test(match[1] ?? '')).
               length;
}

/**
 * The forms a page names as the one saved - keepDrafts(content, 'x-form',
 * draw) - that it has no form of. Misspelt, the form saved is not told from
 * the others, and what was typed into it comes back once it is saved, as if
 * it were still to be saved: 'token-forms' for 'token-form', a mutation the
 * count of draw() let through (the e-mobility provider). A name the page
 * gives by a variable, or by an entry's data-id, is not asked - and neither
 * is one handed on through a function of the page's own, drawAnew('x-form')
 * or load('x-form'): a page that names the form saved that way has only its
 * own eyes on it (the charging station and the meter found theirs so).
 */
export function keptFormsNotOnThePage(Page: Page): string[] {

    const forms = new Set(formsOf(Page));

    return [ ...Page.source.matchAll(/keepDrafts\(\s*[\w.]+\s*,\s*'([^']+)'/g) ].
               map(match => match[1]!).
               filter(name => !forms.has(name));

}

/**
 * Where a page says itself who is signed in - "Signed in as ${…}" - rather
 * than through mayButNot. Said by hand, it was said four ways, and one of them,
 * ?? 'somebody' after the roles joined, told an account with no role "Signed
 * in as , which may …": [].join(', ') is '', not the undefined ?? waits for.
 */
export function signedInSaidByHand(Page: Page): string[] {
    return [ ...Page.source.matchAll(/Signed in as \$\{[^}]*\}/g) ].
               map(match => match[0]);
}

/**
 * Where a page names a role as the one that something needs - "That needs the
 * CPO or the system administrator role" - though which roles there are, and
 * what each may, is the configuration file's to say: a node given other roles,
 * or other rights for these, sends somebody after a role it does not have.
 * "That needs a role that may change it", as mayButNot says it, names none.
 */
export function rolesNamedAsNeeded(Page: Page): string[] {
    return [ ...Page.source.matchAll(/\bneeds?\s+the\s+(?:(?!roles?\b)[\w-]+,?\s+(?:(?:or|and)\s+)?(?:the\s+)?){1,6}?roles?\b/gi) ].
               map(match => match[0].replace(/\s+/g, ' '));
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

    describe('a page drawn anew', () => {

        for (const page of pages.filter(page => page.source.includes('<form'))) {

            it(`${page.name} draws itself anew through keepDrafts, so that what is typed into one form outlives saving another`, () => {
                const times = drawnAnewWithoutItsDrafts(page);
                assert.equal(times, 0, `${page.name} draws itself anew with draw() ${times} time(s) beyond the first, and what is typed ` +
                                       `into its forms goes with it - keepDrafts(content, the form saved or null, draw) puts it back`);
            });

            it(`${page.name} names a form it has where it names the one saved`, () => {
                const named = keptFormsNotOnThePage(page);
                assert.deepEqual(named, [], `${page.name} names ${named.join(', ')} as the form saved, and has no form of that id - ` +
                                            `what was typed into the one saved comes back after the save`);
            });

            it(`${page.name} gives every form an id or a data-id, so that what is typed into it outlives a drawing anew`, () => {
                const unknown = formsKnownByNothing(page);
                assert.equal(unknown, 0, `${page.name} has ${unknown} form(s) with neither an id nor a data-id, whose drafts ` +
                                         `keepDrafts cannot tell from their neighbours and drops`);
            });

        }

    });

    describe('a page drawn by comparing', () => {

        for (const page of pages.filter(drawsByComparing)) {

            it(`${page.name} binds an attribute that is there or not, rather than saying it as text in a tag`, () => {
                assert.deepEqual(attributesSaidAsText(page), [],
                                 `${page.name} draws with view.ts and says an attribute as text - ?disabled=\${...}, ?checked=\${...} ` +
                                 `bind it; lit-html refuses the other when the page is drawn`);
            });

            it(`${page.name} binds what a textarea holds as its defaultValue, not as an expression between its tags`, () => {
                assert.deepEqual(expressionsInATextarea(page), [],
                                 `${page.name} draws with view.ts and puts an expression into a textarea, which lit-html does not support - ` +
                                 `.defaultValue=\${...} does`);
            });

            it(`${page.name} needs neither keepDrafts nor innerHTML`, () => {
                assert.doesNotMatch(page.source, /keepDrafts\(/,
                                    `${page.name} draws with view.ts, which keeps what is typed by itself - keepDrafts would put back a value over the node's answer`);
                assert.doesNotMatch(page.source, /\.innerHTML\s*=/,
                                    `${page.name} draws with view.ts and replaces a part of itself with innerHTML, which throws away what it was keeping`);
            });

        }

    });

    // Every page, not the ones with a form: an input outside any form is
    // emptied as easily (the charging station's evses.ts, which this did not
    // ask while it asked only the pages with a form).
    describe('a number on a page', () => {

        for (const page of pages)
            it(`${page.name} reads its numbers with numberField, so that an emptied field is not 0`, () => {
                const read = numbersReadAsZeroWhenEmptied(page);
                assert.deepEqual(read, [], `${page.name} reads ${read.join(', ')} with Number(), which makes an emptied field 0`);
            });

    });

    describe('a pattern on a page', () => {

        for (const page of pages)
            it(`${page.name} writes every pattern as a browser reads it`, () => {
                const refused = patternsABrowserRefuses(page);
                assert.deepEqual(refused, [], `${page.name} has a pattern a browser refuses, and with it every check of its field: ` +
                                              `${refused.join(', ')} - in a class, a hyphen is escaped (\\\\-), as the v flag wants it`);
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

        for (const page of pages) {

            it(`${page.name} takes its look from the stylesheet, not from a style the policy drops`, () => {
                const styles = inlineStylesOf(page);
                assert.deepEqual(styles, [], `${page.name} writes ${styles.join(', ')} into itself - style-src 'self' lets no style through that is not in the stylesheet; say it by a class`);
            });

            it(`${page.name} scrolls a table inside a .table-scroll, so that on a phone the page does not scroll sideways`, () => {
                const tables = tablesOutsideAScroll(page);
                assert.deepEqual(tables, [], `${page.name} draws ${tables.join(', ')} outside a <div class="table-scroll"> - wider than its card, it stands past it`);
            });

        }

    });

    describe('what a page says somebody may not do', () => {

        for (const page of pages) {

            it(`${page.name} says who is signed in through mayButNot, so that an account with no role is not left without a name`, () => {
                const said = signedInSaidByHand(page);
                assert.deepEqual(said, [], `${page.name} says ${said.join(', ')} itself - mayButNot('look at …', 'change it') says it as every kind says it`);
            });

            it(`${page.name} names no role as the one that is needed, as which roles there are is the configuration file's to say`, () => {
                const named = rolesNamedAsNeeded(page);
                assert.deepEqual(named, [], `${page.name} says "${named.join('", "')}" - "that needs a role that may …" names none`);
            });

        }

    });

}
