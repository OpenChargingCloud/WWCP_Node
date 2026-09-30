/**
 * What the stylesheets promise a narrow screen, asked of the rules
 * themselves - Node draws no page, so what these guard was measured in a
 * browser, 375 pixels across: a column no wider than the page (a table in a
 * card made the local controller's 402), a name server's address on a line
 * of its own (it had 67 pixels), and an open menu read from the top down
 * (the local controller's Logs stood beside Configuration).
 */

import { strict as assert }           from 'node:assert';
import { readdirSync, readFileSync }  from 'node:fs';
import { describe, it }               from 'node:test';


/** A rule of a stylesheet: what it says, and the rules inside it. */
interface Rule {
    selector:      string;
    declarations:  Map<string, string>;
    rules:         Rule[];
}

/**
 * The rules of an SCSS file as they nest, without its comments - enough of
 * SCSS for these files, which have no strings with braces or slashes in them.
 */
function rulesOf(File: string): Rule {

    const text  = readFileSync(new URL(`./styles/${File}`, import.meta.url), 'utf-8').
                      replace(/\/\*[\s\S]*?\*\//g, '').
                      replace(/\/\/[^\n]*/g, '');

    const root: Rule  = { selector: '', declarations: new Map(), rules: [] };
    const open        = [ root ];
    let   said        = '';

    const declare = (rule: Rule, declaration: string) => {
        const colon = declaration.indexOf(':');
        if (colon > 0)
            rule.declarations.set(declaration.slice(0, colon).trim(),
                                  declaration.slice(colon + 1).trim().replace(/\s+/g, ' '));
    };

    for (const char of text) {

        if (char === '{') {
            const rule: Rule = { selector: said.trim().replace(/\s+/g, ' '), declarations: new Map(), rules: [] };
            open[open.length - 1].rules.push(rule);
            open.push(rule);
            said = '';
        }

        else if (char === '}') {
            declare(open.pop()!, said);
            said = '';
        }

        else if (char === ';') {
            declare(open[open.length - 1], said);
            said = '';
        }

        else
            said += char;

    }

    return root;

}

/** The rule reached through these selectors, one inside the other. */
function rule(Root: Rule, ...Selectors: string[]): Rule {

    return Selectors.reduce((outer, selector) => {
        const inner = outer.rules.find(candidate => candidate.selector === selector);
        assert.ok(inner, `no rule "${selector}" inside "${outer.selector}"`);
        return inner;
    }, Root);

}

/** Every value of one property, in a rule and the rules inside it. */
function valuesOf(Rule: Rule, Property: string): string[] {
    return [ ...(Rule.declarations.has(Property) ? [ Rule.declarations.get(Property)! ] : []),
             ...Rule.rules.flatMap(inner => valuesOf(inner, Property)) ];
}


describe('a narrow screen', () => {

    const narrow = rule(rulesOf('_responsive.scss'), '@media (max-width: 52rem)');

    it('has no column as wide as the widest thing in it, but one as wide as the page', () => {

        // A track of 1fr is minmax(auto, 1fr): at least as wide as what is in
        // it cannot get narrower - a whole table.
        const columns = valuesOf(narrow, 'grid-template-columns');

        assert.ok(columns.length >= 2, 'the frame\'s and the cards\'');

        for (const tracks of columns)
            assert.doesNotMatch(tracks.replace(/minmax\(0, [\d.]+fr\)/g, ''), /[\d.]+fr/,
                                `"${tracks}" lets a column grow to what is in it`);

    });

    it('lists the open menu an entry to a line, and scrolls what does not fit', () => {

        const sidebar  = rule(narrow, '.sidebar');
        const menu     = rule(sidebar, '.menu');

        assert.equal(sidebar.declarations.get('overflow-y'), 'auto');
        assert.equal(menu.declarations.get('flex'),         '1 0 100%', 'the menu on lines of its own');
        assert.ok(!menu.declarations.has('display'),        'the entries flowed as a row');
        assert.ok(!menu.declarations.has('flex-wrap'),      'the entries flowed as a row');

    });

});


describe('a path, a token or an address in a sentence', () => {

    it('breaks anywhere in code, in a hint and in a notice, rather than taking the page sideways', () => {

        // Nothing to break at: on a phone the DNS page's "Saved to
        // D:\Coding\...\configuration.json" made it 420 pixels of 375, and the
        // certificate store's directory 443 (found by the hub).
        const rules = readdirSync(new URL('./styles/', import.meta.url)).
                          filter(file => file.endsWith('.scss')).
                          flatMap(file => rulesOf(file).rules);

        for (const selector of [ 'code', '.hint', '.notice' ])
            assert.ok(rules.some(rule => rule.selector.split(',').map(one => one.trim()).includes(selector) &&
                                         rule.declarations.get('overflow-wrap') === 'anywhere'),
                      `${selector} does not break a word that has nothing to break at`);

    });

    it('breaks a sentence between its words, in the test dialog as in every hint and notice', () => {

        // break-all broke the words of the test dialog's sentences wherever a
        // line ended - "nothi|ng", "answe|r" at 320 pixels (found by the
        // charging station). What has nothing to break at, a hint breaks
        // anywhere already, as above.
        const every = (Rule: Rule): Rule[] => [ Rule, ...Rule.rules.flatMap(every) ];

        const sentences = readdirSync(new URL('./styles/', import.meta.url)).
                              filter(file => file.endsWith('.scss')).
                              flatMap(file => every(rulesOf(file))).
                              filter(rule => /(^|[\s>,])\.(hint|notice)\b/.test(rule.selector));

        assert.ok(sentences.length >= 2, 'the hints and notices were found at all');

        for (const sentence of sentences)
            assert.notEqual(sentence.declarations.get('word-break'), 'break-all',
                            `"${sentence.selector}" breaks a sentence inside its words`);

    });

    it('keeps to one piece as code in a table, which scrolls in its card instead', () => {

        // Code that may break anywhere is as narrow as one letter, and a table
        // narrows its column to that rather than scroll: on a phone the EMSP's
        // serial numbers stood ten lines high and 29 pixels wide, and a UID of
        // eight letters took three lines (found by the EMSP).
        assert.equal(rule(rulesOf('_tables.scss'), '.table-scroll', 'code').declarations.get('overflow-wrap'), 'normal');

    });

});


describe('a name server in a narrow list', () => {

    const dns = rulesOf('_dns-nts.scss');

    it('has its address on a line of its own', () => {

        assert.equal(rule(dns, '.server-list').declarations.get('container-type'), 'inline-size',
                     'the list measured by its own width');

        const narrow = dns.rules.filter(candidate => /^@container \(max-width: [\d.]+rem\)$/.test(candidate.selector) &&
                                                     candidate.rules.some(inner => inner.selector === '.server-row'));

        assert.ok(narrow.length > 0, 'a narrow list says nothing of its rows');

        const row = rule(narrow[0], '.server-row');

        assert.equal(row.declarations.get('flex-wrap'), 'wrap');
        assert.equal(rule(row, 'input[data-field="address"]').declarations.get('flex-basis'), '100%');

    });

});
