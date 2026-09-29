/**
 * What the stylesheets promise a narrow screen, asked of the rules
 * themselves - Node draws no page, so what these guard was measured in a
 * browser, 375 pixels across: a column no wider than the page (a table in a
 * card made the local controller's 402), a name server's address on a line
 * of its own (it had 67 pixels), and an open menu read from the top down
 * (the local controller's Logs stood beside Configuration).
 */

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';


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
