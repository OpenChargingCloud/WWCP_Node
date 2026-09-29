/**
 * What the page for an address with no page says there is instead.
 *
 * Mounted at "/EV": the base is read from the page once, when the modules are
 * loaded, so the page is there before they are imported.
 */

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

(globalThis as unknown as { document: unknown }).document = {
    querySelector: (selector: string) => selector === 'meta[name="base"]'      ? { content: '/EV' }
                                       : selector === 'meta[name="node-name"]' ? { content: 'energy meter' }
                                       : null
};

const { whatThereIs } = await import('./notFound.ts');


describe('what there is instead of a page that is not', () => {

    it('is one link to the sign-in for somebody signed out, not a list of links that would all end there', () => {

        const said = whatThereIs(null).value;

        assert.match       (said, /^<a href="\/EV\/login">Sign in<\/a> to see what this energy meter has\.$/);
        assert.equal       (said.match(/<a /g)?.length, 1);

    });

    it('is the pages somebody signed in may open, each with the base in its link', () => {

        const said = whatThereIs([
            { path: '/meter',  label: 'Meter',  icon: 'fa-bolt'    },
            { path: '/logs',   label: 'Logs',   icon: 'fa-list-ul' }
        ]).value;

        assert.match(said, /This energy meter has/);
        assert.match(said, /<a href="\/EV\/meter">Meter<\/a>\s+and <a href="\/EV\/logs">Logs<\/a>\./);

    });

    it('says so where nothing is open to them, rather than asking them to sign in again', () => {
        assert.equal(whatThereIs([]).value, 'Nothing this energy meter has is open to the account signed in here.');
    });

    it('writes what a page is called as text', () => {
        assert.match(whatThereIs([ { path: '/x', label: 'A <b>', icon: 'fa-x' } ]).value, />A &lt;b&gt;<\/a>/);
    });

});
