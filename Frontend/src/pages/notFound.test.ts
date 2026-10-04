/**
 * What the page for an address with no page says there is instead.
 *
 * Mounted at "/EV": the base is read from the page once, when the modules are
 * loaded, so the page is there before they are imported.
 */

import '../../test/dom.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

document.head.innerHTML = '<meta name="base" content="/EV"><meta name="node-name" content="energy meter">';

const { whatThereIs } = await import('./notFound.ts');
const { render }      = await import('../view.ts');


/** What whatThereIs draws: its text, and the links in it. */
function drawn(...args: Parameters<typeof whatThereIs>): { text: string; links: { href: string; text: string }[] } {
    const element = document.createElement('p');
    render(element, whatThereIs(...args));
    return {
        text:   element.textContent!.replace(/\s+/g, ' ').trim(),
        links:  [ ...element.querySelectorAll('a') ].map(a => ({ href: a.getAttribute('href')!, text: a.textContent! }))
    };
}


describe('what there is instead of a page that is not', () => {

    it('is one link to the sign-in for somebody signed out, not a list of links that would all end there', () => {

        const said = drawn(null);

        assert.equal    (said.text,  'Sign in to see what this energy meter has.');
        assert.deepEqual(said.links, [ { href: '/EV/login', text: 'Sign in' } ]);

    });

    it('is the pages somebody signed in may open, each with the base in its link', () => {

        const said = drawn([
            { path: '/meter',  label: 'Meter',  icon: 'fa-bolt'    },
            { path: '/logs',   label: 'Logs',   icon: 'fa-list-ul' }
        ]);

        assert.equal    (said.text,  'This energy meter has Meter and Logs.');
        assert.deepEqual(said.links, [ { href: '/EV/meter', text: 'Meter' }, { href: '/EV/logs', text: 'Logs' } ]);

    });

    it('says so where nothing is open to them, rather than asking them to sign in again', () => {
        assert.equal(drawn([]).text, 'Nothing this energy meter has is open to the account signed in here.');
    });

    it('writes what a page is called as text', () => {

        const said = drawn([ { path: '/x', label: 'A <b>', icon: 'fa-x' } ]);

        assert.deepEqual(said.links, [ { href: '/EV/x', text: 'A <b>' } ]);

    });

});
