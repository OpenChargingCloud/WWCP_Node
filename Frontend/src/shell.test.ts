/**
 * The frame every signed-in page sits in: which entries of the menu somebody
 * is shown, which one is the page being shown, where its links go, and who
 * the foot of the menu says is signed in.
 *
 * Mounted at "/EV", as a node is where several share one HTTP server: the
 * base is read from the page once, when the modules are loaded, so the page
 * is there before they are imported.
 */

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { NodeMe }       from './api/client.ts';

(globalThis as unknown as { document: unknown }).document = {
    querySelector: (selector: string) => selector === 'meta[name="base"]'      ? { content: '/EV' }
                                       : selector === 'meta[name="node-name"]' ? { content: 'electric vehicle' }
                                       : null
};

const { auth }                                                             = await import('./auth.ts');
const { configureShell, mayOpen, menuHTML, versions, visibleMenu, whoIsSignedIn } = await import('./shell.ts');


/** Somebody signed in who may do this, and nothing else. */
const signedIn = (...Permissions: string[]): NodeMe =>
    ({ username: 'alice', roles: [ 'desk' ], permissions: Permissions as NodeMe['permissions'], mayReadTheLog: true });

const menu = [
    {
        path:        '/configuration',
        label:       'Configuration',
        icon:        'fa-sliders',
        permission:  [ 'configuration:read' ],
        children:    [
            { path: '/configuration/dns',  label: 'DNS client',  icon: 'fa-magnifying-glass-location',  permission: [ 'dns:read' ] },
            { path: '/configuration/nts',  label: 'NTS client',  icon: 'fa-clock',                      permission: [ 'nts:read' ] }
        ]
    },
    { path: '/contracts',  label: 'Contracts',  icon: 'fa-file-contract',  permission: [ 'contracts:run', 'contracts:edit' ] },
    { path: '/accounts',   label: 'Accounts',   icon: 'fa-users' }
];

const paths = (Entries: { path: string; children?: { path: string }[] }[]) =>
    Entries.map(entry => entry.children ? `${entry.path} [${entry.children.map(child => child.path).join(' ')}]` : entry.path);


describe('what the menu shows somebody', () => {

    it('is everything to somebody who may do everything, children included', () => {

        auth.set(signedIn('configuration:read', 'dns:read', 'nts:read', 'contracts:run'));

        assert.deepEqual(paths(visibleMenu(menu)), [
            '/configuration [/configuration/dns /configuration/nts]',
            '/contracts',
            '/accounts'
        ]);

    });

    it('is an entry without a permission to everybody signed in', () => {

        auth.set(signedIn());

        assert.deepEqual(paths(visibleMenu(menu)), [ '/accounts' ]);

    });

    it('is an entry to whoever holds any one of its permissions, not only to whoever holds them all', () => {

        auth.set(signedIn('contracts:edit'));

        assert.ok(visibleMenu(menu).some(entry => entry.path === '/contracts'),
                  'somebody who may change contracts was not shown them because they may not run them');

    });

    it('leaves out the pages below an entry that are not theirs', () => {

        auth.set(signedIn('configuration:read', 'nts:read'));

        assert.deepEqual(paths(visibleMenu(menu)), [
            '/configuration [/configuration/nts]',
            '/accounts'
        ]);

    });

    it('puts the pages that are theirs in the place of an entry that is not', () => {

        // Somebody who may look at the name servers and at nothing else of the
        // configuration: the configuration's page would refuse them, and the
        // name servers they may read would have gone with it.
        auth.set(signedIn('dns:read'));

        assert.deepEqual(paths(visibleMenu(menu)), [ '/configuration/dns', '/accounts' ]);

    });

    it('asks an entry that decides for itself', () => {

        let theirs = false;
        const entry = { path: '/logs', label: 'Logs', icon: 'fa-list-ul', permission: () => theirs };

        auth.set(signedIn());

        assert.equal(mayOpen(entry), false);

        theirs = true;

        assert.equal(mayOpen(entry), true);

    });

    it('is the menu the kind of node said it has, when asked without one', () => {

        configureShell({ name: 'Electric Vehicle', icon: 'fa-car', menu });
        auth.set(signedIn('contracts:run'));

        assert.deepEqual(paths(visibleMenu()), [ '/contracts', '/accounts' ]);

    });

});


describe('the menu as it is drawn', () => {

    const entries = [
        {
            path:      '/configuration',
            label:     'Configuration',
            icon:      'fa-sliders',
            children:  [ { path: '/configuration/dns', label: 'DNS client', icon: 'fa-magnifying-glass-location' } ]
        },
        { path: '/logs', label: 'Logs & more', icon: 'fa-list-ul' }
    ];

    it('marks the page being shown, and only that one', () => {

        const drawn = menuHTML(entries, '/logs').value;

        assert.equal(drawn.match(/aria-current="page"/g)?.length, 1);
        assert.match(drawn, /<a href="\/EV\/logs"\s+class="active"\s+aria-current="page">/);

    });

    it('carries the base in every link, for a page opened in a tab the router never sees', () => {

        const drawn = menuHTML(entries, '/configuration').value;

        assert.match(drawn, /href="\/EV\/configuration"/);
        assert.match(drawn, /href="\/EV\/configuration\/dns"/);
        assert.doesNotMatch(drawn, /href="\/configuration/);

    });

    it('unfolds the pages below an entry while it or one of them is open, and not otherwise', () => {

        assert.match       (menuHTML(entries, '/configuration').value,      /class="submenu"/);
        assert.match       (menuHTML(entries, '/configuration/dns').value,  /class="submenu"/);
        assert.doesNotMatch(menuHTML(entries, '/logs').value,               /class="submenu"/);

    });

    it('writes what an entry is called as text', () => {
        assert.match(menuHTML(entries, '').value, /Logs &amp; more/);
    });

});


describe('the foot of the menu', () => {

    it('says who is signed in by their roles', () => {

        configureShell({ name: 'Electric Vehicle', icon: 'fa-car', menu: [] });

        assert.deepEqual(whoIsSignedIn({ ...signedIn(), roles: [ 'driver', 'service' ] }),
                         { line: 'driver, service', title: 'Signed in as driver, service' });

        assert.deepEqual(whoIsSignedIn({ ...signedIn(), roles: [] }),
                         { line: '', title: 'Signed in, in no role' });

    });

    it('says it as the kind of node says it, where it has a better name for a role', () => {

        configureShell({
            name:  'Energy Meter',
            icon:  'fa-bolt',
            menu:  [],
            who:   Me => ({ line: 'Auditor', title: `${Me.username} may read everything and change nothing` })
        });

        assert.deepEqual(whoIsSignedIn(signedIn()),
                         { line: 'Auditor', title: 'alice may read everything and change nothing' });

    });

    it('names the node as the node names itself, beside its version and the web interface\'s', () => {
        assert.match(versions().value, /^electric vehicle \S+ &middot; web \S+$/);
    });

});
