/**
 * The frame every signed-in page sits in: which entries of the menu somebody
 * is shown, which one is the page being shown, where its links go, and who
 * the foot of the menu says is signed in - drawn, in a document of happy-dom,
 * with what a page puts beside its heading.
 *
 * Mounted at "/EV", as a node is where several share one HTTP server: the
 * base is read from the page once, when the modules are loaded, so the page
 * is there before they are imported.
 */

import '../test/dom.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { NodeMe }       from './api/client.ts';

// What the node writes into the page it serves, read as the modules load.
for (const [ name, content ] of [ [ 'base', '/EV' ], [ 'node-name', 'electric vehicle' ] ]) {
    const meta = document.createElement('meta');
    meta.name     = name!;
    meta.content  = content!;
    document.head.append(meta);
}

const { auth }                                                             = await import('./auth.ts');
const { configureShell, mayButNot, mayOpen, menuView, shell, signedInAs, versions, visibleMenu, whoIsSignedIn } = await import('./shell.ts');
const { html: stringHTML }                                                 = await import('./html.ts');
const { html, render }                                                     = await import('./view.ts');

/** A template drawn into an element of its own. */
function drawn(template: Parameters<typeof render>[1]): HTMLElement {
    const element = document.createElement('div');
    render(element, template);
    return element;
}


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

    it('takes a page below an entry that says nothing of its own as its entry\'s', () => {

        // The roaming hub's OCPI, below the configuration and with no
        // permission of its own: for an account that may read the time
        // servers and nothing else, it stood in the configuration's place.
        const withOCPI = [ { ...menu[0]!, children: [ ...menu[0]!.children!, { path: '/configuration/ocpi', label: 'OCPI', icon: 'fa-plug' } ] } ];

        auth.set(signedIn('nts:read'));
        assert.deepEqual(paths(visibleMenu(withOCPI)), [ '/configuration/nts' ]);

        auth.set(signedIn('configuration:read'));
        assert.deepEqual(paths(visibleMenu(withOCPI)), [ '/configuration [/configuration/ocpi]' ]);

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

        const menu    = drawn(menuView(entries, '/logs'));
        const current = [ ...menu.querySelectorAll('a[aria-current]') ];

        assert.deepEqual(current.map(link => [ link.getAttribute('href'), link.className, link.getAttribute('aria-current') ]),
                         [ [ '/EV/logs', 'active', 'page' ] ]);
        assert.equal(menu.querySelectorAll('a.active').length, 1);

    });

    it('carries the base in every link, for a page opened in a tab the router never sees', () => {

        const links = [ ...drawn(menuView(entries, '/configuration')).querySelectorAll('a') ].map(link => link.getAttribute('href'));

        assert.deepEqual(links, [ '/EV/configuration', '/EV/configuration/dns', '/EV/logs' ]);

    });

    it('unfolds the pages below an entry while it or one of them is open, and not otherwise', () => {

        assert.ok(drawn(menuView(entries, '/configuration')).querySelector('.submenu')      !== null);
        assert.ok(drawn(menuView(entries, '/configuration/dns')).querySelector('.submenu')  !== null);
        assert.ok(drawn(menuView(entries, '/logs')).querySelector('.submenu')               === null);

    });

    it('writes what an entry is called as text', () => {

        const menu = drawn(menuView([ { path: '/logs', label: 'Logs & <b>more</b>', icon: 'fa-list-ul' } ], ''));

        assert.equal(menu.querySelector('a span')!.textContent, 'Logs & <b>more</b>');
        assert.ok(menu.querySelector('b') === null, 'what an entry is called was taken as markup');

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
        assert.match(drawn(versions()).textContent!.trim(), /^electric vehicle \S+ \u00b7 web \S+$/);
    });

});


describe('what a page says somebody may not do', () => {

    it('says who they are signed in as, and that it needs a role that may', () => {

        configureShell({ name: 'Electric Vehicle', icon: 'fa-car', menu: [] });

        assert.equal(mayButNot('look at the name resolution', 'change it', { ...signedIn(), roles: [ 'driver', 'service' ] }),
                     'Signed in as driver, service, which may look at the name resolution but not change it. ' +
                     'That needs a role that may change it.');

    });

    it('says that they hold no role where they hold none, rather than leave the name empty', () => {

        configureShell({ name: 'Electric Vehicle', icon: 'fa-car', menu: [] });

        assert.equal(signedInAs({ ...signedIn(), roles: [] }), 'Signed in as an account with no role');

        assert.equal(mayButNot('look at the time servers', 'change them', { ...signedIn(), roles: [] }),
                     'Signed in as an account with no role, which may look at the time servers but not change them. ' +
                     'That needs a role that may change them.');

    });

    it('names them as the foot of the menu does, where the kind of node has a better name for a role', () => {

        configureShell({
            name:  'Energy Meter',
            icon:  'fa-bolt',
            menu:  [],
            who:   () => ({ line: 'Auditor', title: 'may read everything and change nothing' })
        });

        assert.equal(signedInAs(signedIn()), 'Signed in as Auditor');

    });

    it('asks who is signed in when it is said, not when the page was loaded', () => {

        configureShell({ name: 'Electric Vehicle', icon: 'fa-car', menu: [] });

        auth.set({ ...signedIn(), roles: [ 'installer' ] });

        try {
            assert.match(mayButNot('look at the store', 'change it'), /^Signed in as installer, which may look at the store/);
        }
        finally {
            auth.set(null);
        }

    });

    it('is written as text on a page, a role\'s name with it', () => {

        configureShell({ name: 'Electric Vehicle', icon: 'fa-car', menu: [] });

        const said = drawn(html`<div class="notice">${mayButNot('look at the store', 'change it', { ...signedIn(), roles: [ '<b>boss</b>' ] })}</div>`);

        assert.match(said.textContent!, /Signed in as <b>boss<\/b>, which may/);
        assert.ok(said.querySelector('b') === null, 'a role\'s name was taken as markup');

    });

});


describe('the menu on a screen too narrow for it beside the page', () => {

    /** The frame drawn into a root of its own, for somebody who may read the configuration and the name servers. */
    function frame(root: HTMLElement = document.createElement('div')): HTMLElement {

        configureShell({ name: 'Local Controller', icon: 'fa-sitemap', menu });
        auth.set(signedIn('configuration:read', 'dns:read'));

        shell(root, { active: '/configuration', title: 'Configuration' });

        return root;

    }

    const toggle  = (root: HTMLElement) => root.querySelector<HTMLButtonElement>('#menu-toggle')!;
    const isOpen  = (root: HTMLElement) => [ root.querySelector('.sidebar')!.classList.contains('open'), toggle(root).getAttribute('aria-expanded') ];

    it('is folded away behind a button that says so, and which parts it opens', () => {

        const root = frame();

        assert.equal(toggle(root).getAttribute('aria-expanded'), 'false');
        assert.equal(toggle(root).getAttribute('aria-controls'), 'menu sidebar-foot');
        assert.ok(root.querySelector('#menu.menu')                 !== null, 'the menu the button opens');
        assert.ok(root.querySelector('#sidebar-foot.sidebar-foot') !== null, 'the foot the button opens');

    });

    it('opens with the button, says it is open, and folds away with it again', () => {

        const root = frame();

        toggle(root).click();

        assert.deepEqual(isOpen(root), [ true, 'true' ]);

        toggle(root).click();

        assert.deepEqual(isOpen(root), [ false, 'false' ]);

    });

    it('opens with one click after the frame was drawn again into the same root, not with every listener a drawing added', () => {

        const root = frame();
        frame(root);

        toggle(root).click();

        assert.deepEqual(isOpen(root), [ true, 'true' ]);

    });

});


describe('the frame of a page', () => {

    /** The frame drawn into a root of its own with what a page puts beside its heading. */
    function framed(actions?: Parameters<typeof shell>[1]['actions']): { root: HTMLElement; content: HTMLElement } {

        configureShell({ name: 'Local Controller', icon: 'fa-sitemap', menu });
        auth.set(signedIn('configuration:read'));

        const root    = document.createElement('div');
        const content = shell(root, { active: '/configuration', title: 'Configuration', subtitle: 'What it was started with', actions });

        return { root, content };

    }

    it('hands back the element the page draws itself into, below the heading', () => {

        const { root, content } = framed();

        assert.ok(content === root.querySelector('main.content > #content-body'), 'not the body of the page');
        assert.equal(root.querySelector('.page-head h1')!.textContent, 'Configuration');
        assert.equal(root.querySelector('.page-head p.muted')!.textContent, 'What it was started with');
        assert.equal(root.querySelector('.brand span')!.textContent, 'Local Controller');

    });

    it('shows a template of view.ts beside the heading, with its listener bound in it', () => {

        let reloaded = 0;

        const { root } = framed(html`<button type="button" id="reload" class="btn small" @click=${() => reloaded++}>Reload</button>`);

        const reload = root.querySelector<HTMLButtonElement>('.page-actions #reload');

        assert.ok(reload !== null, `no Reload beside the heading - there is "${root.querySelector('.page-actions')!.innerHTML}"`);

        reload.click();

        assert.equal(reloaded, 1);

    });

    it('shows a fragment of html.ts beside the heading as the markup it is, for a kind that still says it so', () => {

        const { root } = framed(stringHTML`<button type="button" id="reload" class="btn small">Reload ${'<b>all</b>'}</button>`);

        assert.equal(root.querySelector('.page-actions #reload')!.textContent, 'Reload <b>all</b>');
        assert.ok(root.querySelector('.page-actions b') === null, 'what the fragment escaped was taken as markup');

    });

    it('signs out with the button in the foot of the menu', () => {

        const signOut = auth.signOut;
        let   asked   = 0;

        auth.signOut = async () => { asked++; };

        try {
            framed().root.querySelector<HTMLButtonElement>('#sign-out')!.click();
            assert.equal(asked, 1);
        }
        finally {
            auth.signOut = signOut;
        }

    });

});
