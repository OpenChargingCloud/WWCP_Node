/**
 * What a kind of node gets by starting its web interface through startNode:
 * its routes in the order the router asks them, the pages every node has,
 * and the log offered to whoever the node says it is for.
 *
 * Mounted at "/EV": the base is read from the page once, when the modules
 * are loaded, so the page is there before they are imported.
 */

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { NodeMe }       from './api/client.ts';
import type { Page }         from './router.ts';

(globalThis as unknown as { document: unknown }).document = {
    querySelector: (selector: string) => selector === 'meta[name="base"]' ? { content: '/EV' } : null
};

const { auth }                                                        = await import('./auth.ts');
const { configureShell }                                              = await import('./shell.ts');
const { afterASignInChange, firstPageOfTheMenu, mayReadTheLog, nodeMenu, routesOf } = await import('./start.ts');


const signedIn = (Log: boolean, ...Permissions: string[]): NodeMe =>
    ({ username: 'alice', roles: [ 'desk' ], permissions: Permissions as NodeMe['permissions'], mayReadTheLog: Log });

const page = (Title: string): Page => ({ title: Title, render: () => undefined });

const theKinds = {
    name:   'Electric Vehicle',
    icon:   'fa-car',
    menu:   [],
    pages:  { '/':                    page('the kind\'s home'),
              '/configuration/dns':   page('the kind\'s DNS page'),
              '/vehicle':             page('the vehicle') }
};

/** Which route the router takes for a path: the first whose path is that path. */
const routeFor = (Path: string, Routes = routesOf(theKinds)) =>
    Routes.find(route => route.path === Path);


describe('the routes of a kind of node', () => {

    it('ask the kind\'s own routes first, then its pages, then its public pages, then every node\'s', () => {

        const guard  = { path: '/old-bookmark', page: page('sent on') };
        const routes = routesOf({ ...theKinds, routes: [ guard ], publicPages: { '/signup': page('sign-up') } });

        const at     = (Path: string) => routes.findIndex(route => route.path === Path);

        assert.equal(at('/old-bookmark'), 0);
        assert.ok   (at('/vehicle') < at('/signup'),  'a public page was asked before the kind\'s pages');
        assert.ok   (at('/signup')  < at('/logs'),    'every node\'s pages were asked before the kind\'s public ones');

    });

    it('take the kind\'s page where every node has one at the same path', () => {

        // The router takes the first route that matches, so the kind's "/"
        // has to come before every node's - or the configuration a local
        // controller shows at "/" would have been a redirect to its menu.
        assert.equal(routeFor('/')?.page.title, 'the kind\'s home');

    });

    it('keep every one of the kind\'s pages behind the sign-in, and its public pages not', () => {

        const routes = routesOf({ ...theKinds, publicPages: { '/signup': page('sign-up') } });

        auth.set(null);

        assert.equal(routeFor('/vehicle', routes)?.guard?.(new URL('http://here/EV/vehicle')), '/login?next=%2Fvehicle');
        assert.equal(routeFor('/signup',  routes)?.guard, undefined);
        assert.equal(routeFor('/login',   routes)?.guard, undefined);

    });

    it('have a sign-in, a log, the name servers, the time servers and a home page of every node\'s', () => {

        const routes = routesOf({ ...theKinds, pages: {} });

        assert.equal(routeFor('/login',              routes)?.page.title, 'Sign in');
        assert.equal(routeFor('/logs',               routes)?.page.title, 'Logs');
        assert.equal(routeFor('/configuration/dns',  routes)?.page.title, 'DNS client');
        assert.equal(routeFor('/configuration/nts',  routes)?.page.title, 'NTS client');
        assert.equal(routeFor('/configuration/certificates', routes)?.page.title, 'Certificates');
        assert.equal(routeFor('/configuration/certificates', routesOf({ ...theKinds, pages: {}, certificates: { title: 'Certificate store' } }))?.page.title,
                     'Certificate store');
        assert.equal(routeFor('/',                   routes)?.page,       firstPageOfTheMenu);

        auth.set(null);

        assert.equal(routeFor('/configuration/dns', routes)?.guard?.(new URL('http://here/EV/configuration/dns')),
                     '/login?next=%2Fconfiguration%2Fdns');
        assert.equal(routeFor('/configuration/nts', routes)?.guard?.(new URL('http://here/EV/configuration/nts')),
                     '/login?next=%2Fconfiguration%2Fnts');
        assert.equal(routeFor('/configuration/certificates', routes)?.guard?.(new URL('http://here/EV/configuration/certificates')),
                     '/login?next=%2Fconfiguration%2Fcertificates');

    });

});


describe('the log', () => {

    const toTheLog = (Me: NodeMe | null) => {
        auth.set(Me);
        return routeFor('/logs')?.guard?.(new URL('http://here/EV/logs'));
    };

    it('is opened for whoever the node says it is for', () => {
        assert.equal(toTheLog(signedIn(true)), null);
    });

    it('sends whoever the node says it is not for home, rather than to a stream that would be refused', () => {
        assert.equal(toTheLog(signedIn(false, 'configuration:read')), '/');
    });

    it('sends nobody signed in to the sign-in first', () => {
        assert.equal(toTheLog(null), '/login?next=%2Flogs');
    });

    it('is in the menu of whoever it is for, and of nobody else', () => {

        auth.set(signedIn(true));
        assert.equal(mayReadTheLog(), true);
        assert.equal((nodeMenu.logs.permission as () => boolean)(), true);

        auth.set(signedIn(false, 'configuration:read'));
        assert.equal((nodeMenu.logs.permission as () => boolean)(), false);

        auth.set(null);
        assert.equal(mayReadTheLog(), false);

    });

});


describe('a change of who is signed in', () => {

    const open = new Set([ '/login', '/signup' ]);

    it('follows the log for somebody the node says it is for', () => {
        assert.deepEqual(afterASignInChange(signedIn(true), '/vehicle', open),
                         { followTheLog: true, toTheSignIn: false });
    });

    it('does not open a stream for somebody the node says the log is not for', () => {

        // It would only be refused - and they would then be told they may no
        // longer read a log they never could.
        assert.deepEqual(afterASignInChange(signedIn(false, 'configuration:read'), '/vehicle', open),
                         { followTheLog: false, toTheSignIn: false });

    });

    it('stops following the log once nobody is signed in, and shows the sign-in', () => {
        assert.deepEqual(afterASignInChange(null, '/vehicle', open),
                         { followTheLog: false, toTheSignIn: true });
    });

    it('leaves somebody signed out where they are on a page anybody may open', () => {
        assert.equal(afterASignInChange(null, '/signup', open).toTheSignIn, false);
        assert.equal(afterASignInChange(null, '/login',  open).toTheSignIn, false);
    });

});


describe('the menu entries every node has', () => {

    it('are each shown to whoever may read what they are about', () => {
        assert.deepEqual(nodeMenu.configuration().permission, [ 'configuration:read' ]);
        assert.deepEqual(nodeMenu.dns.permission,             [ 'dns:read' ]);
        assert.deepEqual(nodeMenu.nts.permission,             [ 'nts:read' ]);
        assert.deepEqual(nodeMenu.certificates.permission,    [ 'certificates:read' ]);
    });

    it('take the pages below the configuration that a kind puts there', () => {
        assert.deepEqual(nodeMenu.configuration([ nodeMenu.dns ]).children, [ nodeMenu.dns ]);
    });

});


describe('"/", where the kind has not said what it shows', () => {

    const opened = (): string | null => {

        let went: string | null = null;

        void firstPageOfTheMenu.render({
            root:      {} as HTMLElement,
            params:    {},
            url:       new URL('http://here/EV/'),
            navigate:  path => { went = path; }
        });

        return went;

    };

    it('opens the first page of the menu this person may open', () => {

        configureShell({
            name:  'Electric Vehicle',
            icon:  'fa-car',
            menu:  [ { path: '/traffic', label: 'Traffic', icon: 'fa-shuffle', permission: [ 'traffic:read' ] },
                     nodeMenu.configuration([ nodeMenu.dns ]),
                     nodeMenu.logs ]
        });

        auth.set(signedIn(true, 'dns:read'));

        assert.equal(opened(), '/configuration/dns');

    });

});
