import type { NodeMe } from './api/client';
import { auth } from './auth';
import { fromURL } from './basePath';
import { must } from './html';
import { logs, type LogStore } from './logs/store';
import { certificatesPage, identitiesPage, serverIdentitiesPage, type CertificatesOptions } from './pages/certificates';
import { sshPage } from './pages/ssh';
import { dnsPage } from './pages/dns';
import { loginPage, type SignInWords } from './pages/login';
import { logsPage, type LogsWords } from './pages/logs';
import { notFoundPage } from './pages/notFound';
import { ntsPage } from './pages/nts';
import { Router, type Guard, type Page, type Route } from './router';
import { configureShell, visibleMenu, type MenuEntry, type ShellSetup } from './shell';
import { html, render } from './view';

/**
 * What a kind of node says about its web interface, once, as it starts: what
 * it is called, what its menu has, and the pages that are its own. Everything
 * every node has - the sign-in, the log, the name servers, the time servers,
 * the certificate store, the frame, following the log while somebody is
 * signed in - comes with it.
 */
export interface NodeFrontend extends ShellSetup {

    /**
     * The kind's own pages, by path, behind the sign-in. A path every node
     * has a page for as well - "/" among them - is the kind's.
     */
    pages:         Record<string, Page>;

    /** Pages anybody may open, signed in or not: an e-mobility provider's sign-up. */
    publicPages?:  Record<string, Page>;

    /** Routes of the kind's own, asked before all others: old bookmarks sent on, and such. */
    routes?:       Route[];

    signIn?:       SignInWords;
    logs?:         LogsWords;
    certificates?: CertificatesOptions;

}


/**
 * What every node has in its menu, for a kind of node to put where it wants
 * them. Each is shown to whoever may open its page: the configuration to
 * whoever may read it, the log to whoever the node says it is for.
 */
export const nodeMenu: {
    configuration:  (Children?: MenuEntry[]) => MenuEntry;
    dns:            MenuEntry;
    nts:            MenuEntry;
    certificates:        MenuEntry;
    identities:          MenuEntry;
    serverIdentities:    MenuEntry;
    ssh:                 MenuEntry;
    logs:                MenuEntry;
} = {

    configuration: (Children: MenuEntry[] = []): MenuEntry => ({
        path:        '/configuration',
        label:       'Configuration',
        icon:        'fa-sliders',
        permission:  [ 'configuration:read' ],
        children:    Children
    }),

    dns: {
        path:        '/configuration/dns',
        label:       'DNS client',
        icon:        'fa-magnifying-glass-location',
        permission:  [ 'dns:read' ]
    },

    nts: {
        path:        '/configuration/nts',
        label:       'NTS client',
        icon:        'fa-clock',
        permission:  [ 'nts:read' ]
    },

    certificates: {
        path:        '/configuration/certificates',
        label:       'Certificates',
        icon:        'fa-certificate',
        permission:  [ 'certificates:read' ]
    },

    // Who the node is as a client, with its keys - for a kind of node whose
    // store keeps one of them: a TLS identity, a vehicle's credentials.
    identities: {
        path:        '/configuration/identities',
        label:       'Identities',
        icon:        'fa-id-card',
        permission:  [ 'certificates:read' ]
    },

    // Who its servers are, with their keys - for a kind of node with
    // listeners of its own, a meter's Modbus/TLS port and web interface.
    serverIdentities: {
        path:        '/configuration/server-identities',
        label:       'Server identities',
        icon:        'fa-server',
        permission:  [ 'certificates:read' ]
    },

    // The SSH server the command line is served over: every node has one.
    ssh: {
        path:        '/configuration/ssh',
        label:       'SSH server',
        icon:        'fa-terminal',
        permission:  [ 'ssh:read' ]
    },

    logs: {
        path:        '/logs',
        label:       'Logs',
        icon:        'fa-list-ul',
        permission:  mayReadTheLog
    }

};


/** Whether the log is for whoever is signed in, as the node says it. */
export function mayReadTheLog(): boolean {
    return auth.user?.mayReadTheLog === true;
}

/** Signed in, and the log is for them - or where they should be instead. */
const toReadTheLog: Guard = url =>
    auth.requireSignIn(url) ?? (mayReadTheLog() ? null : '/');

/**
 * A page that moved: whoever comes to its old address - a bookmark - is sent
 * on to the new one, which replaces it in the history.
 */
export function movedTo(Path: string, Title: string): Page {
    return {
        title: Title,
        render({ navigate }) {
            navigate(Path, true);
        }
    };
}

/**
 * "/", where a kind of node has not said what it shows: the first page of the
 * menu this person may open, or a line saying there is none.
 */
export const firstPageOfTheMenu: Page = {

    title: 'Home',

    render({ root, navigate }) {

        const first = visibleMenu()[0];

        if (first !== undefined && first.path !== '/') {
            navigate(first.path, true);
            return;
        }

        render(root, html`
            <section class="not-found">
                <p>Nothing here is open to the account signed in.</p>
            </section>
        `);

    }

};


/**
 * Every route of a kind of node, in the order the router asks them: the
 * kind's own routes, then its pages - which win over every node's pages at
 * the same path - then its public pages, and every node's pages last.
 */
export function routesOf(Frontend: NodeFrontend): Route[] {

    return [

        ...(Frontend.routes ?? []),

        ...Object.entries(Frontend.pages).
                  map(([ path, page ]) => ({ path, page, guard: auth.requireSignIn })),

        ...Object.entries(Frontend.publicPages ?? {}).
                  map(([ path, page ]) => ({ path, page })),

        // "/" is a route of its own rather than a redirect: the sign-in
        // remembers where somebody was going, and for the first visit that is
        // "/" - which would otherwise be a page that exists on the way in and
        // not on the way back.
        { path: '/',                   page: firstPageOfTheMenu,         guard: auth.requireSignIn },
        { path: '/configuration/dns',  page: dnsPage,                    guard: auth.requireSignIn },
        { path: '/configuration/nts',  page: ntsPage,                    guard: auth.requireSignIn },
        { path: '/configuration/certificates',         page: certificatesPage(Frontend.certificates),        guard: auth.requireSignIn },
        { path: '/configuration/identities',           page: identitiesPage(Frontend.certificates),          guard: auth.requireSignIn },
        { path: '/configuration/server-identities',    page: serverIdentitiesPage(Frontend.certificates),    guard: auth.requireSignIn },
        // Its address for the few hours it was called "Server certificates".
        { path: '/configuration/server-certificates',  page: movedTo('/configuration/server-identities', 'Server identities'), guard: auth.requireSignIn },
        { path: '/configuration/ssh',                  page: sshPage,                                        guard: auth.requireSignIn },
        { path: '/logs',               page: logsPage(Frontend.logs),    guard: toReadTheLog       },
        { path: '/login',              page: loginPage(Frontend.signIn)                            }

    ];

}


/**
 * What a change of who is signed in does to the log and to the page.
 *
 * Signed in: follow the log from now on, whichever page is open - so that
 * opening the Logs page shows what happened while somebody was reading the
 * configuration, and not an empty list. Not for somebody the node says the log
 * is not for: their stream would only be refused, and they would be told they
 * may no longer read what they never could.
 *
 * Signed out - by the button, or because the session expired and a request
 * came back with 401: close the stream, forget the log, and show the sign-in -
 * unless they are on a page anybody may open.
 */
export function afterASignInChange(User:  NodeMe<string> | null,
                                   Route: string,
                                   Open:  ReadonlySet<string>): { followTheLog: boolean; toTheSignIn: boolean } {

    return {
        followTheLog:  User?.mayReadTheLog === true,
        toTheSignIn:   User === null && !Open.has(Route)
    };

}


/**
 * A stream closed while the page waits in the browser's back/forward cache,
 * and opened again when the page is shown - see LogStore.pause(). A page
 * shown for the first time rather than out of the cache is left alone: its
 * stream is the sign-in's to open.
 *
 * startNode() does this for the log. A kind of node with a stream of its own
 * does it for that one too, as the hub does for its traffic: every stream a
 * cached page holds is one of the six connections a browser gives a host
 * (found by the hub).
 */
export function followAcrossTheCache(Window:  EventTarget,
                                     Stream:  Pick<LogStore, 'pause' | 'resume'>): void {

    Window.addEventListener('pagehide', () => Stream.pause());

    Window.addEventListener('pageshow', event => {
        if ((event as PageTransitionEvent).persisted)
            Stream.resume();
    });

}


/**
 * Start the web interface of a kind of node: the frame, the routes, following
 * the log while somebody who may read it is signed in, and the sign-in for
 * whoever is not.
 */
export function startNode(Frontend: NodeFrontend): Router {

    configureShell(Frontend);

    const root = document.getElementById('app');

    if (root === null)
        throw new Error("The '#app' element is missing!");

    render(root, html`<div id="page" class="page"></div>`);

    const router = new Router({
        routes:       routesOf(Frontend),
        outlet:       must<HTMLElement>(root, '#page'),
        notFound:     notFoundPage,
        titleSuffix:  ` · ${Frontend.name}`
    });

    const open = new Set([ '/login', ...Object.keys(Frontend.publicPages ?? {}) ]);

    auth.onChange(user => {

        const next = afterASignInChange(user, fromURL(location.pathname), open);

        if (next.followTheLog)
            logs.start();
        else
            logs.stop();

        if (next.toTheSignIn)
            router.navigate(auth.requireSignIn(new URL(location.href)) ?? '/login', true);

    });

    followAcrossTheCache(window, logs);

    // Find out who is signed in before the first page renders, so that a
    // reload on a deep URL does not flash the sign-in page on its way back to
    // where it was.
    void (async () => {
        await auth.refresh();
        router.start();
    })();

    return router;

}
