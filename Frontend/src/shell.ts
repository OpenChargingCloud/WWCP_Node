import { auth } from './auth';
import { toURL } from './basePath';
import { config } from './config';
import { html, must, render, type HTMLFragment } from './html';
import type { NodeMe } from './api/client';

/**
 * The frame every signed-in page sits in: the menu on the left, a heading and
 * whatever the page puts under it on the right.
 *
 * The menu is here and not in a page because each page renders itself into an
 * emptied outlet - so the frame is drawn again with every navigation, and the
 * entry that is current is simply the one that says so. What a kind of node
 * has pages for, and what it is called at the top of the menu, is the kind's
 * to say, once, when it starts - see start.ts.
 */

export interface MenuEntry {
    path:         string;
    label:        string;
    /** A Font Awesome class, e.g. "fa-sliders". */
    icon:         string;
    /**
     * Who is shown it: whoever holds any one of these permissions, written the
     * way the node writes them - "dns:read" - or whoever this says yes for.
     * Everybody who is signed in when it is left out. A courtesy like every
     * greyed-out button: the node checks every request again when it arrives.
     */
    permission?:  readonly string[] | (() => boolean);
    /** The pages below this one, shown indented while one of them is open. */
    children?:    MenuEntry[];
}

/** What a kind of node is called at the top of its menu and on its sign-in. */
export interface Brand {
    /** "Local Controller", "Charging Station" - as a heading says it. */
    name:  string;
    /** A Font Awesome class, e.g. "fa-sitemap". */
    icon:  string;
}

export interface ShellSetup extends Brand {
    menu:  MenuEntry[];
    /**
     * Who is signed in, in the foot of the menu: one line, and what a pointer
     * resting on it says. The roles they hold, unless a kind has a better
     * name for them.
     */
    who?:  (me: NodeMe<string>) => { line: string; title: string };
}

export interface ShellOptions {
    /** The menu entry to mark as the current one. */
    active:     string;
    /** The heading of the page. */
    title:      string;
    /** One line under the heading, or nothing. */
    subtitle?:  string;
    /** Buttons and such, shown at the right of the heading. */
    actions?:   HTMLFragment;
}


let setup: ShellSetup = { name: 'Node', icon: 'fa-sitemap', menu: [] };

/** Say what this kind of node is called and what it has pages for. Once, as it starts. */
export function configureShell(Setup: ShellSetup): void {
    setup = Setup;
}

/** What this kind of node is called at the top of its menu. */
export function brand(): Brand {
    return { name: setup.name, icon: setup.icon };
}


/** Whether the person signed in may open this entry's page at all. */
export function mayOpen(Entry: MenuEntry): boolean {

    const needs = Entry.permission;

    if (needs === undefined)
        return true;

    if (typeof needs === 'function')
        return needs();

    // Any one of them: a page somebody may either change or run something on
    // is theirs by either. Asked of the list itself rather than through
    // auth.can(), which is typed with every node's resources and not with
    // what a kind of node adds to them.
    const held = (auth.user?.permissions ?? []) as readonly string[];

    return needs.some(permission => held.includes(permission));

}

/**
 * The entries this person may open, and of each the pages below it they may
 * open. Where an entry is not theirs but some of what is below it is, those
 * stand in its place - somebody who may look at the name servers and at
 * nothing else of the configuration still finds the name servers.
 *
 * A page below an entry that says nothing of its own about who may open it
 * is its entry's: it was never shown without it. Taken as everybody's, it
 * stood in the place of an entry that was not theirs - the roaming hub's
 * OCPI for an account that may read the time servers and nothing else, the
 * e-mobility provider's locations and tariffs for a driver.
 */
export function visibleMenu(Menu: readonly MenuEntry[] = setup.menu): MenuEntry[] {

    return Menu.flatMap(entry => {

        const children = entry.children?.filter(child => mayOpen(child.permission === undefined ? { ...child, permission: entry.permission } : child));

        if (!mayOpen(entry))
            return children ?? [];

        return [ children === undefined ? entry : { ...entry, children } ];

    });

}


/**
 * Draw the frame into the given root and hand back the element the page is to
 * render itself into.
 */
export function shell(root:     HTMLElement,
                      options:  ShellOptions): HTMLElement {

    const me   = auth.user;
    const who  = me === null ? null : whoIsSignedIn(me);

    render(root, html`
        <div class="shell">

            <nav class="sidebar" aria-label="Sections">

                <div class="brand">
                    <i class="fa-solid ${setup.icon}"></i>
                    <span>${setup.name}</span>
                </div>

                ${menuHTML(visibleMenu(), options.active)}

                <div class="sidebar-foot">
                    <div class="who" title="${who?.title ?? ''}">
                        <i class="fa-solid fa-user"></i>
                        <span>${me?.username ?? '-'}</span>
                    </div>
                    ${who?.line
                          ? html`<div class="roles small muted">${who.line}</div>`
                          : ''}
                    <button type="button" id="sign-out" class="btn small">Sign out</button>
                    <div class="versions small muted">
                        ${versions()}
                    </div>
                </div>

            </nav>

            <main class="content">

                <header class="page-head">
                    <div>
                        <h1>${options.title}</h1>
                        ${options.subtitle ? html`<p class="muted">${options.subtitle}</p>` : ''}
                    </div>
                    <div class="page-actions">${options.actions ?? ''}</div>
                </header>

                <div id="content-body" class="content-body"></div>

            </main>

        </div>
    `);

    must<HTMLButtonElement>(root, '#sign-out').
        addEventListener('click', () => void auth.signOut());

    return must<HTMLElement>(root, '#content-body');

}

/**
 * Who is signed in, as the foot of the menu says it: the roles they hold -
 * unless the kind of node has a better name for them.
 */
export function whoIsSignedIn(Me: NodeMe<string>): { line: string; title: string } {

    if (setup.who !== undefined)
        return setup.who(Me);

    const roles = Me.roles.join(', ');

    return {
        line:   roles,
        title:  roles.length > 0 ? `Signed in as ${roles}` : 'Signed in, in no role'
    };

}

/** Which node and which web interface this is: in the foot of the menu, and under the sign-in. */
export function versions(): HTMLFragment {
    return html`${config.nodeName} ${config.serverVersion} &middot; web ${config.frontendVersion}`;
}


/** The menu, with the entry that is the page being shown marked. */
export function menuHTML(Entries:  readonly MenuEntry[],
                         Active:   string): HTMLFragment {

    return html`
        <ul class="menu">
            ${Entries.map(entry => html`
                <li>
                    ${link(entry, Active)}
                    ${entry.children?.length && isOpen(entry, Active)
                          ? html`
                              <ul class="submenu">
                                  ${entry.children.map(child => html`<li>${link(child, Active)}</li>`)}
                              </ul>
                          `
                          : ''}
                </li>
            `)}
        </ul>
    `;

}

/**
 * One entry of the menu, marked when it is the page being shown. Its address
 * carries the base the web interface is mounted below, so that a page opened
 * in a new tab - which the router never sees - still finds its way.
 */
function link(entry: MenuEntry, active: string): HTMLFragment {

    const current = entry.path === active;

    return html`
        <a href="${toURL(entry.path)}"
           class="${current ? 'active' : ''}"
           ${current ? html`aria-current="page"` : ''}>
            <i class="fa-solid ${entry.icon}"></i>
            <span>${entry.label}</span>
        </a>
    `;

}

/**
 * Whether an entry's children are shown: while the entry itself is open, or
 * while one of them is. The menu unfolds where somebody is and stays folded
 * everywhere else, so a node with a dozen pages still fits on the left.
 */
function isOpen(entry: MenuEntry, active: string): boolean {
    return entry.path === active ||
           (entry.children ?? []).some(child => child.path === active);
}
