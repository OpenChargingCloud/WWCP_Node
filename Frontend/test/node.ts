/*
 * A node that is a stand-in for fetch, and a document of happy-dom to draw a
 * page into: what the page tests of every kind of node share.
 *
 * Each kind had a copy of its own, eight of them, the same but for its name
 * and icon and what one of them had learned that the others had not: an
 * answer that takes its time (the CSMS, the e-mobility provider, the hub), the
 * query an address was asked with (the e-mobility provider), a refusal that
 * says more than why (the hub), the page drawn before left as the router
 * leaves it (the charging station, the meter), somebody not signed in (the
 * e-mobility provider), typing into a field (the e-mobility provider, the
 * meter). Each of them is here, for all of them.
 *
 * A kind says who it is, and adds what only it has, in a file of its own,
 * which its page tests import first - lit-html looks for the document as it
 * is loaded, and the pages load it:
 *
 *   // test/controller.ts
 *   import { standIn } from '@node/../test/node.ts';
 *   export * from '@node/../test/node.ts';
 *
 *   standIn({ name: 'Local Controller', icon: 'fa-sitemap' });
 *
 *   // src/pages/csms.test.ts
 *   import { open, ... } from '../../test/controller.ts';
 *   const { csmsPage } = await import('./csms.ts');
 */

import './dom.ts';

import { strict as assert } from 'node:assert';

import type { Cleanup, Page } from '../src/router.ts';

const { auth }            = await import('../src/auth.ts');
const { configureShell }  = await import('../src/shell.ts');


/** What the stand-in was asked: GET /configuration/csms, with what came along. */
export interface Asked {
    method:  string;
    /** Below /api/v1, where every node's API is. */
    path:    string;
    query:   URLSearchParams;
    body:    unknown;
}

/**
 * How the stand-in answers: with a value, sent as JSON with 200; with a
 * Response as it is; with undefined, as nothing it knows - 404. Or with a
 * promise of one of them, for an answer that takes its time.
 */
export type Answers = (asked: Asked) => unknown;

/** Everything asked since the page was opened, in order. */
export const asked: Asked[] = [];

let answers: Answers = () => undefined;

globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {

    const url    = new URL(String(input), 'http://127.0.0.1/');
    const method = init?.method ?? 'GET';
    const body   = init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body)) as unknown;
    const one    = { method, path: url.pathname.replace(/^\/api\/v1/, ''), query: url.searchParams, body };

    asked.push(one);

    const answer = await answers(one);

    if (answer instanceof Response)
        return answer;

    if (answer === undefined)
        return refused(404, `nothing at ${method} ${one.path}`);

    return new Response(JSON.stringify(answer), { status: 200, headers: { 'Content-Type': 'application/json' } });

}) as typeof fetch;

/** How the stand-in answers from now on, on a page already open. */
export function answer(how: Answers): void {
    answers = how;
}

/** An answer that refuses, with what the node says why - and whatever else it says along with it. */
export function refused(status: number, error: string, more: object = {}): Response {
    return new Response(JSON.stringify({ error, ...more }), { status, headers: { 'Content-Type': 'application/json' } });
}

/** What window.alert and window.confirm were asked; confirm says yes. */
export const said: string[] = [];

window.alert   = (text?: unknown) => { said.push(String(text)); };
window.confirm = (text?: unknown) => { said.push(String(text)); return true; };


const wait = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Wait until it holds, and fail with what was said if it does not. Counted in
 * turns of 5 ms rather than by the clock: on a busy machine a turn takes
 * longer, and so does the wait.
 */
export async function until(what: () => boolean, failure: string, within_ms = 1_000): Promise<void> {
    for (let i = 0; i < within_ms / 5 && !what(); i++)
        await wait(5);
    assert.ok(what(), failure);
}

/** Let what was asked be answered and drawn, where there is nothing to wait for by name. */
export async function settled(): Promise<void> {
    for (let i = 0; i < 10; i++)
        await wait(2);
}


/** Who the stand-in is: the name and icon of the frame, and what its user has beyond a name, roles and permissions. */
export interface StandIn {
    name:   string;
    icon:   string;
    /** Laid over { username: 'alice', roles: [ 'admin' ], mayReadTheLog: false }. */
    user?:  Record<string, unknown>;
}

let standingIn: StandIn = { name: 'Test node', icon: 'fa-gear' };

/** Say who the stand-in is, once, before the first page is opened. */
export function standIn(Node: StandIn): void {
    standingIn = Node;
}

let leaving: ReturnType<Page['render']> = undefined;

/**
 * Leave the page opened last, as the router does on the way to the next one:
 * what it started - a timer, a stream, a listener of a store - stops. open()
 * leaves the page before by itself.
 */
export function leave(): void {

    const left = leaving;

    leaving = undefined;

    if (left instanceof Promise)
        void left.then((cleanup: Cleanup | void) => cleanup?.());
    else
        left?.();

}

/**
 * A page drawn into a document of its own, for somebody with these
 * permissions - or for nobody signed in, for null - against a stand-in that
 * answers so.
 */
export async function open(page:         Page,
                           path:         string,
                           permissions:  string[] | null,
                           how:          Answers,
                           drawn:        (root: HTMLElement) => boolean): Promise<HTMLElement> {

    leave();

    asked.length = 0;
    said.length  = 0;
    answers      = how;

    configureShell({ name: standingIn.name, icon: standingIn.icon, menu: [] });

    auth.set(permissions === null
                 ? null
                 : { username: 'alice', roles: [ 'admin' ], mayReadTheLog: false, ...standingIn.user, permissions } as never);

    const root = document.createElement('div');
    document.body.replaceChildren(root);

    leaving = page.render({ root, url: new URL(`http://127.0.0.1${path}`), params: {}, navigate: () => undefined } as never);

    await until(() => drawn(root), `${path} did not draw`);

    return root;

}


/** The field of a form, by the form's selector and the field's name. */
export function field<T extends HTMLElement = HTMLInputElement>(root: HTMLElement, form: string, name: string): T {
    const found = root.querySelector<T>(`${form} [name="${name}"]`);
    assert.ok(found, `${form} has no field ${name}`);
    return found;
}

/** Sent as the browser sends a form once it is valid: happy-dom's checks are not a browser's. */
export function submit(root: HTMLElement, form: string): void {
    const found = root.querySelector<HTMLFormElement>(form);
    assert.ok(found, `there is no ${form}`);
    found.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));
}

/** A box or chooser changed by hand: its value set, and the change said. */
export function change(element: HTMLInputElement | HTMLSelectElement, to: boolean | string): void {
    if (typeof to === 'boolean')
        (element as HTMLInputElement).checked = to;
    else
        element.value = to;
    element.dispatchEvent(new Event('change', { bubbles: true }));
}

/** Typed into by hand: the field focused, its text set, the input said - and the cursor put where it is asked to be. */
export function type(element: HTMLInputElement | HTMLTextAreaElement, text: string, cursor?: number): void {
    element.focus();
    element.value = text;
    element.dispatchEvent(new Event('input', { bubbles: true }));
    if (cursor !== undefined)
        element.setSelectionRange(cursor, cursor);
}
