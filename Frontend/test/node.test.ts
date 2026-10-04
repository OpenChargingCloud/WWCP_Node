/*
 * The stand-in every kind's page tests draw against, asked of what it does:
 * how it answers and what it notes, who it signs in, and that the page opened
 * before is left as the router leaves it.
 */

import { asked, change, field, leave, open, refused, said, settled, standIn, submit, type, until, answer } from './node.ts';

import { strict as assert } from 'node:assert';
import { describe, it }      from 'node:test';

const { auth }          = await import('../src/auth.ts');
const { brand }         = await import('../src/shell.ts');
const { html, render }  = await import('../src/view.ts');

import type { Page } from '../src/router.ts';


/** What fetch answered, as a page reads it. */
async function fetched(path: string, init?: RequestInit): Promise<{ status: number; body: unknown }> {
    const response = await fetch(`/api/v1${path}`, init);
    return { status: response.status, body: await response.json() };
}

/** A page that draws a form, and says when it is left: at once, or only once it has drawn. */
function aPage(left: string[], name = 'page', later = false): Page {
    return {
        title: name,
        render({ root }) {
            render(root, html`<form id="form"><input name="host" /><select name="mode"><option>a</option><option>b</option></select></form>`);
            const cleanup = () => { left.push(name); };
            return later ? Promise.resolve(cleanup) : cleanup;
        }
    };
}

const drawn = (root: HTMLElement) => root.querySelector('#form') !== null;


describe('the stand-in', () => {

    it('answers with a value as JSON, a Response as it is, and what it does not know as 404, in the node\'s words', async () => {

        answer(asked => asked.path === '/status'    ? { running: true }
                      : asked.path === '/teapot'    ? refused(418, 'I am a teapot')
                      :                               undefined);

        assert.deepEqual(await fetched('/status'),  { status: 200, body: { running: true } });
        assert.deepEqual(await fetched('/teapot'),  { status: 418, body: { error: 'I am a teapot' } });
        assert.deepEqual(await fetched('/nothing'), { status: 404, body: { error: 'nothing at GET /nothing' } });

    });

    it('waits for an answer that takes its time', async () => {

        answer(async () => { await new Promise(resolve => setTimeout(resolve, 20)); return { late: true }; });

        assert.deepEqual(await fetched('/slow'), { status: 200, body: { late: true } });

    });

    it('notes what it was asked: the method, the path below /api/v1, the query and the body', async () => {

        answer(() => ({}));
        asked.length = 0;

        await fetched('/logs?limit=200&tag=ocpp');
        await fetched('/configuration/dns', { method: 'PUT', body: JSON.stringify({ enabled: false }) });
        await fetched('/certificates/1', { method: 'DELETE', body: null });

        assert.deepEqual(asked.map(one => [ one.method, one.path, one.query.toString(), one.body ]),
                         [ [ 'GET',    '/logs',               'limit=200&tag=ocpp', undefined ],
                           [ 'PUT',    '/configuration/dns',  '',                   { enabled: false } ],
                           [ 'DELETE', '/certificates/1',     '',                   undefined ] ]);

    });

    it('refuses with more than why, where the node says more', async () => {

        answer(() => refused(409, 'taken', { by: 'DE-GEF' }));

        assert.deepEqual(await fetched('/peers'), { status: 409, body: { error: 'taken', by: 'DE-GEF' } });

    });

    it('notes what alert and confirm were asked, and confirm says yes', () => {

        said.length = 0;

        window.alert('saved');

        assert.equal(window.confirm('Remove it?'), true);
        assert.deepEqual(said, [ 'saved', 'Remove it?' ]);

    });

});


describe('waiting', () => {

    it('ends as soon as it holds', async () => {

        let holds = false;
        setTimeout(() => { holds = true; }, 20);

        await until(() => holds, 'never held');

        assert.equal(holds, true);

    });

    it('fails with what was said once it has waited for as long as it was told', async () => {

        const began = Date.now();

        await assert.rejects(until(() => false, 'the page did not draw', 50), /the page did not draw/);

        assert.ok(Date.now() - began >= 50, `gave up after ${Date.now() - began} ms`);

    });

    it('lets what was asked be answered, where there is nothing to wait for by name', async () => {

        answer(() => ({ ok: true }));

        let answered = false;
        void fetched('/status').then(() => { answered = true; });

        await settled();

        assert.equal(answered, true);

    });

});


describe('a page opened', () => {

    it('is drawn in the frame of the node stood in for, for alice with the permissions given and the user it says', async () => {

        standIn({ name: 'Electric Vehicle', icon: 'fa-car-side', user: { roles: [ 'driver' ], mayReadTheLog: true } });

        await open(aPage([]), '/vehicle', [ 'vehicle:edit' ], () => undefined, drawn);

        assert.deepEqual(brand(), { name: 'Electric Vehicle', icon: 'fa-car-side' });
        assert.deepEqual(auth.user, { username: 'alice', roles: [ 'driver' ], mayReadTheLog: true, permissions: [ 'vehicle:edit' ] });

        standIn({ name: 'Test node', icon: 'fa-gear' });

        await open(aPage([]), '/vehicle', [ 'vehicle:edit' ], () => undefined, drawn);

        assert.deepEqual(auth.user, { username: 'alice', roles: [ 'admin' ], mayReadTheLog: false, permissions: [ 'vehicle:edit' ] });

    });

    it('is drawn for nobody signed in, for null', async () => {

        await open(aPage([]), '/signup', null, () => undefined, drawn);

        assert.equal(auth.user, null);

    });

    it('fails, saying where, if it never draws', async () => {

        await assert.rejects(open(aPage([]), '/never', [], () => undefined, () => false), /\/never did not draw/);

    });

    it('leaves the page opened before, and one that says how only once it has drawn as well', async () => {

        const left = [] as string[];

        await open(aPage(left, 'first'),          '/first',  [], () => undefined, drawn);
        await open(aPage(left, 'second', true),   '/second', [], () => undefined, drawn);
        await open(aPage(left, 'third'),          '/third',  [], () => undefined, drawn);

        await settled();

        assert.deepEqual(left, [ 'first', 'second' ]);

        leave();

        assert.deepEqual(left, [ 'first', 'second', 'third' ]);

        leave();

        assert.deepEqual(left, [ 'first', 'second', 'third' ], 'a page was left twice');

    });

    it('starts with nothing asked and nothing said, and answers as it was told for this page', async () => {

        answer(() => ({ before: true }));
        await fetched('/before');
        window.alert('before');

        await open(aPage([]), '/page', [], () => ({ now: true }), drawn);

        assert.deepEqual(asked, []);
        assert.deepEqual(said, []);
        assert.deepEqual(await fetched('/now'), { status: 200, body: { now: true } });

    });

});


describe('a form, by hand', () => {

    it('has its fields found by name, and says which form lacks one', async () => {

        const root = await open(aPage([]), '/form', [], () => undefined, drawn);

        assert.ok(field(root, '#form', 'host') === root.querySelector('#form [name="host"]'));
        assert.throws(() => field(root, '#form', 'port'), /#form has no field port/);

    });

    it('is sent as a browser sends it, and says which form is not there', async () => {

        const root = await open(aPage([]), '/form', [], () => undefined, drawn);

        const sent = [] as { cancelable: boolean; bubbles: boolean }[];
        root.addEventListener('submit', event => sent.push({ cancelable: event.cancelable, bubbles: event.bubbles }));

        submit(root, '#form');

        assert.deepEqual(sent, [ { cancelable: true, bubbles: true } ]);
        assert.throws(() => submit(root, '#other'), /there is no #other/);

    });

    it('is changed with the change said, a box checked and a chooser set', async () => {

        const root   = await open(aPage([]), '/form', [], () => undefined, drawn);
        const mode   = field<HTMLSelectElement>(root, '#form', 'mode');
        const box    = document.createElement('input');
        box.type     = 'checkbox';
        root.querySelector('#form')!.append(box);

        const changes = [] as string[];
        root.addEventListener('change', event => changes.push((event.target as HTMLElement).tagName));

        change(mode, 'b');
        change(box, true);

        assert.equal(mode.value, 'b');
        assert.equal(box.checked, true);
        assert.deepEqual(changes, [ 'SELECT', 'INPUT' ]);

    });

    it('is typed into with the field focused and the input said, the cursor put where asked and left where it is if not', async () => {

        const root  = await open(aPage([]), '/form', [], () => undefined, drawn);
        const host  = field(root, '#form', 'host');

        const inputs = [] as string[];
        root.addEventListener('input', () => inputs.push(host.value));

        type(host, 'ptbtime1.ptb.de', 3);

        assert.ok(document.activeElement === host, 'the field typed into has no focus');
        assert.deepEqual(inputs, [ 'ptbtime1.ptb.de' ]);
        assert.deepEqual([ host.selectionStart, host.selectionEnd ], [ 3, 3 ]);

        type(host, 'ptbtime2.ptb.de');

        assert.deepEqual([ host.selectionStart, host.selectionEnd ], [ 15, 15 ], 'the cursor was moved where nobody asked');

    });

});


describe('the document', () => {

    it('makes a choice with new Option, as a browser does', () => {

        const option = new Option('Port 4443', '4443');

        assert.equal(option.tagName, 'OPTION');
        assert.equal(option.text,  'Port 4443');
        assert.equal(option.value, '4443');
        assert.equal(new Option('udp').value, 'udp');

    });

});
