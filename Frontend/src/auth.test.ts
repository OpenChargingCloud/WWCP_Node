/**
 * Who is signed in, as the pages ask it: the guard that sends somebody to the
 * sign-in and back, what they may do, and a session that is gone.
 *
 * Mounted at "/EV", as a node is where several share one HTTP server: the
 * base is read from the page once, when the modules are loaded, so the page
 * is there before they are imported. None of the eight kinds of node had a
 * test of it.
 */

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { NodeMe }       from './api/client.ts';

(globalThis as unknown as { document: unknown }).document = {
    querySelector: (selector: string) => selector === 'meta[name="base"]' ? { content: '/EV' } : null
};

const { auth }     = await import('./auth.ts');
const { request }  = await import('./api/client.ts');


/** A node that answers every request with this. */
const nodeAnswers = (Status: number, Body: unknown) => {
    (globalThis as unknown as { fetch: unknown }).fetch = () => Promise.resolve({
        ok:          Status >= 200 && Status < 300,
        status:      Status,
        statusText:  '',
        text:        () => Promise.resolve(JSON.stringify(Body)),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0))
    } as unknown as Response);
};

const somebody: NodeMe = { username: 'alice', roles: [ 'dnsdesk' ], permissions: [ 'dns:read', 'dns:edit' ] };


describe('the guard of a page', () => {

    it('sends nobody signed in to the sign-in, with the way back as a route and not as an address', () => {

        auth.set(null);

        // "/EV/logs" carried through the sign-in would come back as
        // "/EV/EV/logs": the router puts the base back on.
        assert.equal(auth.requireSignIn(new URL('http://here/EV/logs?level=warning')),
                     '/login?next=%2Flogs%3Flevel%3Dwarning');

    });

    it('lets somebody signed in through', () => {

        auth.set(somebody);

        assert.equal(auth.requireSignIn(new URL('http://here/EV/logs')), null);

        auth.set(null);

    });

});


describe('what somebody may do', () => {

    it('is what the node said they may, and nothing else', () => {

        auth.set(somebody);

        assert.equal(auth.can('dns', 'edit'),          true);
        assert.equal(auth.can('nts', 'read'),          false);
        assert.equal(auth.can('certificates', 'run'),  false);

        auth.set(null);

        assert.equal(auth.can('dns', 'read'), false, 'nobody signed in may do something');

    });

});


describe('a session', () => {

    it('that is gone is forgotten at the first 401 any request gets', async () => {

        auth.set(somebody);

        let told: unknown = 'nothing';
        const stop = auth.onChange(user => { told = user; });

        nodeAnswers(401, { error: 'Nobody is signed in.' });

        await request('GET', '/status').catch(() => undefined);

        stop();

        assert.equal(auth.user, null, 'the page went on believing somebody was signed in');
        assert.equal(told,      null, 'the guards were not told');

    });

    it('is taken from the node when the page loads', async () => {

        nodeAnswers(200, somebody);

        assert.deepEqual(await auth.refresh(), somebody);
        assert.deepEqual(auth.user,            somebody);

        nodeAnswers(401, { error: 'Nobody is signed in.' });

        assert.equal(await auth.refresh(), null);

    });

    it('is nobody\'s after a sign-in the node refused', async () => {

        auth.set(null);

        nodeAnswers(401, { description: 'The login or the password is not right.' });

        await assert.rejects(() => auth.signIn('alice', 'wrong'), /not right/);

        assert.equal(auth.user, null);

    });

});
