/**
 * What the web interface does when the node does not answer, and how it asks
 * what every node answers.
 *
 * Run with `npm test`, which is Node's own runner reading the TypeScript as it
 * stands - no bundler, no browser, no dependency that is not already here.
 *
 * What is pinned is what was measured to be wrong: a page that waited 98
 * seconds after Save with both buttons greyed out and nothing to say, nine
 * requests left hanging by seven clicks, and a node that could not be reached
 * described to the operator in the browser's words rather than in words about
 * the node. The same tests stood in the suites of five kinds of node; the hub
 * and the meter each had a few more, which are here too.
 */

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

// The client reads config.ts, which reads <meta> tags when it is loaded. The
// page here names its node, and nothing else: the client falls back to its
// own defaults for the rest.
(globalThis as unknown as { document: unknown }).document = {
    querySelector: (selector: string) => selector === 'meta[name="node-name"]' ? { content: 'charging station' } : null
};

const { ApiError, NoAnswer, actWithin, afterAsking, answerWithin, nodeAPI, request } =
    await import('./client.ts');

const api = nodeAPI();


/** What fetch was called with, so that a test can look at the signal. */
let asked: { url: string; init: RequestInit }[] = [];

/** Put a fetch in front of the client that behaves as the test wants. */
function fetchThat(How: (Signal: AbortSignal) => Promise<Response>): void {

    asked = [];

    (globalThis as unknown as { fetch: unknown }).fetch =
        (url: string, init: RequestInit) => {
            asked.push({ url, init });
            return How(init.signal as AbortSignal);
        };

}

/** A node that takes the request and then says nothing, ever. */
const staysSilent = (Signal: AbortSignal): Promise<Response> =>
    new Promise((_, reject) => {
        Signal.addEventListener('abort', () => reject(new Error('aborted')));
    });

/** One that sends its headers and then stops halfway through the body. */
const stopsMidAnswer = (Signal: AbortSignal): Promise<Response> =>
    Promise.resolve({
        ok:      true,
        status:  200,
        text:    () => new Promise<string>((_, reject) => {
                     Signal.addEventListener('abort', () => reject(new Error('aborted')));
                 })
    } as unknown as Response);

/** One that answers at once, with whatever it was told to. */
const answers = (Status: number, Body: unknown) => (): Promise<Response> =>
    Promise.resolve({
        ok:          Status >= 200 && Status < 300,
        status:      Status,
        statusText:  '',
        text:        () => Promise.resolve(JSON.stringify(Body))
    } as unknown as Response);


describe('a node that does not answer', () => {

    it('is given up on, rather than waited for as long as the browser is willing to', async () => {

        fetchThat(staysSilent);

        const started  = Date.now();
        const problem  = await request('GET', '/status', undefined, 60).then(
                                   () => null,
                                   (error: unknown) => error
                               );

        assert.ok(problem instanceof NoAnswer,
                  `a silent node produced ${problem} rather than a NoAnswer`);
        assert.equal((problem as InstanceType<typeof NoAnswer>).reason, 'ran out of time');
        assert.ok(Date.now() - started < 2_000,
                  'the deadline did not fire');

    });

    it('is given up on even when it is silent halfway through the body', async () => {

        // A node that sends its headers and then stops hangs exactly as
        // thoroughly as one that never starts, and a deadline that covers only
        // the connection would not notice.
        fetchThat(stopsMidAnswer);

        const problem = await request('GET', '/status', undefined, 60).
                                  then(() => null, (error: unknown) => error);

        assert.ok(problem instanceof NoAnswer);
        assert.equal((problem as InstanceType<typeof NoAnswer>).reason, 'ran out of time',
                     'the body was not covered by the deadline');

    });

    it('is described in words about the node, in its own name, not the browser\'s', async () => {

        // What the browser says here is "Failed to fetch", which names neither
        // the node nor anything to do about it.
        fetchThat(() => Promise.reject(new TypeError('Failed to fetch')));

        const problem = await request('GET', '/status').then(() => null, (error: unknown) => error);

        assert.ok(problem instanceof NoAnswer);
        assert.equal((problem as InstanceType<typeof NoAnswer>).reason, 'could not be reached');
        assert.ok(!(problem as Error).message.includes('fetch'),
                  `the operator was shown: ${(problem as Error).message}`);
        assert.match((problem as Error).message, /^The charging station could not be reached\./,
                     'not the name the page gave the node');

    });

});


describe('what somebody is told when it runs out', () => {

    it('does not claim a write was not carried out, because nobody knows that', async () => {

        // The page stopped waiting; the node may well have written the file
        // and been slow to say so. Telling somebody it did not work is how a
        // thing gets done twice.
        fetchThat(staysSilent);

        const problem = await request('PUT', '/configuration/nts', {}, 60).
                                  then(() => null, (error: unknown) => error as Error);

        assert.match(problem!.message, /may still have carried this out/);
        assert.match(problem!.message, /reload/i);

    });

    it('does not claim it for a change to a certificate either, which is a PATCH', async () => {

        fetchThat(staysSilent);

        const problem = await request('PATCH', '/certificates/0123456789abcdef', { active: false }, 60).
                                  then(() => null, (error: unknown) => error as Error);

        assert.ok(problem instanceof NoAnswer);
        assert.match(problem!.message, /may still have carried this out/);

    });

    it('does say so for a read, which changed nothing', async () => {

        fetchThat(staysSilent);

        const problem = await request('GET', '/configuration/nts', undefined, 60).
                                  then(() => null, (error: unknown) => error as Error);

        assert.doesNotMatch(problem!.message, /carried this out/);
        assert.match(problem!.message, /did not answer within/);

    });

    it('counts the seconds it actually waited', async () => {

        fetchThat(staysSilent);

        const problem = await request('GET', '/status', undefined, 1_500).
                                  then(() => null, (error: unknown) => error as Error);

        assert.match(problem!.message, /within 2 seconds/);

    });

});


describe('a node that does answer', () => {

    it('is not given up on afterwards', async () => {

        // The timer has to be cleared, or a page left open long enough would
        // abort a connection the browser is quietly holding for the next
        // request. The signal says whether it was.
        fetchThat(answers(200, { version: '0.1.0' }));

        const answer = await request<{ version: string }>('GET', '/status', undefined, 50);

        assert.equal(answer.version, '0.1.0');

        await new Promise(resolve => setTimeout(resolve, 150));

        assert.equal(asked[0]!.init.signal!.aborted, false,
                     'the request was aborted after it had already been answered');

    });

    it('and says no is still an ApiError, with the node\'s own sentence', async () => {

        fetchThat(answers(400, { error: "'nts.minServers' must be at least 1." }));

        const problem = await request('PUT', '/configuration/nts', {}).
                                  then(() => null, (error: unknown) => error);

        assert.ok(problem instanceof ApiError, 'a refusal was turned into something else');
        assert.ok(!(problem instanceof NoAnswer));
        assert.match((problem as Error).message, /minServers/);

    });

    it('and says no with a message rather than an error is read as well, with what came with it', async () => {

        // A registration with a peer that did not go through answers 502 with
        // "ok", "message" and the peers as they now stand - the peers page
        // shows the message and the list, not the status line.
        const body = { ok: false, message: "'DE-GEF_CPO' answered the versions request with 401.", partners: [] };

        fetchThat(answers(502, body));

        const problem = await request('POST', '/ocpi/partners/2.3.0/DE-GEF_CPO/register', {}).
                                  then(() => null, (error: unknown) => error);

        assert.ok(problem instanceof ApiError);
        assert.equal((problem as Error).message, body.message);
        assert.deepEqual((problem as InstanceType<typeof ApiError>).body, body);

    });

    it('reads the node\'s "error" before a "message", and a "description" last', async () => {

        fetchThat(answers(409, { description: 'Hermod said this.', message: 'A kind said this.', error: 'The node said this.' }));
        const all = await request('DELETE', '/certificates/0123456789abcdef').then(() => null, (error: unknown) => error as Error);

        fetchThat(answers(409, { description: 'Hermod said this.', message: 'A kind said this.' }));
        const two = await request('DELETE', '/certificates/0123456789abcdef').then(() => null, (error: unknown) => error as Error);

        fetchThat(answers(401, { description: 'Hermod said this.' }));
        const one = await request('GET', '/auth/me').then(() => null, (error: unknown) => error as Error);

        fetchThat(answers(500, { detail: 'nothing to read' }));
        const none = await request('GET', '/status').then(() => null, (error: unknown) => error as Error);

        assert.equal(all!.message,  'The node said this.');
        assert.equal(two!.message,  'A kind said this.');
        assert.equal(one!.message,  'Hermod said this.');
        assert.equal(none!.message, '500 ', 'no sentence at all, and the status line in its place');

    });

    it('tells a session that is gone from one that is not allowed', async () => {

        fetchThat(answers(403, { error: 'This needs the dnsdesk or systemadmin role.' }));
        const forbidden = await request('PUT', '/configuration/dns', {}).then(() => null, (error: unknown) => error);

        fetchThat(answers(401, { error: 'Nobody is signed in.' }));
        const gone      = await request('PUT', '/configuration/dns', {}).then(() => null, (error: unknown) => error);

        assert.ok(forbidden instanceof ApiError && gone instanceof ApiError);
        assert.equal((forbidden as InstanceType<typeof ApiError>).isForbidden,    true);
        assert.equal((forbidden as InstanceType<typeof ApiError>).isUnauthorized, false, 'signing in again would change nothing');
        assert.equal((gone      as InstanceType<typeof ApiError>).isUnauthorized, true);
        assert.equal((gone      as InstanceType<typeof ApiError>).isForbidden,    false);

    });

});


describe('how long the page is willing to wait', () => {

    it('allows far more than a node has ever needed', () => {

        // Every read and write of the local controller's own configuration
        // measured between 1 and 7 milliseconds. The deadline is here to
        // notice silence and not slowness, so it may be generous by orders of
        // magnitude.
        assert.ok(answerWithin >= 10_000);
        assert.ok(actWithin > answerWithin, 'a write is not given longer than a read');

    });

    it('waits out the node\'s own patience when it has to ask somebody else', () => {

        // Measured on a WWCP node: a name server that never answers, at three
        // seconds and asked again once, took 6.2 seconds - twice three, and a
        // pause in between. A page that gave up at four would be reporting
        // its own impatience as the node's silence.
        assert.ok(afterAsking([6]) > 6_200);

        // And one that is asked nothing waits the ordinary time.
        assert.equal(afterAsking([]), answerWithin);

    });

    it('grows with each step taken one after another', () => {

        // A time server's test is two of them: the key exchange, then the
        // authenticated request, each given the client's timeout.
        assert.ok(afterAsking([10, 10]) > afterAsking([10]));
        assert.equal(afterAsking([10, 10]) - afterAsking([10]), 10_000);

    });

});


describe('signing in', () => {

    // The sign-in is the one call that does not go to the node's own API.
    // Hermod's HTTPExt API is the only place that can check a password, so the
    // frontend posts there and asks "me" afterwards for what that account may
    // do - and a test is the only thing that notices if it ever posts the
    // password to the wrong place.

    it('posts the password to the HTTPExt API and nowhere else', async () => {

        fetchThat(() => Promise.resolve(
            new Response(JSON.stringify({ username: 'root', roles: [], permissions: [] }),
                         { status: 200, headers: { 'Content-Type': 'application/json' } })
        ));

        await api.auth.login('root', 'hunter2');

        const signIn = asked[0];

        assert.ok(signIn.url.endsWith('/ext/login'),
                  `the password went to ${signIn.url}`);

        assert.equal(signIn.init.method, 'POST');
        assert.equal((signIn.init.headers as Record<string, string>)['Content-Type'],
                     'application/x-www-form-urlencoded');

        // "login", not "username": the field is named by the HTTPExt API.
        assert.equal(signIn.init.body, 'login=root&password=hunter2');

        // The password is never repeated to the second request.
        assert.ok(!asked.slice(1).some(call => String(call.init.body ?? '').includes('hunter2')),
                  'the password was sent more than once');

    });

    it('answers with what the account may do, not with what the sign-in said', async () => {

        let call = 0;

        fetchThat(() => {
            call++;
            return Promise.resolve(
                call === 1
                    // What the HTTPExt API answers: its own shape, no roles.
                    ? new Response(JSON.stringify({ '@context': '', description: 'signed in' }),
                                   { status: 201, headers: { 'Content-Type': 'application/json' } })
                    : new Response(JSON.stringify({ username: 'root', roles: ['cpo'], permissions: ['dns:run'] }),
                                   { status: 200, headers: { 'Content-Type': 'application/json' } })
            );
        });

        const me = await api.auth.login('root', 'hunter2');

        assert.deepEqual(me.roles,       ['cpo']);
        assert.deepEqual(me.permissions, ['dns:run']);
        assert.ok(asked[1].url.endsWith('/auth/me'));

    });

    it('says what the HTTPExt API said when it refuses', async () => {

        fetchThat(() => Promise.resolve(
            new Response(JSON.stringify({ '@context': '', description: 'You do not have access to any organization!' }),
                         { status: 401, headers: { 'Content-Type': 'application/json' } })
        ));

        // Its refusals carry "description" where the node's carry "error";
        // somebody who just typed a password has to be told which it was.
        await assert.rejects(
            () => api.auth.login('root', 'hunter2'),
            (problem: unknown) => problem instanceof ApiError &&
                                  problem.message === 'You do not have access to any organization!'
        );

    });

    it('has a deadline and words about the node of its own, because it does not go through the request everything else takes', async () => {

        // The first thing anybody does with a node that has gone quiet is try
        // to sign in again, and that is no place for "Failed to fetch" or for
        // a request that hangs as long as the browser lets it.
        fetchThat(() => Promise.reject(new TypeError('Failed to fetch')));

        await assert.rejects(
            () => api.auth.login('root', 'hunter2'),
            (problem: unknown) => problem instanceof NoAnswer &&
                                  problem.reason === 'could not be reached' &&
                                  /charging station/.test(problem.message)
        );

        assert.ok(asked[0]!.init.signal instanceof AbortSignal,
                  'the sign-in was sent without a deadline');

    });

});


describe('the routes every node has', () => {

    it('asks who is signed in at auth/me', async () => {

        fetchThat(answers(200, { username: 'root', roles: [ 'systemadmin' ], permissions: [ 'dns:read' ] }));

        const me = await api.auth.me();

        assert.equal(asked[0]!.url,          '/api/v1/auth/me');
        assert.equal(asked[0]!.init.method,  'GET');
        assert.equal(me.username,            'root');

    });

    it('asks the clock at /v1/clock, where every node has it now', async () => {

        // At /v1/configuration/time it was one kind's alone; the node's JSON
        // API answers that path with its 404 now, which the NTS page would
        // have shown as a clock nobody can read.
        fetchThat(answers(200, { now: '2026-09-28T00:00:00Z', legal: false }));

        await api.clock();

        assert.equal(asked[0]!.url, '/api/v1/clock');

    });

    it('asks every time server with "Sync now", and is answered with the whole NTS configuration', async () => {

        // The node answers a synchronisation with the whole NTS configuration,
        // because the exchange moves the cookies and the key material the page
        // is showing - and the result of it inside.
        fetchThat(answers(200, { enabled: true, timeSources: [], result: { ok: true, at: '2026-09-28T00:00:00Z', server: 'ptbtime1.ptb.de' } }));

        const answer = await api.nts.sync(1);

        assert.equal(asked[0]!.url,          '/api/v1/configuration/nts/sync');
        assert.equal(asked[0]!.init.method,  'POST');
        assert.equal(answer.result?.server,  'ptbtime1.ptb.de');

    });

    it('streams the log from where every node streams it', () => {
        assert.equal(api.eventsURL, '/api/v1/events');
    });

});
