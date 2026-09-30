/**
 * What the browser's copy of the log does when the stream stops, and what it
 * hands on of the stream besides the log.
 *
 * Run with `npm test`, which is Node's own runner reading the TypeScript as it
 * stands - no bundler, no browser, no dependency that is not already here.
 *
 * What is pinned is what was measured to be wrong: the local controller was
 * stopped and started again, which takes every session with it, and the
 * browser's retry then got a 401 - which it treats as final. The page went on
 * saying "reconnecting ..." over a frozen list, with the node up and running
 * and the operator signed out without being told. And on the energy meter, an
 * account that lost the right to read the log while signed in had its stream
 * opened again every three seconds, and refused every time.
 */

import { strict as assert }       from 'node:assert';
import { describe, it, mock }     from 'node:test';

// The client reads config.ts, which reads <meta> tags when it is loaded.
(globalThis as unknown as { document: unknown }).document = { querySelector: () => null };


/** A stream that does what a test tells it to, and remembers being closed. */
class Stream {

    static readonly CONNECTING = 0;
    static readonly OPEN       = 1;
    static readonly CLOSED     = 2;

    static latest: Stream | null = null;

    readyState = Stream.CONNECTING;
    closed     = false;

    private readonly listeners = new Map<string, ((event: unknown) => void)[]>();

    readonly url: string;

    constructor(url: string) {
        this.url      = url;
        Stream.latest = this;
    }

    addEventListener(name: string, listener: (event: unknown) => void): void {
        this.listeners.set(name, [...(this.listeners.get(name) ?? []), listener]);
    }

    close(): void {
        this.closed     = true;
        this.readyState = Stream.CLOSED;
    }

    /** What the browser does to it, from the outside. */
    fire(name: string, event: unknown = {}): void {
        for (const listener of this.listeners.get(name) ?? [])
            listener(event);
    }

}

(globalThis as unknown as { EventSource: unknown }).EventSource = Stream;

const { LogStore } = await import('./store.ts');


/** What the node was asked, and what it answered. */
let askedFor: string[] = [];

const nodeAnswers = (How: 'yes' | 'signed out' | 'not the log' | 'not there') => {

    askedFor = [];

    (globalThis as unknown as { fetch: unknown }).fetch = (url: string) => {

        askedFor.push(url);

        if (How === 'not there')
            return Promise.reject(new TypeError('Failed to fetch'));

        const status = How === 'yes' ? 200 : How === 'signed out' ? 401 : 403;

        return Promise.resolve({
            ok:          status === 200,
            status,
            statusText:  '',
            text:        () => Promise.resolve(status === 200
                                                   ? JSON.stringify({ lastId: 0, capacity: 2000, tags: [], entries: [] })
                                                   : JSON.stringify({ error: 'No.' }))
        } as unknown as Response);

    };

};

/** A store with its stream open and one that has just given up on it. */
const aStreamThatGaveUp = () => {

    const store = new LogStore();

    store.start();

    const stream = Stream.latest!;

    stream.readyState = Stream.CLOSED;
    stream.fire('error');

    return { store, stream };

};

/** Let the promises of an answer run. */
const settle = async () => {
    for (let turn = 0; turn < 8; turn++)
        await Promise.resolve();
};


describe('a stream that stops', () => {

    it('is left to the browser while the browser is still trying', async () => {

        mock.timers.enable({ apis: ['setTimeout'] });

        try
        {
            nodeAnswers('yes');

            const store = new LogStore();
            store.start();

            // CONNECTING is the browser saying it will try again by itself,
            // and the page saying "reconnecting ..." is then the truth.
            Stream.latest!.readyState = Stream.CONNECTING;
            Stream.latest!.fire('error');

            mock.timers.tick(60_000);
            await Promise.resolve();

            assert.deepEqual(askedFor, [], 'the node was asked about a stream nobody had given up on');

            store.stop();
        }
        finally
        {
            mock.timers.reset();
        }

    });

    it('makes the node be asked why, once the browser has given up - for one entry of the log, as the stream is asked', async () => {

        mock.timers.enable({ apis: ['setTimeout'] });

        try
        {
            nodeAnswers('yes');

            const { store } = aStreamThatGaveUp();

            assert.deepEqual(askedFor, [], 'the node was asked before anything had settled');

            mock.timers.tick(5_000);
            await Promise.resolve();
            await Promise.resolve();

            assert.equal(askedFor.length, 1, 'nobody asked the node anything');
            assert.match(askedFor[0]!, /\/api\/v1\/logs\?limit=1$/);

            store.stop();
        }
        finally
        {
            mock.timers.reset();
        }

    });

    it('is opened again where the node is there and the session still stands', async () => {

        mock.timers.enable({ apis: ['setTimeout'] });

        try
        {
            nodeAnswers('yes');

            const { store, stream } = aStreamThatGaveUp();
            const first = stream;

            mock.timers.tick(5_000);
            await settle();

            assert.equal(first.closed, true, 'the stream that had stopped was left open');
            assert.notEqual(Stream.latest, first, 'no new stream was opened');

            store.stop();
        }
        finally
        {
            mock.timers.reset();
        }

    });

    it('is not opened again when the answer is that nobody is signed in', async () => {

        mock.timers.enable({ apis: ['setTimeout'] });

        try
        {
            nodeAnswers('signed out');

            const { store, stream } = aStreamThatGaveUp();

            mock.timers.tick(5_000);
            await settle();

            // Signing out is what happens next, through the same handler every
            // other request uses; opening another stream would only get the
            // same refusal - and it is not this store's to say anything about
            // a role.
            assert.equal(Stream.latest,       stream, 'a new stream was opened at a node that had refused');
            assert.equal(store.streamRefused, false,  'a signed-out page was told about a role rather than sent to the sign-in');

            // And it stops there rather than asking the same refused question
            // every ten seconds for as long as the page is open.
            const askedOnce = askedFor.length;

            mock.timers.tick(60_000);
            await settle();

            assert.equal(askedFor.length, askedOnce,
                         'it went on asking a node that had already said no');

            store.stop();
        }
        finally
        {
            mock.timers.reset();
        }

    });

    it('is not opened again for somebody still signed in who may no longer read the log', async () => {

        mock.timers.enable({ apis: ['setTimeout'] });

        try
        {
            nodeAnswers('not the log');

            const { store, stream } = aStreamThatGaveUp();

            const said: string[] = [];
            store.onChange(event => { if (event.type === 'error') said.push(event.text); });

            mock.timers.tick(5_000);
            await settle();

            // A new stream would only be refused again - by a node that writes
            // a warning into its log for every refusal.
            assert.equal(stream.closed,       true,   'the stream that had been refused was left open');
            assert.equal(Stream.latest,       stream, 'a new stream was opened for somebody who may not read the log');
            assert.equal(store.streamRefused, true,   'the page would go on saying "reconnecting ..."');
            assert.equal(said.length,         1,      'the page was not told why');
            assert.match(said[0]!,            /may no longer read it/);

            // And it is not asked about again either.
            const askedOnce = askedFor.length;

            mock.timers.tick(60_000);
            await settle();

            assert.equal(askedFor.length, askedOnce, 'it went on asking about a stream that had been refused');

            store.stop();

            assert.equal(store.streamRefused, false, 'a sign-out left the refusal behind for the next account');
        }
        finally
        {
            mock.timers.reset();
        }

    });

    it('opens again with a clean slate after the page has been left and come back to', async () => {

        mock.timers.enable({ apis: ['setTimeout'] });

        try
        {
            nodeAnswers('not the log');

            const { store } = aStreamThatGaveUp();

            mock.timers.tick(5_000);
            await settle();

            assert.equal(store.streamRefused, true);

            // The page goes, and the role is given back before it is opened
            // again: what the last visit was refused says nothing about this one.
            store.stop();
            store.start();

            assert.equal(store.streamRefused, false, 'the refusal of the last visit was held against this one');

            store.stop();
        }
        finally
        {
            mock.timers.reset();
        }

    });

    it('opens again with a clean slate for whoever signs in next on the same page', async () => {

        mock.timers.enable({ apis: ['setTimeout'] });

        try
        {
            nodeAnswers('not the log');

            const { store, stream } = aStreamThatGaveUp();

            mock.timers.tick(5_000);
            await settle();

            assert.equal(store.streamRefused, true);

            // A refusal is a 403, not a 401: the account is still signed in,
            // and whoever signs in over it is handed the stream by a start()
            // with no stop() before it.
            store.start();

            assert.equal(store.streamRefused, false, 'the next account was refused for what the last one may not do');
            assert.notEqual(Stream.latest, stream, 'no stream was opened for the next account');

            store.stop();
        }
        finally
        {
            mock.timers.reset();
        }

    });

    it('keeps trying where the node could not answer either', async () => {

        mock.timers.enable({ apis: ['setTimeout'] });

        try
        {
            nodeAnswers('not there');

            const { store } = aStreamThatGaveUp();

            mock.timers.tick(5_000);
            await settle();

            assert.equal(askedFor.length, 1);

            // A node that is being restarted is away for longer than one
            // attempt, and a page left open in front of it is expected to come
            // back on its own.
            mock.timers.tick(15_000);
            await settle();

            assert.ok(askedFor.length > 1, 'it gave up after one try and went on saying otherwise');

            store.stop();
        }
        finally
        {
            mock.timers.reset();
        }

    });

    it('and stops being asked about once the page is done with it', async () => {

        mock.timers.enable({ apis: ['setTimeout'] });

        try
        {
            nodeAnswers('not there');

            const { store } = aStreamThatGaveUp();

            store.stop();

            mock.timers.tick(60_000);
            await settle();

            assert.deepEqual(askedFor, [], 'a store that had been stopped went on asking');
        }
        finally
        {
            mock.timers.reset();
        }

    });

});


describe('a page the browser keeps for the way back', () => {

    it('lets go of its stream while it waits there, and keeps what it knows', () => {

        nodeAnswers('yes');

        const store = new LogStore();
        store.start();

        const stream = Stream.latest!;

        stream.fire('log', { data: JSON.stringify({ id: 7, timestamp: '2026-09-30T00:00:00Z', level: 'info', tags: [ 'web' ], message: 'up' }) });

        store.pause();

        assert.equal(stream.closed,           true,  'a stream held open for a page nobody sees - one of the six connections a browser gives a host');
        assert.equal(store.entries.length,    1,     'what the page knew was thrown away');
        assert.equal(store.streamConnected,   false);

        store.stop();

    });

    it('opens it again when it is shown, and a page that followed nothing opens nothing', () => {

        nodeAnswers('yes');

        const store = new LogStore();
        store.start();

        const first = Stream.latest!;

        store.pause();
        store.resume();

        assert.notEqual(Stream.latest,          first, 'shown again, the page followed nothing');
        assert.equal   (Stream.latest!.closed,  false);

        const idle    = new LogStore();
        const before  = Stream.latest;

        idle.pause();
        idle.resume();

        assert.equal(Stream.latest, before, 'a stream was opened for a page that followed none');

        // Signed out in between: what was paused is not the page's to open.
        store.pause();
        store.stop();

        const stopped = Stream.latest;

        store.resume();

        assert.equal(Stream.latest, stopped, 'a stream was opened again for somebody signed out');

    });

    it('says it is no longer live as it lets go, so that the page shown again claims nothing', async () => {

        nodeAnswers('yes');

        const store = new LogStore();
        store.start();

        Stream.latest!.fire('open');
        await settle();

        // What the page reads as it is told: told before the store knew, it
        // would draw "live" all the same (found by the hub).
        const told: string[] = [];
        store.onChange(event => told.push(`${event.type}, ${store.streamConnected ? 'live' : 'down'}`));

        store.pause();

        // Unsaid, the page came out of the cache saying "live", and went on
        // saying it where the node had gone meanwhile: a stream that never
        // opens has nothing to say (found by the meter).
        assert.deepEqual(told, [ 'stream, down' ], 'what the page was told of its stream, and could read');
        assert.equal(store.streamConnected, false);

        store.stop();

    });

});


describe('what a kind of node publishes on the stream besides the log', () => {

    const published = (Data: unknown) => ({ data: JSON.stringify(Data) });

    it('is handed to whoever asked for it, as its data reads', () => {

        const store = new LogStore();
        const heard: unknown[] = [];

        store.onEvent<{ peer: string }>('peer', data => heard.push(data));
        store.start();

        Stream.latest!.fire('peer', published({ peer: 'DE-GEF' }));

        assert.deepEqual(heard, [{ peer: 'DE-GEF' }]);

        store.stop();

    });

    it('reaches a stream that was open before anybody asked, and one opened after', () => {

        const store = new LogStore();
        const heard: string[] = [];

        store.start();
        store.onEvent<string>('peer', data => heard.push(data));

        Stream.latest!.fire('peer', published('while open'));

        // A reconnect is a new stream, and the listener has to come with it.
        store.stop();
        store.start();

        Stream.latest!.fire('peer', published('after the next start'));

        assert.deepEqual(heard, ['while open', 'after the next start']);

        store.stop();

    });

    it('stops reaching whoever stopped listening, and nobody else', () => {

        const store = new LogStore();
        const first:  string[] = [];
        const second: string[] = [];

        const stopFirst = store.onEvent<string>('peer', data => first.push(data));
        store.onEvent<string>('peer', data => second.push(data));
        store.start();

        stopFirst();
        Stream.latest!.fire('peer', published('once'));

        assert.deepEqual(first,  []);
        assert.deepEqual(second, ['once']);

        store.stop();

    });

    it('reaches every listener, although one of them failed', () => {

        const store = new LogStore();
        const heard: string[] = [];

        store.onEvent<string>('peer', () => { throw new Error('a page halfway through drawing'); });
        store.onEvent<string>('peer', data => heard.push(data));
        store.start();

        const complaining = console.error;
        console.error     = () => undefined;

        try
        {
            Stream.latest!.fire('peer', published('still here'));
        }
        finally
        {
            console.error = complaining;
        }

        assert.deepEqual(heard, ['still here']);

        store.stop();

    });

});
