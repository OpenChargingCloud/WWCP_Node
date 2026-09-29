/*
 * Where the web interface is mounted, and the routes below it: added on the
 * way into the address bar, taken off on the way out - on a segment boundary,
 * and not merely by the first characters. None of the eight kinds of node had
 * a test of it.
 *
 * Mounted at "/EV/", with the slash a server may well write after it: the
 * base is read from the page once, when basePath.ts is loaded, so the page is
 * there before it is imported.
 */

import { strict as assert } from 'node:assert';
import { describe, it }      from 'node:test';

(globalThis as unknown as { document: unknown }).document = {
    querySelector: (selector: string) => selector === 'meta[name="base"]' ? { content: '/EV/' } : null
};

const { basePath, fromURL, toURL } = await import('./basePath.ts');


describe('a web interface mounted at /EV', () => {

    it('is at /EV, without the slash after it', () => {
        assert.equal(basePath, '/EV');
    });

    it('puts a route below it on the way into the address bar', () => {
        assert.equal(toURL('/logs'), '/EV/logs');
        assert.equal(toURL('logs'),  '/EV/logs');
    });

    it('leaves a path alone that is below it already', () => {
        // A link's own absolute pathname is handed in as it stands.
        assert.equal(toURL('/EV/logs'), '/EV/logs');
        assert.equal(toURL('/EV'),      '/EV');
    });

    it('takes itself off on the way out, and its own root is "/"', () => {
        assert.equal(fromURL('/EV/logs'), '/logs');
        assert.equal(fromURL('/EV'),      '/');
        assert.equal(fromURL('/EV/'),     '/');
    });

    it('does not swallow a route that only begins with the same letters', () => {
        // A station mounted at /EV would otherwise have taken its own /EVSEs.
        assert.equal(toURL('/EVSEs'),   '/EV/EVSEs');
        assert.equal(fromURL('/EVSEs'), '/EVSEs');
    });

});
