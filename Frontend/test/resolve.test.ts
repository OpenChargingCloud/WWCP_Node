/*
 * The hook of resolve.ts, asked the way a kind of node's tests ask it: a
 * shared file under "@node/...", and a relative import without its
 * extension. Both have to arrive at the very module a direct import gets -
 * a second copy of a module would be a second copy of its state.
 */

import { strict as assert } from 'node:assert';
import { describe, it }      from 'node:test';

import * as direct from '../src/html.ts';


describe('resolve', () => {

    it('finds "@node/..." where webpack finds it', async () => {

        const viaAlias = await import('@node/html');

        assert.equal(viaAlias.must, direct.must, 'another module, or none');

    });

    it('finds a relative import that leaves its extension out', async () => {

        const viaRelative = await import('../src/html');

        assert.equal(viaRelative.must, direct.must);

    });

});
