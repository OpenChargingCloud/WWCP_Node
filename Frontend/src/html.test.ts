/*
 * must(), what is left of html.ts: an element, or an error that names the
 * one that is not there.
 */

import { strict as assert } from 'node:assert';
import { describe, it }      from 'node:test';

import { must } from './html.ts';


describe('must', () => {

    it('finds an element or says which one it did not find', () => {

        const found = { id: 'page' };
        const root  = { querySelector: (selector: string) => selector === '#page' ? found : null };

        assert.equal(must(root as unknown as ParentNode, '#page'), found);
        assert.throws(() => must(root as unknown as ParentNode, '#nothing'), /'#nothing' not found/);

    });

});
