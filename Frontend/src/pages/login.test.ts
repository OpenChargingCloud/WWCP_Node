/**
 * What the sign-in says, in the node's own name unless the kind of node says
 * its own.
 */

import '../../test/dom.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

document.head.innerHTML = '<meta name="node-name" content="gateway">';

const { signInHint, signInLine } = await import('./login.ts');


describe('the sign-in', () => {

    it('says what signing in is for, in the node\'s own name', () => {
        assert.equal(signInLine(), 'Sign in to configure this gateway and read its log.');
    });

    it('says where the first password comes from, in the node\'s own name', () => {
        assert.equal(signInHint(), 'The gateway makes up one account at its first start and shows its password once, on the console.');
    });

    it('says what a kind of node says instead, where it says its own', () => {
        assert.equal(signInLine({ line: 'Sign in to look after this EMSP.' }),  'Sign in to look after this EMSP.');
        assert.equal(signInHint({ hint: 'Ask whoever set it up.' }),           'Ask whoever set it up.');
    });

});
