/**
 * What every page every node shares is held to, asked of its source - by the
 * rules of test/pages.ts, which every kind of node asks of its own pages too.
 *
 * Run with `npm test`.
 */

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';

import { everyPageIn }       from '../../test/pages.ts';


everyPageIn(new URL('./', import.meta.url), {

    withForms:    [ 'certificates.ts', 'dns.ts', 'nts.ts', 'ssh.ts' ],

    dialogForms:  [ 'pins-form', 'query-form', 'server-form', 'usages-form' ],

    notDrafts:    { 'login.ts': 'signing in is the way in, and nothing typed there is the node\'s to lose' }

});


describe('a switch in a stacked form', () => {

    it('stands beside its words, as the stylesheet sets it', () => {

        // .form-stack label is the stronger rule and stacks a label's children
        // in a column: with .switch's align-items: center, the box stood
        // centred above its words - on the meter's DNS page, and on the local
        // controller's CSMS and station-group forms. A page may put a switch
        // into a stacked form because this rule is there.
        const forms = readFileSync(new URL('../styles/_forms.scss', import.meta.url), 'utf-8');

        assert.match(forms, /\.form-stack label\.switch\s*\{[^}]*flex-direction:\s*row/);

    });

});
