/**
 * The one page every kind of node serves for all of its addresses: a template
 * each kind's webpack names itself into, and the node fills in as it serves
 * it. Eight kinds kept a copy each, and the copies had begun to differ in
 * their comments.
 *
 * Run with `npm test`. There is no html-webpack-plugin here, so the template
 * is written as that plugin writes it by default - lodash's <%= %> and <% %>,
 * which is all it uses.
 */

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';


const template = readFileSync(new URL('./index.html', import.meta.url), 'utf-8');

/** Every {{...}} the node replaces as it serves the page. */
const filledInByTheNode = [ ...readFileSync(new URL('../../WWCP_Node/WWCPNode.cs', import.meta.url), 'utf-8').
                                matchAll(/Replace\("\{\{(\w+)\}\}"/g) ].map(match => match[1]);

/** The template as html-webpack-plugin writes it for a kind that hands it these options. */
function written(Options: Record<string, string>): string {

    const pieces  = [ 'let out = "";' ];
    let   at      = 0;

    for (const match of template.matchAll(/<%(=?)([\s\S]*?)%>/g)) {
        pieces.push(`out += ${JSON.stringify(template.slice(at, match.index))};`);
        pieces.push(match[1] === '=' ? `out += String((${match[2]}) ?? '');` : match[2]);
        at = match.index + match[0].length;
    }

    pieces.push(`out += ${JSON.stringify(template.slice(at))};`, 'return out;');

    return new Function('htmlWebpackPlugin', pieces.join('\n'))({ options: Options }) as string;

}


describe('the page every kind of node serves', () => {

    it('holds a place for everything the node fills in as it serves it, and for nothing else', () => {

        assert.ok(filledInByTheNode.length >= 5, 'what the node fills in was not found where it is filled in');

        assert.deepEqual([ ...new Set([ ...template.matchAll(/\{\{(\w+)\}\}/g) ].map(match => match[1])) ].sort(),
                         [ ...new Set(filledInByTheNode) ].sort());

    });

    it('is named by the kind: its title, what it is, and the version of its frontend', () => {

        const page = written({ title:        'Local Controller',
                               description:  'The web interface of an OpenChargingCloud local controller',
                               version:      '0.1.0' });

        assert.match(page, /<title>Local Controller<\/title>/);
        assert.match(page, /<meta name="description"\s+content="The web interface of an OpenChargingCloud local controller" \/>/);
        assert.match(page, /<meta name="frontend-version"\s+content="0\.1\.0" \/>/);

    });

    it('is not written for a kind that does not say what it is', () => {

        // Left out, the page would say nothing about itself, and nobody would
        // notice; a build that stops says which option it wants.
        assert.throws(() => written({ title: 'Local Controller', version: '0.1.0' }), /description/);

    });

});
