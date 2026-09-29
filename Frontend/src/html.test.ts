/*
 * html`...`: what every page of every kind of node is written in, and what
 * stands between a value the node sent and markup the browser runs. None of
 * the eight kinds had a test of it; it was the one file all eight had alike.
 */

import { strict as assert } from 'node:assert';
import { describe, it }      from 'node:test';

import { escapeHTML, html, HTMLFragment, must, raw, render } from './html.ts';


describe('html', () => {

    it('escapes every value it is handed', () => {

        const name = `<img src=x onerror="alert('x')">&`;

        assert.equal(html`<b>${name}</b>`.value,
                     '<b>&lt;img src=x onerror=&quot;alert(&#39;x&#39;)&quot;&gt;&amp;</b>');

    });

    it('takes a fragment as it is, and only a fragment', () => {

        const inner = html`<i>${'a & b'}</i>`;

        assert.equal(html`<p>${inner}</p>`.value,   '<p><i>a &amp; b</i></p>');
        assert.equal(html`<p>${raw('<br>')}</p>`.value, '<p><br></p>');
        assert.equal(html`<p>${'<br>'}</p>`.value,      '<p>&lt;br&gt;</p>', 'text that looks like a fragment is still text');

    });

    it('joins a list, and writes nothing for null, undefined and false', () => {

        const items = ['<a>', html`<li>b</li>`];

        assert.equal(html`<ul>${items}</ul>`.value, '<ul>&lt;a&gt;<li>b</li></ul>');
        assert.equal(html`${null}${undefined}${false}`.value, '');
        assert.equal(html`${0}${true}`.value, '0true', 'zero and true are values, not nothing');

    });

    it('is a string where one is asked for', () => {

        assert.ok(html`x` instanceof HTMLFragment);
        assert.equal(`${html`<b>${'<'}</b>`}`, '<b>&lt;</b>');
        assert.equal(escapeHTML(`"'`), '&quot;&#39;');

    });

    it('renders into an element, replacing what was there', () => {

        const target = { innerHTML: '<p>old</p>' };

        render(target as unknown as HTMLElement, html`<p>${'new & shiny'}</p>`);

        assert.equal(target.innerHTML, '<p>new &amp; shiny</p>');

    });

    it('finds an element or says which one it did not find', () => {

        const found = { id: 'page' };
        const root  = { querySelector: (selector: string) => selector === '#page' ? found : null };

        assert.equal(must(root as unknown as ParentNode, '#page'), found);
        assert.throws(() => must(root as unknown as ParentNode, '#nothing'), /'#nothing' not found/);

    });

});
