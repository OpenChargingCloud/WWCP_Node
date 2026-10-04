/*
 * view.ts: what a page drawn by comparing keeps that a page drawn by innerHTML
 * threw away, and the bridge that lets a fragment of html.ts stand in it.
 */

import '../test/dom.ts';

import { strict as assert } from 'node:assert';
import { describe, it }      from 'node:test';

import { html as stringHTML, render as stringRender } from './html.ts';
import { html, keyed, live, nothing, render, repeat } from './view.ts';


function page(): HTMLElement {
    const element = document.createElement('div');
    document.body.append(element);
    return element;
}


describe('view', () => {

    it('keeps what was typed into a form the draw does not change, and where the focus is', () => {

        const root  = page();
        const draw  = (count: number) => render(root, html`
            <form id="a"><input name="name" /></form>
            <p>${count} of them</p>
            <form id="b"><input name="other" /></form>`);

        draw(1);

        const name = root.querySelector<HTMLInputElement>('#a input')!;
        name.value = 'typed, not saved';
        name.focus();

        draw(2);

        assert.equal(root.querySelector('p')!.textContent, '2 of them');
        assert.ok(root.querySelector('#a input') === name, 'the same element, not a new one');
        assert.equal(name.value,                     'typed, not saved');
        assert.ok(document.activeElement === name, 'the focus went');

    });

    it('sets a property bound with live() to the answer, even where the hand changed it', () => {

        const root = page();
        const draw = (on: boolean) => render(root, html`<input type="checkbox" .checked=${live(on)} />`);

        draw(false);
        const box = root.querySelector<HTMLInputElement>('input')!;
        box.checked = true;

        draw(false);

        assert.equal(box.checked, false, 'the node said no, so the box says no');

    });

    it('binds a listener once, however often it draws', () => {

        const root   = page();
        let   clicks = 0;
        const draw   = () => render(root, html`<button @click=${() => clicks++}>go</button>`);

        draw(); draw(); draw();
        root.querySelector('button')!.click();

        assert.equal(clicks, 1);

    });

    it('says an attribute that is there or not as one, not as text', () => {

        const root = page();
        const draw = (may: boolean) => render(root, html`<button ?disabled=${!may}>go</button>`);

        draw(false);
        assert.equal(root.querySelector('button')!.disabled, true);

        draw(true);
        assert.equal(root.querySelector('button')!.disabled, false);

    });

    it('keeps a row with its key, where a row before it goes', () => {

        const root = page();
        const draw = (ids: string[]) => render(root, html`
            <ul>${repeat(ids, id => id, id => html`<li><input data-id=${id} /></li>`)}</ul>`);

        draw(['one', 'two']);
        const two = root.querySelector<HTMLInputElement>('input[data-id="two"]')!;
        two.value = 'typed into two';

        draw(['two']);

        assert.equal(root.querySelectorAll('input').length, 1);
        assert.ok(root.querySelector('input') === two, 'the row of two was made anew');
        assert.equal(two.value, 'typed into two');

    });

    it('draws a form for another key anew, and keeps it for the same one', () => {

        const root = page();
        const draw = (group: string) => render(root, html`
            ${keyed(group, html`<form id="group-form"><input name="name" value=${group} /></form>`)}`);

        draw('a');
        const forA = root.querySelector<HTMLInputElement>('input')!;
        forA.value = 'typed for a';

        draw('a');
        assert.ok(root.querySelector('input') === forA, 'the form for the same key was made anew');
        assert.equal(forA.value, 'typed for a');

        draw('b');
        assert.ok(root.querySelector('input') !== forA, 'the form for b is the one typed into for a');
        assert.equal(root.querySelector<HTMLInputElement>('input')!.value, 'b');

    });

    it('fills a textarea through its defaultValue, which what is typed into it outlives', () => {

        const root = page();
        const draw = (said: string) => render(root, html`<textarea .defaultValue=${said}></textarea>`);

        draw('one');
        const area = root.querySelector('textarea')!;
        assert.equal(area.value, 'one');

        draw('two');
        assert.equal(area.value, 'two', 'untouched, it shows what it is drawn with');

        area.value = 'typed';
        draw('three');
        assert.equal(area.value, 'typed');
        assert.equal(area.defaultValue, 'three');

    });

    it('escapes a value, and takes a fragment of html.ts as the markup it is', () => {

        const root = page();

        render(root, html`<p>${'<b>not bold</b>'}</p><div>${stringHTML`<b>${'a & b'}</b>`}</div><ul>${[stringHTML`<li>x</li>`, 'y']}</ul>`);

        assert.equal(root.querySelector('p')!.textContent,       '<b>not bold</b>');
        assert.ok(root.querySelector('p b') === null, 'a value was taken as markup');
        assert.equal(root.querySelector('div b')!.textContent,   'a & b');
        assert.equal(root.querySelector('ul li')!.textContent,   'x');
        assert.equal(root.querySelector('ul')!.textContent,      'xy');

    });

    it('draws over what html.ts put into the element before, not next to it', () => {

        const root = page();

        stringRender(root, stringHTML`<div class="loading">Loading ...</div>`);
        render(root, html`<p>here</p>`);

        assert.ok(root.querySelector('.loading') === null, 'what html.ts drew is still there');
        assert.equal(root.children.length, 1);

        render(root, nothing);
        assert.equal(root.children.length, 0);

    });

    it('draws again into an element whose content html.ts replaced since - the router root, the next page in it', () => {

        const root = page();
        const sign = (who: string) => html`<section class="login"><p>${who}</p></section>`;

        render(root, sign('first'));
        stringRender(root, stringHTML`<main>another page</main>`);
        render(root, sign('second'));

        assert.ok(root.querySelector('main') === null, 'the other page is still there');
        assert.equal(root.querySelector('.login p')?.textContent, 'second');
        assert.equal(root.querySelectorAll('.login').length, 1);

    });

});
