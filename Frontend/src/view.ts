// Drawing a page with lit-html: html`...` builds a template, render() puts it
// on the page - the first time as html.ts's render() would, every time after
// by comparing it with what is there and changing only what differs. What a
// draw does not change stays: the text somebody typed into another form, the
// field that has the focus and where its cursor is, how far a list is
// scrolled. With innerHTML every draw made all of it anew, and keepDrafts,
// which the pages had for it, put back what it could - the text, but not the
// focus, the cursor or the scroll.
//
// Three things are written differently from html.ts:
//
// - An attribute that is there or not is bound, not spliced in as text:
//   ?disabled=${!may}, ?checked=${on}, ?selected=${chosen}. What a control
//   shows rather than what its markup says is set as a property:
//   .checked=${live(on)} where the node's answer must win over a click.
// - A listener is bound in the template - @submit=${...}, @click=${...} -
//   since the elements outlive a draw: one added with addEventListener after
//   each draw would be added again with every one.
// - A draw does not empty a form any more. A form whose save went through
//   says it is done itself: form.reset().
//
// lit-html does not support an expression inside a <textarea>: what one
// starts with is bound as its .defaultValue=${...}, which it shows until
// somebody types into it.
// And a form that is drawn for one thing and then for another in its place -
// the settings of one group, then of the next - is drawn with keyed(), so
// that the second does not keep what was typed into the first.
//
// A fragment of html.ts in a template of this one is taken as the markup it
// is - it was escaped when it was made - so that what the kinds hand a shared
// page (a hint, a Reload) can stay html.ts's until they draw with this one
// too. A Configuration page's cards are drawn with this one, by cardViews.ts;
// the frame, shell.ts, stays html.ts's: it is drawn once for every page, and
// the kinds' tests load it without a document, which lit-html wants as it loads.

import { html as litHTML, render as litRender, nothing, type TemplateResult } from 'lit-html';
import { keyed }       from 'lit-html/directives/keyed.js';
import { live }        from 'lit-html/directives/live.js';
import { repeat }      from 'lit-html/directives/repeat.js';
import { unsafeHTML }  from 'lit-html/directives/unsafe-html.js';

import { HTMLFragment } from './html';

export { keyed, live, nothing, repeat, type TemplateResult };


function bridged(value: unknown): unknown {

    if (value instanceof HTMLFragment)
        return unsafeHTML(value.value);

    if (Array.isArray(value))
        return value.map(bridged);

    return value;

}

/** A template; a fragment of html.ts in it is taken as markup, everything else as lit-html takes it. */
export function html(strings: TemplateStringsArray, ...values: unknown[]): TemplateResult {
    return litHTML(strings, ...values.map(bridged));
}


/**
 * Where the draws into an element begin to compare from: a comment at its
 * end, which lit-html keeps what it drew in front of and remembers it by.
 */
const anchors = new WeakMap<HTMLElement, Comment>();

/**
 * Draw a template into an element. The first draw into an element empties it
 * of whatever else put something there - the loading box of html.ts's
 * render(), say - since lit-html would draw next to it, not over it. So does
 * a draw into an element whose content somebody else replaced since: the
 * router's root, which the next page fills with html.ts's render() - drawn
 * again into it, lit-html would compare with what is no longer there and show
 * nothing.
 */
export function render(target: HTMLElement, template: TemplateResult | typeof nothing): void {

    let anchor = anchors.get(target);

    if (anchor === undefined || anchor.parentNode !== target) {
        anchor = document.createComment('');
        target.replaceChildren(anchor);
        anchors.set(target, anchor);
    }

    litRender(template, target, { renderBefore: anchor });

}
