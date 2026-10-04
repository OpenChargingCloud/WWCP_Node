// Drawing a page with lit-html: html`...` builds a template, render() puts it
// on the page - the first time as innerHTML would, every time after by
// comparing it with what is there and changing only what differs. What a
// draw does not change stays: the text somebody typed into another form, the
// field that has the focus and where its cursor is, how far a list is
// scrolled. With innerHTML every draw made all of it anew, and keepDrafts,
// which the pages had for it, put back what it could - the text, but not the
// focus, the cursor or the scroll.
//
// Three things are written differently from html.ts's html`...`, which every
// page was written in before, a string drawn with innerHTML:
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
// unsafeHTML() is for markup a page made itself and cannot say as a template
// - the SVG a QR code library writes - and never for what a node or somebody
// typing says: that goes in as text, as everything in a template does.

import { html, render as litRender, nothing, type TemplateResult } from 'lit-html';
import { keyed }       from 'lit-html/directives/keyed.js';
import { live }        from 'lit-html/directives/live.js';
import { repeat }      from 'lit-html/directives/repeat.js';
import { unsafeHTML }  from 'lit-html/directives/unsafe-html.js';

export { html, keyed, live, nothing, repeat, unsafeHTML, type TemplateResult };


/**
 * Where the draws into an element begin to compare from: a comment at its
 * end, which lit-html keeps what it drew in front of and remembers it by.
 */
const anchors = new WeakMap<HTMLElement, Comment>();

/**
 * Draw a template into an element. The first draw into an element empties it
 * of whatever else put something there - a loading box, say - since lit-html
 * would draw next to it, not over it. So does a draw into an element whose
 * content somebody else replaced since: the router's root, which the router
 * empties for the next page - drawn again into it, lit-html would compare with
 * what is no longer there and show nothing.
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
