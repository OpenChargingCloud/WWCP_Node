/*
 * cardViews.ts draws what cards.ts draws: the same markup, field for field,
 * for the same sections - so that a page that moves from card() to cardView()
 * shows what it showed. Compared as the browser has them, in a document of
 * happy-dom, without lit-html's comments and the blanks between tags.
 */

import '../test/dom.ts';

import { strict as assert } from 'node:assert';
import { describe, it }      from 'node:test';

import { breakable, card, librariesCard }               from './cards.ts';
import { breakableView, cardView, librariesCardView }    from './cardViews.ts';
import { html as stringHTML, render as stringRender }   from './html.ts';
import { html, render }                                  from './view.ts';


/** What an element holds, as markup to compare: no comments, no blanks between tags or at the ends of text. */
function markupOf(element: HTMLElement): string {
    return element.innerHTML.
               replace(/<!--[\s\S]*?-->/g, '').
               replace(/>\s+/g, '>').
               replace(/\s+</g, '<').
               trim();
}

function drawnWithHTML(fragment: ReturnType<typeof card>): string {
    const element = document.createElement('div');
    stringRender(element, fragment);
    return markupOf(element);
}

function drawnWithView(template: ReturnType<typeof cardView>): string {
    const element = document.createElement('div');
    render(element, template);
    return markupOf(element);
}


/** A section with a bit of everything cards.ts tells apart. */
const section = {
    entries:       12,
    enabled:       true,
    nothingInIt:   {},
    words:         [ 'dns', 'nts' ],
    metrological:  { path: 'logs/metrological', keyId: 'd5c0f73cdcce32b5', bus: { nodes: [ { id: 1 }, { id: 2 } ] } },
    servers:       [ { address: '192.0.2.53', port: 53 }, { address: '198.51.100.1', port: 853 } ],
    escaped:       '<b>not bold</b> & co'
};

const libraries = [
    { name: 'WWCP_ISO15118', version: '1.0', assembly: 'cloud.charging.open.protocols.ISO15118.SDP', commit: 'f81fa510590d9ec045dfb6f089a284a6c0335a82' },
    { name: 'WWCP_ISO15118', version: '1.0', assembly: 'cloud.charging.open.protocols.ISO15118.V2G', commit: 'f81fa510590d9ec045dfb6f089a284a6c0335a82' },
    { name: 'Hermod',        version: '2.1.1', assembly: 'org.GraphDefined.Vanaheimr.Hermod' }
];


describe('the cards drawn with view.ts', () => {

    it('draw a section as card() does, a block for every thing in it, a line for everything else', () => {

        const withHTML = drawnWithHTML(card('Event log', 'fa-list-ul', section));

        assert.equal(drawnWithView(cardView('Event log', 'fa-list-ul', section)), withHTML);
        assert.match(withHTML, /<div class="kv-nested"><span class="k">Metrological<\/span>/, 'the comparison compared nothing');

    });

    it('draw the extra above the fields, as card() does, and nothing where there is none', () => {

        assert.equal(drawnWithView(cardView('Local controller', 'fa-sitemap', { ocppId: 'lc001' },
                                            html`<div class="kv"><span class="k">Uptime</span><span class="v">${3} minutes</span></div>`)),
                     drawnWithHTML(card('Local controller', 'fa-sitemap', { ocppId: 'lc001' },
                                        stringHTML`<div class="kv"><span class="k">Uptime</span><span class="v">${3} minutes</span></div>`)));

        assert.equal(drawnWithView(cardView('Local controller', 'fa-sitemap', { ocppId: 'lc001' })),
                     drawnWithHTML(card('Local controller', 'fa-sitemap', { ocppId: 'lc001' })));

    });

    it('draw the Libraries card as librariesCard() does, an assembly only where two lines share a name', () => {

        const withHTML = drawnWithHTML(librariesCard(libraries));

        assert.equal(drawnWithView(librariesCardView(libraries)), withHTML);
        assert.match(withHTML, /ISO15118\.<wbr>SDP/, 'the comparison compared nothing');
        assert.doesNotMatch(withHTML, /Vanaheimr\.<wbr>Hermod/, 'an assembly was named that tells no two lines apart');

    });

    it('break a dotted name where breakable() does, and nowhere in a number', () => {

        for (const name of [ 'cloud.charging.open.protocols.WWCP', 'WWCP_ISO15118', 'Hermod 2.1.1', 'plain' ]) {
            const withHTML = document.createElement('span');
            const withView = document.createElement('span');
            stringRender(withHTML, breakable(name));
            render(withView, breakableView(name));
            assert.equal(markupOf(withView), markupOf(withHTML), name);
        }

    });

});
