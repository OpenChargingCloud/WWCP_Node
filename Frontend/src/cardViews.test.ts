/*
 * The cards of a Configuration page, asked of what they draw: a value that is
 * one thing of its own as a block and not as JSON (the CSMS's finding, on the
 * metrological log), an assembly named only where it tells two lines apart
 * (the vehicle's), and a name broken only where it may be - and, field for
 * field, the markup cards.ts drew with html.ts, so that the pages that moved
 * from card() to cardView() show what they showed. Asked as the browser has
 * them, in a document of happy-dom, without lit-html's comments and the
 * blanks between tags.
 */

import '../test/dom.ts';

import { strict as assert } from 'node:assert';
import { describe, it }      from 'node:test';

import { breakableView, cardView, librariesCardView } from './cardViews.ts';
import { html, render }                               from './view.ts';


/** What an element holds, as markup to compare: no comments, no blanks between tags or at the ends of text. */
function markupOf(element: HTMLElement): string {
    return element.innerHTML.
               replace(/<!--[\s\S]*?-->/g, '').
               replace(/>\s+/g, '>').
               replace(/\s+</g, '<').
               trim();
}

function drawn(template: ReturnType<typeof cardView>): string {
    const element = document.createElement('div');
    render(element, template);
    return markupOf(element);
}

const line   = (key: string, value: string) => `<div class="kv"><span class="k">${key}</span><span class="v">${value}</span></div>`;
const block  = (key: string, ...items: string[]) => `<div class="kv-nested"><span class="k">${key}</span><div class="nested">` +
                                                    items.map(item => `<div class="nested-item">${item}</div>`).join('') +
                                                    `</div></div>`;
const card   = (icon: string, title: string, ...fields: string[]) => `<section class="card"><h2><i class="fa-solid ${icon}"></i>${title}</h2>` +
                                                                      `<div class="kv-list">${fields.join('')}</div></section>`;


describe('a card', () => {

    it('draws a section as cards.ts drew it: a block for every thing in it, however deep, a line for everything else', () => {

        assert.equal(drawn(cardView('Event log', 'fa-list-ul', {
                         entries:       12,
                         enabled:       true,
                         nothingInIt:   {},
                         words:         [ 'dns', 'nts' ],
                         metrological:  { path: 'logs/metrological', keyId: 'd5c0f73cdcce32b5', bus: { nodes: [ { id: 1 }, { id: 2 } ] } },
                         servers:       [ { address: '192.0.2.53', port: 53 }, { address: '198.51.100.1', port: 853 } ],
                         escaped:       '<b>not bold</b> & co'
                     })),
                     card('fa-list-ul', 'Event log',
                          line('Entries', '12'),
                          line('Enabled', 'yes'),
                          line('Nothing in it', '{}'),
                          line('Words', 'dns, nts'),
                          block('Metrological', line('Path', 'logs/metrological') +
                                                line('Key ID', 'd5c0f73cdcce32b5') +
                                                block('Bus', block('Nodes', line('ID', '1'), line('ID', '2')))),
                          block('Servers', line('Address', '192.0.2.53')   + line('Port', '53'),
                                           line('Address', '198.51.100.1') + line('Port', '853')),
                          line('Escaped', '&lt;b&gt;not bold&lt;/b&gt; &amp; co')));

    });

    it('draws a value that is one thing of its own as a block below its name, not as JSON', () => {

        const markup = drawn(cardView('Event log', 'fa-list-ul', {
                           entries:       12,
                           metrological:  { path: 'logs/metrological', keyId: 'd5c0f73cdcce32b5', head: 'R9qths4n' }
                       }));

        assert.ok(!markup.includes('&quot;'), 'the metrological log as JSON');
        assert.ok(markup.includes(block('Metrological', line('Path', 'logs/metrological') + line('Key ID', 'd5c0f73cdcce32b5') + line('Head', 'R9qths4n'))));

    });

    it('draws each of a list of things as a block, and a list of words, nothing and an empty thing on a line', () => {

        const markup = drawn(cardView('Time', 'fa-clock', {
                           servers:  [ { host: 'ptbtime1.ptb.de' }, { host: 'ptbtime2.ptb.de' } ],
                           tags:     [ 'nts', 'clock' ],
                           none:     null,
                           empty:    {}
                       }));

        assert.equal(markup, card('fa-clock', 'Time',
                                  block('Servers', line('Host', 'ptbtime1.ptb.de'), line('Host', 'ptbtime2.ptb.de')),
                                  line('Tags', 'nts, clock'),
                                  line('None', '-'),
                                  line('Empty', '{}')));

    });

    it('draws the station\'s bus, a thing with things and a list of things in it, without a line of JSON', () => {

        // The station's 10BASE-T1S bus, as its V2G section sends it.
        const markup = drawn(cardView('V2G', 'fa-plug', {
                           t1s: {
                               medium:   'loopback',
                               thermal:  { state: 'normal', alarm: false },
                               nodes:    [ { id: 1, name: 'inlet', mac: '02:00:00:00:00:01' },
                                           { id: 2, name: 'cable', mac: '02:00:00:00:00:02', extra: { weight: 3 } } ]
                           }
                       }));

        assert.ok(!markup.includes('&quot;'), 'a thing as JSON');
        assert.equal(markup.match(/<div class="nested-item">/g)?.length, 5,
                     'the bus, its thermal state, each of its two nodes, and what the second has extra');
        assert.ok(markup.includes(block('Thermal', line('State', 'normal') + line('Alarm', 'no'))));
        assert.ok(markup.includes(block('Extra', line('Weight', '3'))));

    });

    it('draws the extra above the fields, and nothing where there is none', () => {

        assert.equal(drawn(cardView('Local controller', 'fa-sitemap', { ocppId: 'lc001' },
                                    html`<div class="kv"><span class="k">Uptime</span><span class="v">${3} minutes</span></div>`)),
                     card('fa-sitemap', 'Local controller', line('Uptime', '3 minutes'), line('OCPP ID', 'lc001')));

        assert.equal(drawn(cardView('Local controller', 'fa-sitemap', { ocppId: 'lc001' })),
                     card('fa-sitemap', 'Local controller', line('OCPP ID', 'lc001')));

    });

});


describe('the Libraries card', () => {

    const library = (name: string, assembly: string, commit: unknown = '1111111111111111111111111111111111111111') =>
                        ({ name, assembly, version: '1.0.0', commit });

    it('draws as cards.ts drew it: an assembly only where two lines share a name, the whole commit where there is one', () => {

        assert.equal(drawn(librariesCardView([
                         { name: 'WWCP_ISO15118', version: '1.0',   assembly: 'cloud.charging.open.protocols.ISO15118.SDP', commit: 'f81fa510590d9ec045dfb6f089a284a6c0335a82' },
                         { name: 'WWCP_ISO15118', version: '1.0',   assembly: 'cloud.charging.open.protocols.ISO15118.V2G', commit: 'f81fa510590d9ec045dfb6f089a284a6c0335a82' },
                         { name: 'Hermod',        version: '2.1.1', assembly: 'org.GraphDefined.Vanaheimr.Hermod' }
                     ])),
                     card('fa-cubes', 'Libraries',
                          line('WWCP_<wbr>ISO15118', '1.0<span class="muted small">cloud.<wbr>charging.<wbr>open.<wbr>protocols.<wbr>ISO15118.<wbr>SDP</span>' +
                                                     '<span class="muted small commit">f81fa510590d9ec045dfb6f089a284a6c0335a82</span>'),
                          line('WWCP_<wbr>ISO15118', '1.0<span class="muted small">cloud.<wbr>charging.<wbr>open.<wbr>protocols.<wbr>ISO15118.<wbr>V2G</span>' +
                                                     '<span class="muted small commit">f81fa510590d9ec045dfb6f089a284a6c0335a82</span>'),
                          line('Hermod', '2.1.1')));

    });

    it('names an assembly only where two lines share a repository name', () => {

        const markup = drawn(librariesCardView([
                           library('Hermod',                'org.GraphDefined.Vanaheimr.Hermod'),
                           library('WWCP_ISO15118',         'cloud.charging.open.protocols.ISO15118.SDP'),
                           library('ModbusTLSEnergyMeter',  'ModbusTLSEnergyMeter'),
                           library('ModbusTLSEnergyMeter',  'ModbusTLSEnergyMeterCLI')
                       ]));

        assert.equal(markup.match(/<span class="muted small">/g)?.length, 2, 'an assembly beside each of the two of one name');
        assert.ok(markup.includes('ModbusTLSEnergyMeterCLI'));
        assert.ok(!markup.includes('SDP'),       'the first assembly the node found of WWCP_ISO15118, beside it');
        assert.ok(!markup.includes('Vanaheimr'), 'Hermod\'s assembly, beside it');

    });

    it('shows the whole commit, and none where the node sent none', () => {

        const markup = drawn(librariesCardView([
                           library('Hermod', 'Hermod', 'abcdef0123456789abcdef0123456789abcdef01'),
                           library('Styx',   'Styx',   null)
                       ]));

        assert.equal(markup.match(/class="muted small commit"/g)?.length, 1);
        assert.ok(markup.includes('>abcdef0123456789abcdef0123456789abcdef01<'));

    });

});


describe('a dotted name', () => {

    it('may break after a dot that ends a word and after an underscore, and not inside a number', () => {

        for (const [ name, broken ] of [ [ 'cloud.charging.open.protocols.OCPIv2_2_1', 'cloud.<wbr>charging.<wbr>open.<wbr>protocols.<wbr>OCPIv2_<wbr>2_<wbr>1' ],
                                         [ 'cloud.charging.open.protocols.WWCP',       'cloud.<wbr>charging.<wbr>open.<wbr>protocols.<wbr>WWCP' ],
                                         [ 'WWCP_ISO15118',                            'WWCP_<wbr>ISO15118' ],
                                         [ 'Hermod 2.1.1',                             'Hermod 2.1.1' ],
                                         [ 'OCPI 2.2.1',                               'OCPI 2.2.1' ],
                                         [ 'plain',                                    'plain' ] ] as const)
            assert.equal(drawn(breakableView(name)), broken, name);

    });

});
