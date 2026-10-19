/*
 * The fields that say what a server's certificate is held to, drawn for the
 * node's two kinds of server and for one a kind of node brings: a time
 * server's mismatch is evidence and said so, a name server's is not, and a
 * charging station's meter is called a meter and its mismatch is evidence
 * where the station says it is - rather than a time server's or a name
 * server's words on a page about a meter.
 */

import '../../test/dom.ts';

import { strict as assert } from 'node:assert';
import { describe, it }      from 'node:test';

import { noPins }           from './pins.ts';
import { pinsFieldset }     from './pinViews.ts';
import { render }           from '../view.ts';


function drawn(context: Parameters<typeof pinsFieldset>[1]): string {
    const element = document.createElement('div');
    render(element, pinsFieldset(noPins(), context));
    return element.textContent!.replace(/\s+/g, ' ');
}


describe('the fields that say what a server is held to', () => {

    it('speak of a time server, whose mismatch is evidence, and of a name server, whose is not', () => {

        const nts = drawn({ service: 'nts', shown: null, offers: null });
        const dns = drawn({ service: 'dns', shown: null, offers: null });

        assert.match(nts,        /Beyond what every time server is held to/);
        assert.match(nts,        /for a time server, that goes into the metrological log either way/);
        assert.match(dns,        /Beyond what every name server is held to/);
        assert.doesNotMatch(dns, /metrological log either way/);

    });

    it('speak of what a kind of node calls its server, and say its mismatch is evidence where that kind says so', () => {

        const meter = drawn({ service: 'meter', what: 'meter', evidence: true, shown: null, offers: null });

        assert.match(meter,        /Beyond what every meter is held to/);
        assert.match(meter,        /for a meter, that goes into the metrological log either way/);
        assert.doesNotMatch(meter, /time server|name server/);

    });

});
