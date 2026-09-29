/**
 * The cards of a Configuration page, asked of what they draw: a value that is
 * one thing of its own as a block and not as JSON (the CSMS's finding, on the
 * metrological log), an assembly named only where it tells two lines apart
 * (the vehicle's), and a name broken only where it may be.
 */

import { strict as assert } from 'node:assert';
import { describe, it }     from 'node:test';

import { breakable, card, librariesCard } from './cards.ts';


describe('a card', () => {

    it('draws a value that is one thing of its own as a block below its name, not as JSON', () => {

        const drawn = card('Event log', 'fa-list-ul', {
                          entries:       12,
                          metrological:  { path: 'logs/metrological', keyId: 'd5c0f73cdcce32b5', head: 'R9qths4n' }
                      }).value;

        assert.ok(!drawn.includes('{&quot;path&quot;'), 'the metrological log as JSON');
        assert.match(drawn, /<div class="kv-nested">\s*<span class="k">Metrological<\/span>/);
        assert.match(drawn, /<span class="k">Path<\/span>\s*<span class="v">logs\/metrological<\/span>/);
        assert.match(drawn, /<span class="k">Key ID<\/span>\s*<span class="v">d5c0f73cdcce32b5<\/span>/);
        assert.match(drawn, /<span class="k">Entries<\/span>\s*<span class="v">12<\/span>/);

    });

    it('draws each of a list of things as a block, and a list of words, nothing and an empty thing on a line', () => {

        const drawn = card('Time', 'fa-clock', {
                          servers:  [ { host: 'ptbtime1.ptb.de' }, { host: 'ptbtime2.ptb.de' } ],
                          tags:     [ 'nts', 'clock' ],
                          none:     null,
                          empty:    {}
                      }).value;

        assert.equal(drawn.match(/<div class="nested-item">/g)?.length, 2, 'a block for each server');
        assert.match(drawn, /<span class="k">Tags<\/span>\s*<span class="v">nts, clock<\/span>/);
        assert.match(drawn, /<span class="k">None<\/span>\s*<span class="v">-<\/span>/);
        assert.match(drawn, /<span class="k">Empty<\/span>\s*<span class="v">\{\}<\/span>/);

    });

});


describe('the Libraries card', () => {

    const line = (name: string, assembly: string, commit: unknown = '1111111111111111111111111111111111111111') =>
                     ({ name, assembly, version: '1.0.0', commit });

    it('names an assembly only where two lines share a repository name', () => {

        const drawn = librariesCard([
                          line('Hermod',                'org.GraphDefined.Vanaheimr.Hermod'),
                          line('WWCP_ISO15118',         'cloud.charging.open.protocols.ISO15118.SDP'),
                          line('ModbusTLSEnergyMeter',  'ModbusTLSEnergyMeter'),
                          line('ModbusTLSEnergyMeter',  'ModbusTLSEnergyMeterCLI')
                      ]).value;

        assert.equal(drawn.match(/<span class="muted small">/g)?.length, 2, 'an assembly beside each of the two of one name');
        assert.ok(drawn.includes('ModbusTLSEnergyMeterCLI'));
        assert.ok(!drawn.includes('SDP'),       'the first assembly the node found of WWCP_ISO15118, beside it');
        assert.ok(!drawn.includes('Vanaheimr'), 'Hermod\'s assembly, beside it');

    });

    it('shows the whole commit, and none where the node sent none', () => {

        const drawn = librariesCard([
                          line('Hermod', 'Hermod', 'abcdef0123456789abcdef0123456789abcdef01'),
                          line('Styx',   'Styx',   null)
                      ]).value;

        assert.equal(drawn.match(/class="muted small commit"/g)?.length, 1);
        assert.ok(drawn.includes('>abcdef0123456789abcdef0123456789abcdef01<'));

    });

});


describe('a dotted name', () => {

    it('may break after a dot that ends a word and after an underscore, and not inside a number', () => {

        assert.equal(breakable('cloud.charging.open.protocols.OCPIv2_2_1').value,
                     'cloud.<wbr>charging.<wbr>open.<wbr>protocols.<wbr>OCPIv2_<wbr>2_<wbr>1');
        assert.equal(breakable('WWCP_ISO15118').value, 'WWCP_<wbr>ISO15118');
        assert.equal(breakable('OCPI 2.2.1').value,    'OCPI 2.2.1');

    });

});
