/**
 * What the NTS page calls a group on its tab, which names it takes for one,
 * and how what is typed into the "+" tab becomes the display name the node is
 * told.
 */

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import { displayNameOf, isGroupId, labelOf } from './ntsGroups.ts';


describe('the name of a group on its tab', () => {

    it('is "<id> time" where the group has no display name', () => {
        assert.equal(labelOf({ id: 'legal', displayName: null }, [ 'en' ]), 'Legal time');
        assert.equal(labelOf({ id: 'local', displayName: {}   }, [ 'en' ]), 'Local time');
        assert.equal(labelOf({ id: 'grid',  displayName: ' '  }, [ 'en' ]), 'Grid time', 'a blank name is none');
    });

    it('is the one text a group has for every language', () => {
        assert.equal(labelOf({ id: 'local', displayName: ' Site clock ' }, [ 'de' ]), 'Site clock');
    });

    it('is the text in the first of the reader\'s languages the group has, or in the one it is a dialect of', () => {

        const local = { id: 'local', displayName: { en: 'Local time', de: 'Lokale Zeit', 'de-at': 'Lokalzeit' } };

        assert.equal(labelOf(local, [ 'de-AT', 'de' ]), 'Lokalzeit');
        assert.equal(labelOf(local, [ 'de-CH' ]),       'Lokale Zeit',  'the language a dialect is of');
        assert.equal(labelOf(local, [ 'fr', 'de' ]),    'Lokale Zeit',  'the second language where the first has nothing');
        assert.equal(labelOf({ id: 'local', displayName: { DE: 'Lokale Zeit' } }, [ 'de' ]), 'Lokale Zeit', 'regardless of case');

    });

    it('is the text for every language, then the English one, then any, where the reader\'s languages have none', () => {
        assert.equal(labelOf({ id: 'local', displayName: { en: 'Local time', '*': 'Site clock' } }, [ 'fr' ]), 'Site clock');
        assert.equal(labelOf({ id: 'local', displayName: { de: 'Lokale Zeit', en: 'Local time' } }, [ 'fr' ]), 'Local time');
        assert.equal(labelOf({ id: 'local', displayName: { de: 'Lokale Zeit' } },                    [ 'fr' ]), 'Lokale Zeit');
    });

});


describe('the name of a new group', () => {

    it('is lower-case letters, digits and hyphens, beginning with a letter, and not too long', () => {

        for (const id of [ 'legal', 'local', 'grid-a', 'site2' ])
            assert.equal(isGroupId(id, 32), true, id);

        for (const id of [ 'Local', '1st', 'grid_a', 'grid a', '-grid', '', 'a'.repeat(33) ])
            assert.equal(isGroupId(id, 32), false, JSON.stringify(id));

    });

});


describe('the display name of a new group', () => {

    it('is nothing where no line says anything', () => {
        assert.deepEqual(displayNameOf([ { language: 'en', text: ' ' }, { language: '', text: '' } ]), {});
    });

    it('is one text where the only line is for every language', () => {
        assert.deepEqual(displayNameOf([ { language: '',  text: ' Site clock ' } ]), { name: 'Site clock' });
        assert.deepEqual(displayNameOf([ { language: '*', text: 'Site clock' } ]),   { name: 'Site clock' });
    });

    it('is the texts by language, in lower case, otherwise', () => {
        assert.deepEqual(displayNameOf([ { language: 'en', text: 'Local time' }, { language: 'DE-at', text: 'Lokalzeit' }, { language: 'fr', text: '' } ]),
                         { name: { en: 'Local time', 'de-at': 'Lokalzeit' } });
    });

    it('says which line is not a language, rather than leaving it to the node', () => {
        assert.match(displayNameOf([ { language: 'english', text: 'Local time' } ]).error ?? '', /"english" is not a language/);
        assert.match(displayNameOf([ { language: 'en', text: 'Local time' }, { language: '', text: 'Lokale Zeit' } ]).error ?? '',
                     /"Lokale Zeit" is said in no language/);
    });

});
