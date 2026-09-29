/**
 * What every page every node shares is held to, asked of its source.
 *
 * Run with `npm test`. Node's runner has no browser to open a page in, so what
 * is asked here is the pages' source:
 *
 * - that each page with a form says, for as long as it is open, whether it is
 *   holding anything, and that its Reload asks first - five pages of the local
 *   controller threw a typed address, port, station, subject or authority away
 *   on one click of Reload or of the menu, without a word;
 * - that a number is read as one - an emptied field is not given, where
 *   Number("") made it 0, which the node refuses for a timeout, the whole save
 *   with it (found on the energy meter, and on the local controller's DNS and
 *   NTS pages too);
 * - that a switch stands outside a stacked form - inside one, the form's label
 *   rule stood the box centred above its words (found on the meter's DNS page).
 *
 * A kind of node's own pages are asked the same by its own copy of this test.
 */

import { strict as assert }           from 'node:assert';
import { readdirSync, readFileSync }  from 'node:fs';
import { describe, it }               from 'node:test';


/** Pages whose form is not a draft: signing in is the way in, and nothing typed there is the node's to lose. */
const notDrafts = new Set([ 'login.ts' ]);

const here      = new URL('./', import.meta.url);

const pages     = readdirSync(here).
                      filter(name => name.endsWith('.ts') && !name.endsWith('.test.ts')).
                      map(name => ({ name, source: readFileSync(new URL(name, here), 'utf-8') }));

const withForms = pages.filter(page => page.source.includes('<form') && !notDrafts.has(page.name));


describe('every page with a form', () => {

    it('is found at all, so that what follows is not said of nothing', () => {
        assert.deepEqual(withForms.map(page => page.name).sort(), [ 'certificates.ts', 'dns.ts', 'nts.ts' ]);
    });

    for (const page of withForms) {

        it(`${page.name} says whether it is holding anything`, () => {
            assert.match(page.source, /unsaved\.heldBy\(/,
                         `${page.name} has a form and never says when it is holding a draft, so leaving it asks nothing`);
        });

        if (page.source.includes('id="reload"'))
            it(`${page.name} asks before its Reload throws a draft away`, () => {
                assert.match(page.source, /unsaved\.mayBeLost\(\)/,
                             `${page.name} has a form and a Reload that redraws it without asking`);
            });

        it(`${page.name} holds every form it has, not only the first one`, () => {

            const forms = [ ...page.source.matchAll(/<form id="([^"]+)"/g) ].map(match => match[1]!).
                              // A dialog's form lives and dies with its dialog,
                              // which asks for itself when it is closed.
                              filter(id => !/^(server|pins|query|usages)-form$/.test(id));

            for (const id of forms)
                assert.match(page.source, new RegExp(`typedSinceDrawn\\(content\\.querySelector\\('#${id}'\\)\\)`),
                             `${page.name}: what is typed into #${id} is thrown away without a question`);

        });

    }

});


describe('a number on a page', () => {

    for (const page of withForms) {

        it(`${page.name} reads its numbers with numberField, so that an emptied field is not 0`, () => {

            // The one allowed: a priority, where empty means 0, the priority
            // every server has unless it is given another.
            const read = [ ...page.source.matchAll(/Number\(data\.get\('([^']+)'\)/g) ].
                             map(match => match[1]).
                             filter(name => name !== 'priority');

            assert.deepEqual(read, [], `${page.name} reads ${read.join(', ')} with Number(), which makes an emptied field 0`);

        });

    }

});


describe('a switch', () => {

    for (const page of pages) {

        it(`${page.name} puts none inside a stacked form, where it would stand above its words`, () => {

            for (const form of page.source.matchAll(/<form[^>]*class="[^"]*form-stack[^"]*"[^>]*>([\s\S]*?)<\/form>/g))
                assert.doesNotMatch(form[1]!, /class="switch/,
                                    `${page.name} has a switch inside a .form-stack; label.checkbox is what a form takes`);

        });

    }

});
