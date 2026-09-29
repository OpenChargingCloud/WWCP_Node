/*
 * The rules of pages.ts, asked of pages written for them: what each one has to
 * find, and what it has to let pass. The ways a page holds its forms are the
 * ones the eight kinds of node were found using when their pages were first
 * asked - by name, all at once, and by a flag of the page's own.
 */

import { strict as assert } from 'node:assert';
import { describe, it }     from 'node:test';

import { asksBeforeItsReload, drawnAnewWithoutItsDrafts, formsKnownByNothing, formsNotHeld, formsOf, inlineStylesOf, keptFormsNotOnThePage, linksPastTheBase, numbersReadAsZeroWhenEmptied, rolesNamedAsNeeded, saysWhetherItHolds, signedInSaidByHand } from './pages.ts';


const page = (source: string) => ({ name: 'page.ts', source });


describe('a page with a form', () => {

    it('says whether it is holding anything only by telling unsaved', () => {
        assert.equal(saysWhetherItHolds(page(`<form id="dns-form" class="form-stack"></form>`)), false);
        assert.equal(saysWhetherItHolds(page(`const release = unsaved.heldBy(() => dirty);`)), true);
    });

    it('is read for every form it has, with its id or without one', () => {
        assert.deepEqual(formsOf(page(`<form id="dns-form" class="form-stack">  <form class="form-stack upload-form" data-id="\${entry.id}">
                                       <form
                                           class="form-stack" id="add-form">`)),
                         [ 'dns-form', null, 'add-form' ]);
    });

});


describe('a page holding its forms', () => {

    it('by name holds the ones it names, and not the one it forgot', () => {

        const session = page(`<form id="link-form">  <form id="goals-form">  <form id="run-form">
                              unsaved.heldBy(() => typedSinceDrawn(content.querySelector('#link-form')) ||
                                                   typedSinceDrawn(content.querySelector('#goals-form')));`);

        assert.deepEqual(formsNotHeld(session), [ '#run-form' ]);

    });

    it('by name cannot hold a form without one', () => {
        assert.deepEqual(formsNotHeld(page(`<form class="form-stack" data-edit="\${entry.id}">
                                            unsaved.heldBy(() => typedSinceDrawn(content.querySelector('#add-form')));`)),
                         [ 'a form without an id' ]);
    });

    it('all at once holds every one, a form without an id as well', () => {
        assert.deepEqual(formsNotHeld(page(`<form id="socket-form">  <form class="form-stack upload-form">
                                            unsaved.heldBy(() => anyFormTypedSinceDrawn(content));`)),
                         []);
    });

    it('by a flag of its own alone holds none: what is typed and not yet added is in no flag', () => {
        assert.deepEqual(formsNotHeld(page(`<form id="add-form" class="form-stack">
                                            const release = unsaved.heldBy(() => dirty);`)),
                         [ '#add-form' ]);
    });

    it('by its flag and by its forms holds them all', () => {
        assert.deepEqual(formsNotHeld(page(`<form id="add-form" class="form-stack">
                                            const release = unsaved.heldBy(() => dirty || anyFormTypedSinceDrawn(content));`)),
                         []);
    });

    it('does not have to hold a dialog\'s form, which asks for itself', () => {

        const dns = page(`<form id="dns-form">  <form id="pins-form">
                          unsaved.heldBy(() => typedSinceDrawn(content.querySelector('#dns-form')));`);

        assert.deepEqual(formsNotHeld(dns),                 [ '#pins-form' ]);
        assert.deepEqual(formsNotHeld(dns, [ 'pins-form' ]), []);

    });

});


describe('a Reload', () => {

    it('that asks before it throws a draft away passes', () => {
        assert.equal(asksBeforeItsReload(page(`<button id="reload">  if (!unsaved.mayBeLost()) return;`)), true);
    });

    it('that does not is found', () => {
        assert.equal(asksBeforeItsReload(page(`<button id="reload">  void load();`)), false);
    });

    it('is not asked of a page that has none', () => {
        assert.equal(asksBeforeItsReload(page(`<form id="add-form">`)), true);
    });

});


describe('a number', () => {

    it('read with Number() is found, as an emptied field would be 0', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`timeout: Number(data.get('timeout')),  retries: Number(data.get('maxRetries'))`)),
                         [ 'timeout', 'maxRetries' ]);
    });

    it('read with numberField passes', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`timeout: numberField(form, 'timeout')`)), []);
    });

    it('may be read with Number() where it is a priority, since empty means 0 there', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`priority: Number(data.get('priority') ?? 0)`)), []);
    });

    it('read with Number() of field() is found as well', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`pingEvery: Number(field(form, 'pingEvery')),`)), [ 'pingEvery' ]);
    });

    it('read with Number() of an input\'s value is found as well, and of what is not typed is not', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`const index = Number(input.dataset.index);
                                                           servers[index].port = Number(input.value);`)),
                         [ 'input.value' ]);
    });

    it('may be read with Number() where the page says itself what empty means', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`port: field(form, 'port') === '' ? 0 : Number(field(form, 'port')),`)), []);
    });

});


describe('a style', () => {

    it('written into a page as an attribute is found, as the policy drops it', () => {
        assert.deepEqual(inlineStylesOf(page(`<button type="button" id="reveal" class="btn small" style="margin-left:auto">`)),
                         [ 'style="margin-left:auto"' ]);
    });

    it('in a style element, or set as an attribute by the script, is found as well', () => {
        assert.deepEqual(inlineStylesOf(page(`<style>.x { color: red }</style>  row.setAttribute('style', 'display:none');`)),
                         [ '<style', "setAttribute('style'" ]);
    });

    it('said by a class passes, and so does a style property the script sets, which the policy lets through', () => {
        assert.deepEqual(inlineStylesOf(page(`<input name="partyId" class="capitals" data-style="x" />  bar.style.width = \`\${percent}%\`;`)),
                         []);
    });

});


describe('a link', () => {

    it('written with a path of its own is found, as it leads past the base', () => {
        assert.deepEqual(linksPastTheBase(page(`Every reading is in the <a href="/logs">log</a>.`)), [ '/logs' ]);
    });

    it('through toURL passes, and so do one to elsewhere and one within the page', () => {
        assert.deepEqual(linksPastTheBase(page(`<a href="\${toURL('/logs')}">log</a>  <a href="https://www.ptb.de/">PTB</a>  <a href="#legal">legal time</a>`)),
                         []);
    });

});


describe('a page drawn anew', () => {

    it('with draw() after something was done on it is found, once for each time beyond the first', () => {
        assert.equal(drawnAnewWithoutItsDrafts(page(`<form id="connection-form">  <form id="credentials-form">
                                                     current = await api.csms.save(update);  draw();
                                                     current = await api.csms.saveCredentials(update);  draw();
                                                     current = loaded;  draw();`)),
                     2);
    });

    it('with a form known by neither an id nor a data-id is found, one for each such form', () => {
        assert.equal(formsKnownByNothing(page(`<form id="add-form">  <form class="form-stack upload-form" data-id="\${entry.id}">
                                               <form class="form-stack" data-edit="\${entry.id}">  <form>`)),
                     2);
    });

    it('naming as the one saved a form it has not is found, and a form it has, none, or a variable pass', () => {
        assert.deepEqual(keptFormsNotOnThePage(page(`<form id="token-form" class="form-stack">
                                                     keepDrafts(content, 'token-forms', draw);  keepDrafts(content, 'token-form', draw);
                                                     keepDrafts(content, null, draw);  keepDrafts(content, saved, draw);  keepDrafts(content, id, draw);`)),
                         [ 'token-forms' ]);
    });

    it('through keepDrafts passes, and so do a card drawn on its own and a draw() a comment speaks of', () => {
        assert.equal(drawnAnewWithoutItsDrafts(page(`<form id="connection-form">  <form id="credentials-form">
                                                     keepDrafts(content, 'connection-form', draw);
                                                     keepDrafts(content, null, draw);
                                                     drawServers();  shown.draw();
                                                     // Redrawn with draw(); once, which threw the credentials away.
                                                     /* draw(); draw(); */
                                                     current = loaded;  draw();`)),
                     0);
    });

});


describe('who is signed in', () => {

    it('said by the page itself is found, whichever way it names them', () => {
        assert.deepEqual(signedInSaidByHand(page(`Signed in as \${auth.user?.roles.join(', ') ?? 'somebody'}, which may look at the name
                                                  resolution but not change it.  Signed in as \${auth.user?.roleTitle ?? 'somebody'}, which may`)),
                         [ `Signed in as \${auth.user?.roles.join(', ') ?? 'somebody'}`, `Signed in as \${auth.user?.roleTitle ?? 'somebody'}` ]);
    });

    it('said through mayButNot passes, and so does a table that shows the name alone', () => {
        assert.deepEqual(signedInSaidByHand(page(`<div class="notice">\${mayButNot('look at the store', 'change it')}</div>
                                                  <tr><td>Signed in as</td><td><code>\${me?.username ?? '-'}</code></td></tr>`)),
                         []);
    });

});


describe('a role', () => {

    it('named as the one that is needed is found, one or several, across a line\'s end', () => {
        assert.deepEqual(rolesNamedAsNeeded(page(`That needs the system administrator role.  That needs the CPO or the system administrator role.
                                                  That needs the driver, the service or the system
                                                  administrator role.  Switching one off needs the CPO role; the others need the installer role.
                                                  That needs the operator role or better.`)),
                         [ 'needs the system administrator role', 'needs the CPO or the system administrator role',
                           'needs the driver, the service or the system administrator role', 'needs the CPO role',
                           'need the installer role', 'needs the operator role' ]);
    });

    it('that is needed without a name passes, and so does what else a page says is needed', () => {
        assert.deepEqual(rolesNamedAsNeeded(page(`That needs a role that may change it.  Looking something up needs a role that may run queries.
                                                  That needs the role that changes how this station connects.
                                                  A partner needs the token it was given to call any of them.
                                                  Which roles there are, and what the role of an account may, is the configuration file's to say.`)),
                         []);
    });

});
