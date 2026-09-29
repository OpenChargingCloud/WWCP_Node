/*
 * The rules of pages.ts, asked of pages written for them: what each one has to
 * find, and what it has to let pass. The ways a page holds its forms are the
 * ones the eight kinds of node were found using when their pages were first
 * asked - by name, all at once, and by a flag of the page's own.
 */

import { strict as assert } from 'node:assert';
import { describe, it }     from 'node:test';

import { asksBeforeItsReload, formsNotHeld, formsOf, numbersReadAsZeroWhenEmptied, saysWhetherItHolds } from './pages.ts';


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
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`priority: Number(data.get('priority'))`)), []);
    });

});
