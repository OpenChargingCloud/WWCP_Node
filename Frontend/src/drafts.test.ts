/**
 * What keepDrafts carries across a page drawing itself anew: what is typed
 * into the forms not saved, and nothing else. The vehicle kept its pages'
 * drafts this way first; its tests came along.
 *
 * The forms are stand-ins with the properties the DOM gives a form and its
 * controls, since Node has no DOM.
 */

import { strict as assert } from 'node:assert';
import { describe, it }     from 'node:test';

import { draftsIn, keepDrafts } from './drafts.ts';
import { typedSinceDrawn }      from './unsaved.ts';


interface Option {
    value:            string;
    selected:         boolean;
    defaultSelected:  boolean;
}

interface Control {
    tagName:         string;
    name:            string;
    type:            string;
    value:           string;
    defaultValue:    string;
    checked:         boolean;
    defaultChecked:  boolean;
    multiple?:       boolean;
    size?:           number;
    options?:        Option[];
}

/** A text field drawn with one value, and typed into to hold another. */
const text = (name: string, drawn: string, typed: string = drawn): Control =>
    ({ tagName: 'INPUT', name, type: 'text', value: typed, defaultValue: drawn, checked: false, defaultChecked: false });

/** A field the page wrote and nobody sees: its value is its default, whatever it is set to. */
const hidden = (name: string, drawn: string): Control =>
    ({ tagName: 'INPUT', name, type: 'hidden', value: drawn, defaultValue: drawn, checked: false, defaultChecked: false });

/** A box drawn ticked or not, and left ticked or not - standing for "on", or for the value given. */
const box = (name: string, drawn: boolean, ticked: boolean = drawn, value: string = 'on'): Control =>
    ({ tagName: 'INPUT', name, type: 'checkbox', value, defaultValue: value, checked: ticked, defaultChecked: drawn });

/** A list drawn with one choice, and left at another. */
const list = (name: string, values: string[], drawn: string, chosen: string = drawn): Control =>
    ({ tagName: 'SELECT', name, type: 'select-one', value: chosen, defaultValue: '', checked: false, defaultChecked: false,
       multiple: false, size: 0,
       options: values.map(value => ({ value, selected: value === chosen, defaultSelected: value === drawn })) });

const button = (): Control =>
    ({ tagName: 'BUTTON', name: '', type: 'submit', value: '', defaultValue: '', checked: false, defaultChecked: false });

/**
 * A form with an id - or with none, '', and a data-id instead, as a form drawn
 * for each entry of a list has. Its id property is what the DOM makes it: the
 * control named "id", where there is one.
 */
const form = (id: string, controls: Control[], entry: string | null = null) =>
    ({ id:                controls.find(control => control.name === 'id') ?? id,
       elements:          controls,
       getAttribute:      (name: string) => name === 'id'      ? (id === '' ? null : id)
                                          : name === 'data-id' ? entry
                                          : null,
       querySelectorAll:  (selector: string) => selector === 'input, textarea, select'
                                                    ? controls.filter(control => control.tagName !== 'BUTTON')
                                                    : [] });

type Form = ReturnType<typeof form>;

/** A page, whose forms a draw replaces with new ones - as rendering it anew does. */
const page = (forms: Form[]) => {
    const it = { forms, querySelectorAll: (selector: string) => selector === 'form' ? it.forms : [] };
    return it;
};

const asRoot = (Page: ReturnType<typeof page> | Form) => Page as unknown as ParentNode;


describe('a page drawn anew with a draft on it', () => {

    it('keeps what is typed into a form other than the one saved', () => {

        const shown = page([ form('identity-form', [ text('name', 'EV', 'EV of the day'), button() ]),
                             form('battery-form',  [ text('soc',  '30', '31'),           button() ]) ]);

        keepDrafts(asRoot(shown), 'battery-form', () => {
            shown.forms = [ form('identity-form', [ text('name', 'EV'), button() ]),
                            form('battery-form',  [ text('soc',  '31'), button() ]) ];
        });

        assert.equal(shown.forms[0]!.elements[0]!.value, 'EV of the day', 'the name typed and not saved');
        assert.equal(typedSinceDrawn(asRoot(shown.forms[0]!)), true, 'and it still asks before it is left');
        assert.equal(shown.forms[1]!.elements[0]!.value, '31', 'the form saved is what the node now has');
        assert.equal(typedSinceDrawn(asRoot(shown.forms[1]!)), false);

    });

    it('leaves a form nobody typed into as it is drawn, the node\'s answer in it', () => {

        const shown = page([ form('interface-form', [ text('interface', 'eth0') ]),
                             form('settings-form',  [ text('maxRetries', '15') ]) ]);

        keepDrafts(asRoot(shown), null, () => {
            shown.forms = [ form('interface-form', [ text('interface', 'eth1') ]),
                            form('settings-form',  [ text('maxRetries', '15') ]) ];
        });

        assert.equal(shown.forms[0]!.elements[0]!.value, 'eth1');

    });

    it('keeps a box ticked and something else chosen from a list', () => {

        const shown = page([ form('link-form', [ box('renegotiate', false, true),
                                                 list('protocol', [ 'both', '20', '2' ], 'both', '20') ]),
                             form('goals-form', [ text('targetEnergyKWh', '') ]) ]);

        keepDrafts(asRoot(shown), 'goals-form', () => {
            shown.forms = [ form('link-form', [ box('renegotiate', false),
                                                list('protocol', [ 'both', '20', '2' ], 'both') ]),
                            form('goals-form', [ text('targetEnergyKWh', '42') ]) ];
        });

        const [ renegotiate, protocol ] = shown.forms[0]!.elements;

        assert.equal(renegotiate!.checked, true);
        assert.deepEqual(protocol!.options!.filter(option => option.selected).map(option => option.value), [ '20' ]);
        assert.equal(typedSinceDrawn(asRoot(shown.forms[0]!)), true);

    });

    it('leaves boxes that stand for other things as drawn, as many as they were', () => {

        const shown = page([ form('import-form', [ box('usage', false, true, 'modbus'), box('usage', false, false, 'web') ]) ]);

        keepDrafts(asRoot(shown), null, () => {
            shown.forms = [ form('import-form', [ box('usage', false, false, 'dns'), box('usage', false, false, 'nts') ]) ];
        });

        assert.deepEqual(shown.forms[0]!.elements.map(control => control.checked), [ false, false ],
                         'modbus ticked, and the time servers\' box ticked for it');

    });

    it('leaves a form drawn with other controls as drawn, where what went where is no longer certain', () => {

        const shown = page([ form('servers-form', [ text('address', '192.0.2.1', '192.0.2.9') ]) ]);

        keepDrafts(asRoot(shown), null, () => {
            shown.forms = [ form('servers-form', [ text('address', '192.0.2.1'), text('address', '192.0.2.2') ]) ];
        });

        assert.deepEqual(shown.forms[0]!.elements.map(control => control.value), [ '192.0.2.1', '192.0.2.2' ]);

    });

    it('holds no draft of a form that was only drawn, or of the one saved', () => {

        const shown = page([ form('identity-form', [ text('name', 'EV') ]),
                             form('battery-form',  [ text('soc', '30', '31') ]) ]);

        assert.deepEqual([ ...draftsIn(asRoot(shown), 'battery-form').keys() ], []);
        assert.deepEqual([ ...draftsIn(asRoot(shown), null).keys() ], [ 'battery-form' ]);

    });

});


describe('a form drawn for each entry of a list', () => {

    it('is known by its data-id where it has no id, and keeps what is typed into it', () => {

        const shown = page([ form('', [ text('password', '', 'secret') ], 'lc001'),
                             form('', [ text('password', '') ],           'lc002') ]);

        keepDrafts(asRoot(shown), null, () => {
            shown.forms = [ form('', [ text('password', '') ], 'lc002'),
                            form('', [ text('password', '') ], 'lc001') ];
        });

        assert.deepEqual(shown.forms.map(one => one.elements[0]!.value), [ '', 'secret' ],
                         'what was typed for one entry is back in that entry\'s form, wherever it is drawn now');

    });

    it('is the one saved where its data-id is the one named', () => {

        const shown = page([ form('', [ text('label', 'old', 'new') ], 'lc001'),
                             form('', [ text('label', 'x',   'y')   ], 'lc002') ]);

        assert.deepEqual([ ...draftsIn(asRoot(shown), 'lc001').keys() ], [ '[data-id=lc002]' ]);

    });

    it('is not given what was typed for another entry, where one form is drawn for whichever is being edited', () => {

        const shown = page([ form('group-form', [ text('name', 'Depot', 'Depot North') ], 'depot') ]);

        keepDrafts(asRoot(shown), null, () => {
            shown.forms = [ form('group-form', [ text('name', 'Yard') ], 'yard') ];
        });

        assert.equal(shown.forms[0]!.elements[0]!.value, 'Yard', 'the name typed for the depot, in the yard\'s form');

    });

    it('is drawn anew where it has neither an id nor a data-id, as it cannot be told from its neighbours', () => {

        const shown = page([ form('', [ text('label', '', 'typed') ]) ]);

        assert.deepEqual([ ...draftsIn(asRoot(shown), null).keys() ], []);

    });

});


describe('a form with a control named "id"', () => {

    it('is known by the id its attribute gives it, not by that control, and is the one saved when named', () => {

        const shown = page([ form('station-form', [ text('id', '', 'lc-station-7'), text('note', '') ]),
                             form('group-form',   [ text('name', 'Depot', 'Depot North') ]) ]);

        keepDrafts(asRoot(shown), 'group-form', () => {
            shown.forms = [ form('station-form', [ text('id', ''), text('note', '') ]),
                            form('group-form',   [ text('name', 'Depot North') ]) ];
        });

        assert.equal(shown.forms[0]!.elements[0]!.value, 'lc-station-7', 'the station typed and not added yet');

        assert.deepEqual([ ...draftsIn(asRoot(page([ form('station-form', [ text('id', '', 'lc-station-8') ]) ])), 'station-form').keys() ],
                         [], 'the form saved, named by its id');

    });

});


describe('a field nobody typed into', () => {

    it('is left as the page drew it anew, where the page wrote it hidden', () => {

        const shown = page([ form('group-form', [ hidden('version', '3'), text('name', 'Depot', 'Depot North') ]) ]);

        keepDrafts(asRoot(shown), null, () => {
            shown.forms = [ form('group-form', [ hidden('version', '4'), text('name', 'Depot') ]) ];
        });

        assert.deepEqual(shown.forms[0]!.elements.map(control => control.value), [ '4', 'Depot North' ],
                         'the node\'s version as it now is, and the name as it was typed');

    });

});
