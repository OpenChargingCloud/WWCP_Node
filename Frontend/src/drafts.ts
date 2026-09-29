/**
 * What somebody typed into the forms of a page, carried across the page
 * drawing itself anew.
 *
 * A page draws itself anew from the node's answer whenever something is done
 * on it - a form saved, an entry removed, a row opened for editing - and with
 * it every other form, which may hold what somebody typed and has not saved
 * yet. That was gone, and nobody was asked, because the page itself threw it
 * away: on the vehicle's pages, which were the first to keep it, and on the
 * pages of every other kind with more than one form, or with a form beside a
 * list. keepDrafts draws anew and puts back into every other form what was
 * typed into it: the form saved is drawn as the node now has it, the rest as
 * they were left - still typed into, so that leaving the page still asks
 * first.
 *
 * What a page shows because of what is typed - a remark beside a list, the
 * fields a box shows and lets be filled in - is drawn anew as the node's
 * answer has it, not as what is put back: putting a value back is not typing
 * it, and no input or change is sent for it, since a listener may save at
 * once what it is told of, as a switch in a list does. A page with such a
 * thing on a form that is not the one saved says it again after keepDrafts
 * (the local controller's remark on the kind of key to make); a field left
 * disabled that way is not sent by FormData at all (found by the e-mobility
 * provider and the hub).
 */

import { typedSinceDrawn } from './unsaved';


/** A form's control, as far as this needs one: what the DOM has, and what a test can stand in for. */
interface Control {
    tagName:   string;
    name:      string;
    type:      string;
    value:     string;
    checked:   boolean;
    options?:  ArrayLike<{ value: string; selected: boolean }>;
}

/**
 * A form, as far as this needs one. Its id is asked of its attributes: where a
 * form has a control named "id", as the local controller's form for a
 * station's login has, form.id is that control.
 */
interface Form {
    elements:      ArrayLike<unknown>;
    getAttribute:  (Name: string) => string | null;
}

/** What one control was left at. */
export interface Kept {
    name:      string;
    type:      string;
    value:     string;
    checked:   boolean;
    /** What is chosen, where it is a list. */
    selected:  string[] | null;
}


/**
 * The controls of a form that hold something typed: not its buttons, not a
 * file, which cannot be put back, and not a hidden field, which is what the
 * page drew and nobody typed - put back, it would say what the page said
 * before the node answered.
 */
function controlsOf(Form: Form): Control[] {
    return (Array.from(Form.elements) as Control[]).
               filter(control => [ 'INPUT', 'SELECT', 'TEXTAREA' ].includes(control.tagName) &&
                                 control.name !== '' &&
                                 ![ 'file', 'hidden', 'submit', 'reset', 'button', 'image' ].includes(control.type));
}

function formsIn(Root: ParentNode): Form[] {
    return Array.from(Root.querySelectorAll('form')) as unknown as Form[];
}

/**
 * What a form is known by from one drawing to the next: its id, and the entry
 * it is drawn for, its data-id, where it has one - so that a form drawn for
 * each entry of a list is known without an id, and the one form a page draws
 * for whichever entry is being edited is not given what was typed for
 * another. A form with neither cannot be told from its neighbours, and is
 * drawn anew.
 */
function nameOf(Form: Form): string | null {

    const id     = Form.getAttribute('id')      ?? '';
    const entry  = Form.getAttribute('data-id') ?? '';

    if (id === '' && entry === '')
        return null;

    return entry === '' ? id : `${id}[data-id=${entry}]`;

}

/** Whether a form is the one called Except: by its id, or, where it has none, by its data-id. */
function isCalled(Form: Form, Except: string | null): boolean {

    if (Except === null)
        return false;

    const id = Form.getAttribute('id') ?? '';

    return id !== '' ? id === Except : (Form.getAttribute('data-id') ?? '') === Except;

}


/** What is typed into every form in Root but the one called Except, by what each form is known by. */
export function draftsIn(Root: ParentNode, Except: string | null): Map<string, Kept[]> {

    const drafts = new Map<string, Kept[]>();

    for (const form of formsIn(Root)) {

        const name = nameOf(form);

        if (name === null || isCalled(form, Except) || !typedSinceDrawn(form as unknown as ParentNode))
            continue;

        drafts.set(name, controlsOf(form).map(control => ({
            name:      control.name,
            type:      control.type,
            value:     control.value,
            checked:   control.checked,
            selected:  control.tagName === 'SELECT'
                           ? Array.from(control.options ?? []).filter(option => option.selected).map(option => option.value)
                           : null
        })));

    }

    return drafts;

}


/**
 * Put what was typed back into the forms drawn anew, control by control. A
 * form drawn with other controls than it had is left as drawn: which of them
 * a value belonged to is no longer certain. A box or a radio button is the
 * same one only with the same value, which is what it stands for: boxes for
 * what another kind of certificate is for, as many as before, would have been
 * ticked as the boxes of the kind chosen before were (found by the meter).
 */
export function putBack(Root: ParentNode, Drafts: ReadonlyMap<string, readonly Kept[]>): void {

    for (const form of formsIn(Root)) {

        const name = nameOf(form);
        const kept = name !== null ? Drafts.get(name) : undefined;

        if (kept === undefined)
            continue;

        const controls = controlsOf(form);

        if (controls.length !== kept.length ||
            controls.some((control, index) => control.name !== kept[index]!.name ||
                                              control.type !== kept[index]!.type ||
                                              ((control.type === 'checkbox' || control.type === 'radio') &&
                                               control.value !== kept[index]!.value)))
            continue;

        controls.forEach((control, index) => {

            const was = kept[index]!;

            if (was.selected !== null)
                for (const option of Array.from(control.options ?? []))
                    option.selected = was.selected.includes(option.value);

            else if (control.type === 'checkbox' || control.type === 'radio')
                control.checked = was.checked;

            else
                control.value = was.value;

        });

    }

}


/**
 * Draw anew, and keep what is typed into every form in Root but the one called
 * Except - the form whose save is why the page is drawn anew, by its id, or
 * by its data-id where it has none; null where nothing was saved, as after an
 * entry was removed.
 */
export function keepDrafts(Root: ParentNode, Except: string | null, Draw: () => void): void {

    const drafts = draftsIn(Root, Except);

    Draw();

    putBack(Root, drafts);

}
