/**
 * A box for certificates as text: typed or pasted into, pasted with a button,
 * and dropped files on - each of which the page turns into text of its own,
 * by asking its node what is in it.
 *
 * Text is what the box holds and what is sent: a PEM can be read, compared
 * and corrected where it was pasted, and a PKCS#12 or a DER file dropped on
 * the box becomes PEM in it, so that what is about to be imported is what is
 * on the screen. Its private keys included, where they came along: the box is
 * not autocompleted, spell-checked or remembered by the browser, and the page
 * empties it once its certificates are in.
 *
 * The Paste button reads the clipboard, which a browser allows on a secure
 * origin only - not a node reached at a LAN address over plain HTTP. There the
 * button says so, and Ctrl+V into the box works as it always does.
 */

import { html, type TemplateResult } from './view';


/** What a page says to a box: where it is, and what to do with what arrives. */
export interface PemBoxOptions {
    /** The id of the textarea. */
    id:            string;
    /** Its name in the form. */
    name:          string;
    rows?:         number;
    placeholder?:  string;
    /** What the file chooser offers. */
    accept?:       string;
    /** Files chosen or dropped: the page reads them, and puts what it finds into the box with appendText(). */
    onFiles:       (files: File[], box: HTMLTextAreaElement) => void | Promise<void>;
    /** Something in the box changed: typed, pasted, dropped or appended. */
    onChanged?:    (box: HTMLTextAreaElement) => void;
}


/**
 * Add text to the end of a box, on a line of its own, and say so as typing
 * would: an "input" event, which a page's draft and its preview listen to.
 */
export function appendText(Box:   HTMLTextAreaElement,
                           Text:  string): void {

    const text = Text.trim();

    if (text.length === 0)
        return;

    const before = Box.value.replace(/\s+$/, '');

    Box.value = (before.length > 0 ? before + '\n' : '') + text + '\n';

    Box.dispatchEvent(new Event('input', { bubbles: true }));

}


/**
 * The clipboard's text, put at the end of the box - or why it could not be
 * read, as the sentence to show beside the button.
 */
export async function pasteInto(Box: HTMLTextAreaElement): Promise<string> {

    try
    {

        const text = await navigator.clipboard.readText();

        if (text.trim().length === 0)
            return 'The clipboard holds no text.';

        appendText(Box, text);

        return 'Pasted.';

    }
    catch
    {

        Box.focus();

        return 'This browser will not let the page read the clipboard here - press Ctrl+V in the box.';

    }

}


/** The box, its Paste button and its file chooser, and what they do. */
export function pemBox(Options: PemBoxOptions): TemplateResult {

    function boxOf(element: Element): HTMLTextAreaElement {
        return element.closest('.pem-box')!.querySelector<HTMLTextAreaElement>('textarea')!;
    }

    function noteOf(element: Element): HTMLElement {
        return element.closest('.pem-box')!.querySelector<HTMLElement>('[data-pem-note]')!;
    }

    function over(event: DragEvent): void {
        event.preventDefault();
        (event.currentTarget as HTMLElement).classList.add('dropping');
        if (event.dataTransfer)
            event.dataTransfer.dropEffect = 'copy';
    }

    function left(event: DragEvent): void {
        (event.currentTarget as HTMLElement).classList.remove('dropping');
    }

    function dropped(event: DragEvent): void {

        event.preventDefault();

        const zone  = event.currentTarget as HTMLElement;
        const box   = boxOf(zone);

        zone.classList.remove('dropping');

        const files = Array.from(event.dataTransfer?.files ?? []);

        if (files.length > 0) {
            void Options.onFiles(files, box);
            return;
        }

        // Text dragged from somewhere else - a mail, an editor - is text to
        // keep, at the end, as a file's would be.
        const text = event.dataTransfer?.getData('text/plain') ?? '';

        if (text.trim().length > 0)
            appendText(box, text);

    }

    function chosen(event: Event): void {

        const input = event.currentTarget as HTMLInputElement;
        const files = Array.from(input.files ?? []);

        // Chosen again, the same file is another change.
        input.value = '';

        if (files.length > 0)
            void Options.onFiles(files, boxOf(input));

    }

    async function paste(event: Event): Promise<void> {

        const button = event.currentTarget as HTMLElement;

        noteOf(button).textContent = await pasteInto(boxOf(button));

    }

    return html`
        <div class="pem-box" @dragover=${over} @dragenter=${over} @dragleave=${left} @drop=${dropped}>

            <textarea id="${Options.id}"
                      name="${Options.name}"
                      rows="${Options.rows ?? 10}"
                      spellcheck="false"
                      autocomplete="off"
                      autocapitalize="off"
                      autocorrect="off"
                      placeholder="${Options.placeholder ?? '-----BEGIN CERTIFICATE-----'}"
                      @input=${(event: Event) => Options.onChanged?.(event.currentTarget as HTMLTextAreaElement)}></textarea>

            <div class="pem-box-actions">
                <button type="button" class="btn small" data-paste @click=${(event: Event) => void paste(event)}>
                    <i class="fa-solid fa-paste"></i> Paste
                </button>
                <label class="btn small file-button">
                    <i class="fa-solid fa-folder-open"></i> Files ...
                    <input type="file" multiple hidden data-files accept="${Options.accept ?? '.pem,.crt,.cer,.der,.p12,.pfx,.key'}" @change=${chosen} />
                </label>
                <span class="hint">or drop files on the box</span>
                <span class="form-notice" role="status" data-pem-note></span>
            </div>

        </div>
    `;

}
