/*
 * A browser's document for a test that draws: lit-html draws into a real DOM,
 * and Node has none. happy-dom stands in, as the window and document of this
 * test file's process - Node's runner gives every test file a process of its
 * own, so nothing else sees it.
 *
 * Imported first, before anything that imports lit-html: lit-html looks for
 * the document as it is loaded.
 *
 *   import '../test/dom.ts';
 */

import { GlobalRegistrator } from '@happy-dom/global-registrator';

GlobalRegistrator.register({ url: 'http://127.0.0.1/' });


/**
 * What Chrome does and happy-dom does not, for as long as it is asked to: a
 * control in Root that is switched off while it has the focus loses it, and
 * nothing has it afterwards - which whileSaving() did to the field somebody
 * was typing into, on the DNS and the certificates pages (found by the
 * gateway). happy-dom's blur() leaves a disabled control as it is, so the
 * focus goes to a button that is then taken away.
 *
 *   const browser = chromeTakesTheFocus(root);
 *   ...
 *   browser.disconnect();
 */
export function chromeTakesTheFocus(Root: Node): MutationObserver {

    const browser = new MutationObserver(changes => {
        for (const { target } of changes)
            if (target === document.activeElement && (target as HTMLInputElement).disabled) {
                const away = document.createElement('button');
                document.body.append(away);
                away.focus();
                away.remove();
            }
    });

    browser.observe(Root, { subtree: true, attributes: true, attributeFilter: [ 'disabled' ] });

    return browser;

}
