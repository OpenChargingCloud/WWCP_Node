import { auth } from '../auth';
import { toURL } from '../basePath';
import { config } from '../config';
import { html, render, type HTMLFragment } from '../html';
import type { Page } from '../router';
import { shell, visibleMenu, type MenuEntry } from '../shell';

/**
 * What there is instead, under "There is no page at ...": the pages this
 * person may open - or, signed out, the sign-in, since what somebody may see
 * is what their role says and nobody has one yet. Links that would all have
 * bounced to the sign-in are one link to it.
 */
export function whatThereIs(Pages: readonly MenuEntry[] | null): HTMLFragment {

    if (Pages === null)
        return html`<a href="${toURL('/login')}">Sign in</a> to see what this ${config.nodeName} has.`;

    if (Pages.length === 0)
        return html`Nothing this ${config.nodeName} has is open to the account signed in here.`;

    return html`This ${config.nodeName} has
                ${Pages.map((entry, index) => html`${index > 0 ? ' and ' : ''}<a href="${toURL(entry.path)}">${entry.label}</a>`)}.`;

}

export const notFoundPage: Page = {

    title: 'Not found',

    render({ root, url }) {

        // Signed out, this page is all there is - no menu to put it in.
        const content = auth.user
                            ? shell(root, { active: '', title: 'Not found' })
                            : root;

        render(content, html`
            <section class="not-found">
                <p>There is no page at <code>${url.pathname}</code>.</p>
                <p class="muted">${whatThereIs(auth.user ? visibleMenu() : null)}</p>
            </section>
        `);

    }

};
