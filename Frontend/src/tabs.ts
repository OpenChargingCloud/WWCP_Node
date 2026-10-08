/**
 * Tabs: one page in parts, of which one is shown at a time.
 *
 * Switched on the page and not by a navigation: every part is drawn and the
 * others are only hidden, so that what is typed into one - a certificate half
 * pasted - is still there when somebody looks at another and comes back. The
 * tab shown is kept in the address as ?tab=, replaced rather than pushed, so
 * that a reload or a link opens the page on it, and the Back button leaves the
 * page rather than walking through its tabs.
 *
 * A row of buttons with the roles of WAI-ARIA's tabs pattern: the arrow keys
 * move along the row, Home and End to its ends, and only the tab shown is in
 * the order Tab walks through.
 */

import { html, repeat, type TemplateResult } from './view';


/** One tab: what it is called in the address and the page, and its icon. */
export interface Tab {
    /** In the address and in the ids of its button and its panel: "upload". */
    id:     string;
    label:  string;
    /** A Font Awesome class. */
    icon?:  string;
}


/**
 * The tab a page opens on: the one the address names, where it is one of the
 * page's, and the first one otherwise.
 */
export function tabFromURL(Tabs:  readonly Tab[],
                           Url:   URL = new URL(location.href)): string {

    const named = Url.searchParams.get('tab');

    return Tabs.find(tab => tab.id === named)?.id ?? Tabs[0]!.id;

}


/**
 * Keep the tab shown in the address, replacing what it says - nothing for the
 * first tab, which is the page as it opens anyway.
 */
export function rememberTab(Tabs:  readonly Tab[],
                            Id:    string): void {

    const url = new URL(location.href);

    if (Id === Tabs[0]!.id)
        url.searchParams.delete('tab');
    else
        url.searchParams.set('tab', Id);

    if (url.href !== location.href)
        history.replaceState(history.state, '', url.pathname + url.search + url.hash);

}


/**
 * The row of tabs. Each button controls the panel with the id "panel-<id>",
 * which the page draws, hidden where its tab is not the one shown.
 */
export function tabsView(Tabs:     readonly Tab[],
                         Shown:    string,
                         Show:     (id: string) => void,
                         Label:    string): TemplateResult {

    function keyed(event: KeyboardEvent): void {

        const at   = Tabs.findIndex(tab => tab.id === Shown);
        const next = event.key === 'ArrowRight' ? (at + 1) % Tabs.length
                   : event.key === 'ArrowLeft'  ? (at - 1 + Tabs.length) % Tabs.length
                   : event.key === 'Home'       ? 0
                   : event.key === 'End'        ? Tabs.length - 1
                   :                              -1;

        if (next < 0)
            return;

        event.preventDefault();

        const id = Tabs[next]!.id;

        Show(id);

        (event.currentTarget as HTMLElement).ownerDocument.getElementById(`tab-${id}`)?.focus();

    }

    return html`
        <div class="tabs" role="tablist" aria-label="${Label}" @keydown=${keyed}>
            ${repeat(Tabs, tab => tab.id, tab => html`
                <button type="button"
                        role="tab"
                        class="tab ${tab.id === Shown ? 'active' : ''}"
                        id="tab-${tab.id}"
                        aria-selected="${tab.id === Shown ? 'true' : 'false'}"
                        aria-controls="panel-${tab.id}"
                        tabindex="${tab.id === Shown ? '0' : '-1'}"
                        @click=${() => Show(tab.id)}>
                    ${tab.icon ? html`<i class="fa-solid ${tab.icon}"></i> ` : ''}${tab.label}
                </button>
            `)}
        </div>
    `;

}
