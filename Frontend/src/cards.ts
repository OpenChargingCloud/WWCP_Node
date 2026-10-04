/**
 * The cards of a Configuration page: a section as the node sent it, and the
 * lines of what the node was built from.
 *
 * Every kind of node with such a page had card() and breakable() of its own,
 * seven of them byte for byte alike, and each showed a section's value that
 * is one thing of its own - the metrological log's path, key and head - as
 * JSON, since only a list of things was drawn as a block (found by the CSMS).
 * The lines of the Libraries card named an assembly beside every repository,
 * the first the node found of it, which beside WWCP_ISO15118 read as if
 * "cloud.charging.open.protocols.ISO15118.SDP" were all there was of it; the
 * vehicle's page was the first to name one only where it tells two lines
 * apart.
 *
 * cardViews.ts draws the same cards with view.ts, for a page that draws by
 * comparing; what a card shows is decided here, for both. This module stays
 * free of lit-html, which wants a document as it is loaded: the kinds'
 * Configuration pages, and their tests, load it without one.
 */

import { html, type HTMLFragment } from './html';
import { formatValue, humanizeKey } from './ui';


/**
 * One section: every field the node sent, in the order it sent them, with a
 * field that is itself a thing, or a list of things, drawn as a block of its
 * own below its name.
 *
 * Which sections a page shows, in which order and under which heading, is
 * the page's to say; what is in them is the node's.
 */
export function card(title:   string,
                     icon:    string,
                     values:  Record<string, unknown>,
                     extra?:  HTMLFragment): HTMLFragment {

    return html`
        <section class="card">

            <h2><i class="fa-solid ${icon}"></i> ${title}</h2>

            <div class="kv-list">

                ${extra ?? ''}

                ${fields(values ?? {})}

            </div>

        </section>
    `;

}


/**
 * The fields of a thing, a line each, and a field that is itself a thing or
 * a list of things as a block below its name - inside a block as well.
 *
 * Drawn one level deep, the charging station's 10BASE-T1S bus - a thing in
 * its V2G section - showed its thermal limits, and every node on the bus, as
 * a line of JSON: a card 1127 pixels high for two nodes (found by the station).
 */
function fields(values: Record<string, unknown>): HTMLFragment[] {

    return Object.entries(values).map(([key, value]) => {

        const things = thingsIn(value);

        return things !== null
            ? html`
                <div class="kv-nested">
                    <span class="k">${humanizeKey(key)}</span>
                    <div class="nested">
                        ${things.map(thing => html`
                            <div class="nested-item">
                                ${fields(thing)}
                            </div>
                        `)}
                    </div>
                </div>
            `
            : html`
                <div class="kv">
                    <span class="k">${humanizeKey(key)}</span>
                    <span class="v">${formatValue(value)}</span>
                </div>
            `;

    });

}


/**
 * The things a value is made of, each to be drawn as a block: the things of
 * a list of them, or the one thing a value is on its own. Null for a value
 * that is said in a line - a number, a word, a list of words, and an empty
 * thing, which the line says as "{}" rather than as a name over nothing.
 */
export function thingsIn(value: unknown): Record<string, unknown>[] | null {

    if (Array.isArray(value))
        return value.some(item => typeof item === 'object' && item !== null)
                   ? value as Record<string, unknown>[]
                   : null;

    if (typeof value === 'object' && value !== null && Object.keys(value).length > 0)
        return [ value as Record<string, unknown> ];

    return null;

}


/**
 * The names of the Libraries card's lines, and those of them that more than
 * one line shares - which are told apart by their assembly.
 */
export function libraryNames(lines: Record<string, unknown>[]): { names: string[]; shared: Set<string> } {

    const names = lines.map(line => formatValue(line.name));

    return { names, shared: new Set(names.filter((name, index) => names.indexOf(name) !== index)) };

}


/**
 * The Libraries card: one line per repository the node was built from, as
 * the node sends them, with its version and the whole commit - never
 * shortened, since it is read out of a bug report and pasted into a checkout.
 *
 * An assembly is named only where two lines share a repository's name and
 * would not say which is which without it, as the console's banner does it.
 */
export function librariesCard(lines: Record<string, unknown>[]): HTMLFragment {

    const { names, shared } = libraryNames(lines);

    return html`
        <section class="card">
            <h2><i class="fa-solid fa-cubes"></i> Libraries</h2>
            <div class="kv-list">
                ${lines.map((line, index) => html`
                    <div class="kv">
                        <span class="k">${breakable(names[index])}</span>
                        <span class="v">
                            ${formatValue(line.version)}
                            ${shared.has(names[index])
                                  ? html`<span class="muted small">${breakable(formatValue(line.assembly))}</span>`
                                  : ''}
                            ${typeof line.commit === 'string'
                                  ? html`<span class="muted small commit">${line.commit}</span>`
                                  : ''}
                        </span>
                    </div>
                `)}
            </div>
        </section>
    `;

}


/**
 * A dotted name that may break where somebody reading it would: after a dot
 * that ends a word, and after an underscore.
 *
 * A library's name has no space in it to break at, so a long one ran out of
 * its column and across the version beside it, and broke wherever the line
 * happened to end. A dot before a digit is inside a number - "2.1.1" stays
 * whole - and "WWCP_ISO15118" may break after its underscore.
 */
export function breakable(name: string): HTMLFragment {

    const parts = breakingParts(name);

    return html`${parts.map((part, index) => index < parts.length - 1
                                                 ? html`${part}<wbr>`
                                                 : html`${part}`)}`;

}


/** The parts of a dotted name, cut where breakable() lets it break. */
export function breakingParts(name: string): string[] {
    return name.split(/(?<=\.)(?=\D)|(?<=_)/);
}
