/**
 * The cards of a Configuration page, drawn with view.ts: what cards.ts draws
 * with html.ts, for a page that draws by comparing - its extra a template of
 * view.ts, not a fragment of html.ts.
 *
 * Which fields there are, what is drawn as a block and which libraries are
 * named by their assembly is decided in cards.ts, for both; only the markup
 * is said twice, and cardViews.test.ts holds the two to drawing the same.
 * cards.ts goes once no page draws with html.ts any more.
 */

import { breakingParts, libraryNames, thingsIn } from './cards';
import { formatValue, humanizeKey } from './ui';
import { html, nothing, type TemplateResult } from './view';


/** One section, as card() draws it. */
export function cardView(title:   string,
                         icon:    string,
                         values:  Record<string, unknown>,
                         extra?:  TemplateResult): TemplateResult {

    return html`
        <section class="card">

            <h2><i class="fa-solid ${icon}"></i> ${title}</h2>

            <div class="kv-list">

                ${extra ?? nothing}

                ${fieldsView(values ?? {})}

            </div>

        </section>
    `;

}


/** The fields of a thing, as cards.ts's fields() draws them. */
function fieldsView(values: Record<string, unknown>): TemplateResult[] {

    return Object.entries(values).map(([key, value]) => {

        const things = thingsIn(value);

        return things !== null
            ? html`
                <div class="kv-nested">
                    <span class="k">${humanizeKey(key)}</span>
                    <div class="nested">
                        ${things.map(thing => html`
                            <div class="nested-item">
                                ${fieldsView(thing)}
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


/** The Libraries card, as librariesCard() draws it. */
export function librariesCardView(lines: Record<string, unknown>[]): TemplateResult {

    const { names, shared } = libraryNames(lines);

    return html`
        <section class="card">
            <h2><i class="fa-solid fa-cubes"></i> Libraries</h2>
            <div class="kv-list">
                ${lines.map((line, index) => html`
                    <div class="kv">
                        <span class="k">${breakableView(names[index]!)}</span>
                        <span class="v">
                            ${formatValue(line.version)}
                            ${shared.has(names[index]!)
                                  ? html`<span class="muted small">${breakableView(formatValue(line.assembly))}</span>`
                                  : nothing}
                            ${typeof line.commit === 'string'
                                  ? html`<span class="muted small commit">${line.commit}</span>`
                                  : nothing}
                        </span>
                    </div>
                `)}
            </div>
        </section>
    `;

}


/** A dotted name that may break where breakable() lets it. */
export function breakableView(name: string): TemplateResult {

    const parts = breakingParts(name);

    return html`${parts.map((part, index) => index < parts.length - 1
                                                 ? html`${part}<wbr>`
                                                 : html`${part}`)}`;

}
