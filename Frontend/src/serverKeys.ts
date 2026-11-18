import { nodeAPI, type CertificateStore, type ListenerServerKeys, type ServerKey } from './api/client';
import { config } from './config';
import { errorMessage, formatTimestamp, whileSaving } from './ui';
import { html, nothing, repeat, type TemplateResult } from './view';
import type { CertificatesSection, SectionContext } from './pages/certificates';

/** The section, and whether it has anything to show: a page that keeps nothing says so, rather than show an empty card. */
export type ServerKeysSection<S extends CertificateStore = CertificateStore> = CertificatesSection<S> & { shows(): boolean };

const api = nodeAPI();

/**
 * The server keys of a node's listeners, on the "Server identities" page of
 * its store: keys the node made that a listener's clients may pin, each shown
 * in a self-signed carrier certificate made from it until - and after - a
 * certificate authority issues one for it.
 *
 * One card per listener: the key pin of its current key, which is what is
 * handed to the clients, and of the announced next one, which is handed to
 * them before anybody switches to it - and the switch, which names the next
 * key's pin as the page shows it, so that a key announced meanwhile by
 * somebody else is refused rather than switched to. What was issued for a key
 * stands among the identities of the page like every other, and here under
 * its key as well.
 *
 * A listener is shown where it has a server key, or goes on serving the last
 * certificate it showed, or where the kind of node offers it one - its station
 * port, say, by "listeners".
 */


/** What the section is told by the page. */
export interface ServerKeysOptions {
    /** The listeners a key may be made for although none has been - a gateway's "ocpp". */
    listeners?:  readonly string[];
    /** What a listener is called on the page: the service, see usageName. */
    name?(listener: string):  string;
}


/** The key pin as it is read out: in groups of eight, so that two of them can be compared by eye. */
export function groupedKeyPin(KeyPin: string): string {
    return KeyPin.replace(/(.{8})(?=.)/g, '$1 ');
}

/** What a listener's card says it shows now. */
export function shownText(Keys: ListenerServerKeys): string {

    if (Keys.shown === null)
        return 'Nothing: every connection to it is refused.';

    return `'${Keys.shown.label}'` +
           (Keys.shown.presentedAs === 'carrier' ? ', the carrier of its current key' : '') +
           (Keys.shown.keptOn                    ? ' - not valid, and shown all the same: nothing else is' : '') +
           '.';

}

/** A listener with no key, as the node would say it. */
function none(Listener: string): ListenerServerKeys {
    return { listener: Listener, keepsServingLast: false, current: null, next: null, shown: null, keys: [] };
}


/**
 * The section the "Server identities" page draws for the server keys - see
 * pages/certificates.ts, which adds it to that page of every node.
 */
export function serverKeysSection<S extends CertificateStore = CertificateStore>(Context:  SectionContext<S>,
                                                                                  Options:  ServerKeysOptions = {}): ServerKeysSection<S> {

    /** What the node said last, by listener; null where it could not be asked. */
    let known: ListenerServerKeys[] | null = null;

    const nameOf = (listener: string) => Options.name?.(listener) ?? listener;

    /** Every listener there is a card for, in the order of their names. */
    function listeners(): ListenerServerKeys[] {

        const byName = new Map((known ?? []).map(keys => [ keys.listener, keys ] as const));

        for (const offered of Options.listeners ?? [])
            if (!byName.has(offered))
                byName.set(offered, none(offered));

        return [ ...byName.values() ].sort((a, b) => a.listener.localeCompare(b.listener));

    }

    async function act(Listener: string, Doing: () => Promise<unknown>, Done: string): Promise<void> {

        const card   = Context.page.querySelector<HTMLElement>(`[data-server-keys="${Listener}"]`);
        const note   = card?.querySelector<HTMLElement>('[data-server-keys-note]') ?? null;
        const error  = card?.querySelector<HTMLElement>('[data-server-keys-error]') ?? null;

        if (error !== null)
            error.textContent = '';

        try
        {
            await whileSaving(Context.page, note, Doing);
            await Context.reload();
            Context.page.querySelector<HTMLElement>(`[data-server-keys="${Listener}"] [data-server-keys-note]`)?.replaceChildren(Done);
        }
        catch (e)
        {
            Context.page.querySelector<HTMLElement>(`[data-server-keys="${Listener}"] [data-server-keys-error]`)?.replaceChildren(errorMessage(e));
        }

    }

    function keyRow(Key: ServerKey): TemplateResult {

        const valid = Key.issued.filter(entry => entry.active && !entry.expired && !entry.notYetValid);

        return html`
            <tr data-server-key="${Key.id}" data-state="${Key.state}">
                <td>
                    <span class="chip ${Key.state === 'current' ? 'on' : Key.state === 'next' ? 'warn' : ''}">${Key.state}</span>
                </td>
                <td>
                    <code class="mono" data-key-pin="${Key.keyPin}" title="${Key.keyPinCurl}">${groupedKeyPin(Key.keyPin)}</code>
                    <div class="muted small">${Key.algorithm}, made ${formatTimestamp(Key.createdAt)}${Key.currentSince !== null ? html`, current since ${formatTimestamp(Key.currentSince)}` : nothing}</div>
                </td>
                <td data-issued="${Key.issued.length}">
                    ${Key.issued.length === 0
                          ? html`<span class="muted">none issued: shown in its carrier</span>`
                          : html`${Key.issued.length} issued, ${valid.length} valid now`}
                </td>
            </tr>
        `;

    }

    function card(Keys: ListenerServerKeys): TemplateResult {

        const current   = Keys.keys.find(key => key.state === 'current') ?? null;
        const next      = Keys.keys.find(key => key.state === 'next')    ?? null;
        const may       = Context.mayChange;

        return html`
            <section class="card" data-server-keys="${Keys.listener}">

                <h2><i class="fa-solid fa-key"></i> Server keys of ${nameOf(Keys.listener)}</h2>

                <p class="hint">
                    A key its clients may pin, shown in a certificate made from it where no certificate issued for it
                    is valid. A new key is announced as the next one first, and its key pin handed to the clients,
                    before anybody switches to it: a key never takes the place of what is shown by itself.
                    ${Keys.keepsServingLast ? html`Where nothing is valid, it goes on showing what it showed last.` : nothing}
                </p>

                <dl class="kv">
                    <dt>Shows</dt>         <dd data-shown>${shownText(Keys)}</dd>
                    <dt>Current key</dt>   <dd>${current !== null ? html`<code class="mono" data-current-pin>${groupedKeyPin(current.keyPin)}</code>` : html`<span class="muted">none</span>`}</dd>
                    <dt>Next key</dt>      <dd>${next    !== null ? html`<code class="mono" data-next-pin>${groupedKeyPin(next.keyPin)}</code>`       : html`<span class="muted">none announced</span>`}</dd>
                </dl>

                ${Keys.keys.length > 0 ? html`
                    <table class="table">
                        <thead><tr><th>State</th><th>Key pin</th><th>Certificates</th></tr></thead>
                        <tbody>${repeat(Keys.keys, key => key.id, key => keyRow(key))}</tbody>
                    </table>
                ` : nothing}

                <div class="form-actions">
                    ${current === null && Keys.keys.length === 0 && Keys.shown === null ? html`
                        <button type="button" class="btn small" data-make-server-key ?disabled=${!may}
                                @click=${() => void act(Keys.listener, () => api.certificates.serverKeys.create(Keys.listener, {}), 'The server key was made.')}>
                            Make the server key
                        </button>
                    ` : next === null ? html`
                        <button type="button" class="btn small" data-announce-next-key ?disabled=${!may}
                                @click=${() => void act(Keys.listener, () => api.certificates.serverKeys.create(Keys.listener, { asNext: true }), 'The next key was announced: hand its key pin to the clients.')}>
                            Announce a next key
                        </button>
                    ` : html`
                        <button type="button" class="btn small danger" data-switch-to-next-key ?disabled=${!may}
                                title="Clients that pinned only the current key are refused from their next connection on"
                                @click=${() => void act(Keys.listener, () => api.certificates.serverKeys.switchTo(Keys.listener, next.keyPin), 'Switched to the next key.')}>
                            Switch to the next key
                        </button>
                    `}
                    <span class="form-notice" role="status" data-server-keys-note></span>
                    <span class="form-error"  role="alert"  data-server-keys-error></span>
                </div>

                ${may ? nothing : html`<p class="hint">Making a key and switching are for whoever may change the certificates of this ${config.nodeName}.</p>`}

            </section>
        `;

    }

    return {

        below:  'presents',
        page:   'serverIdentities',

        shows:  () => listeners().length > 0,

        // A node that cannot say - an older one, or a refusal - is shown no
        // server keys, and the rest of the page all the same.
        load:   async () => {
                    try         { known = (await api.certificates.serverKeys.all()).listeners; }
                    catch (_)   { known = null; }
                },

        draw:   () => {

                    const all = listeners();

                    return all.length === 0
                               ? html``
                               : html`<div data-server-keys-section>${repeat(all, keys => keys.listener, keys => card(keys))}</div>`;

                }

    };

}
