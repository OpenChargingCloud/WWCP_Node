import { webSocketLoginsAPI as api, type ClientAuthentication, type ClientTrust, type TrustedChain } from '../api/webSocketLogins';
import { auth } from '../auth';
import { loginServer } from '../settings';
import { must } from '../../html';
import { toURL } from '../../basePath';
import type { Page } from '../../router';
import { mayButNot, reloadButton, shell } from '../../shell';
import { errorMessage, field, formatTimestamp } from '../../ui';
import { anyFormTypedSinceDrawn, unsaved } from '../../unsaved';
import { html, live, nothing, render, repeat, type TemplateResult } from '../../view';

/**
 * Which chains the own certificate of a client of a WebSocket server of this
 * node may lead to - a charging station's, a registration authority's: see
 * loginServer() -, the other half of TLS, and the half that decides who gets
 * in under OCPP security profile 3.
 *
 * This list and nothing else: not the trust store of the operating system,
 * whose several hundred authorities are the ones the world trusts to vouch for
 * web sites, every one of which could issue a certificate for a charging
 * station that this controller would then believe. A charging station is
 * vouched for by whoever runs the charging network, and that is a list with one
 * or two entries on it.
 *
 * Drawn by view.ts: a draw changes only what differs, so that an authority
 * half pasted into the form outlives a chain switched off or removed.
 */
export const clientTrustPage: Page = {

    title: 'Accepted chains',

    render({ root }) {

        const ws       = loginServer();

        /** Security profile 3, where the server speaks of OCPP's profiles. */
        const profile  = ws.securityProfiles ? ' (security profile 3)' : '';

        const content = shell(root, {
            active:    ws.trustPage,
            title:     'Accepted chains',
            subtitle:  `Which certificate authorities a ${ws.login} may be vouched for by.`,
            actions:   reloadButton(() => load())
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        const mayManage = auth.can('certificates', 'edit');

        let cancelled = false;
        let trust:  ClientTrust             | null = null;
        let server: ClientAuthentication[]  | null = null;


        function draw(): void {

            if (trust === null || server === null)
                return;

            const store         = trust;
            const allowed       = server;

            render(content, html`

                ${mayManage ? nothing : html`
                    <div class="notice">
                        ${mayButNot('look at the accepted chains', 'change them')} Whoever may add one can let
                        in a ${ws.login} that nobody issued a password to.
                    </div>
                `}

                ${allowed.includes('tlsClientCertificate') ? nothing : html`
                    <div class="notice">
                        <a href="${toURL(ws.page)}">A TLS client certificate</a>${profile} is not allowed at the moment,
                        so nothing here is being used: no ${ws.login} is asked for a certificate.
                    </div>
                `}

                ${allowed.includes('tlsClientCertificate') && store.enabled === 0 ? html`
                    <div class="notice warn">
                        A TLS client certificate${profile} is allowed and no chain is accepted, so no ${ws.login} can connect
                        with a certificate. An empty list is "nobody", not "everybody".
                    </div>
                ` : nothing}

                <div class="cards">

                    <section class="card">

                        <h2><i class="fa-solid fa-plus"></i> Accept another</h2>

                        <form id="add-form" class="form-stack" @submit=${add}>

                            <label>What to call it
                                <input type="text" name="name" maxlength="100"
                                       placeholder="Our charging network" ?disabled=${!mayManage} />
                            </label>

                            <label>The certificate authority
                                <textarea name="pem" rows="6" placeholder="-----BEGIN CERTIFICATE-----&#10;..."
                                          ?disabled=${!mayManage}></textarea>
                            </label>

                            <span class="hint">
                                The authority whose ${ws.logins} should be let in, and any certificates below
                                it. Both can go in one file, the way they are usually handed out: the one that
                                nothing else here signed becomes the anchor, and the rest are kept to build chains
                                with - which is what lets in a ${ws.login} that does not send its own intermediates.
                            </span>

                            <div class="form-actions">
                                <button type="submit" class="btn primary" ?disabled=${!mayManage}>Accept it</button>
                                <span id="add-error" class="form-error" role="alert"></span>
                            </div>

                        </form>

                    </section>

                    <section class="card wide">

                        <h2><i class="fa-solid fa-user-shield"></i> Accepted</h2>

                        <p class="hint">
                            ${store.enabled} of ${store.entries.length} switched on, at most ${store.maxEntries}.
                            In ${store.directory}.
                        </p>

                        ${store.entries.length === 0
                              ? html`<p class="muted">No certificate authority has been named yet.</p>`
                              : repeat(store.entries, entry => entry.id, entry => entryCard(entry))}

                    </section>

                </div>
            `);

        }


        function entryCard(entry: TrustedChain): TemplateResult {

            return html`
                <div class="entry ${entry.enabled ? '' : 'dimmed'}">

                    <div class="entry-head">
                        <div>
                            <strong>${entry.name}</strong>
                            <code class="small">${entry.id}</code>
                            <span class="badge ${entry.state === 'valid' ? 'ok' : 'warn'}">${entry.state}</span>
                            ${entry.isCA ? nothing : html`<span class="badge warn">not an authority</span>`}
                        </div>
                        <div class="entry-actions">
                            <label class="switch small">
                                <input type="checkbox" class="trust-enabled" data-id="${entry.id}"
                                       .checked=${live(entry.enabled)}
                                       ?disabled=${!mayManage}
                                       @change=${(event: Event) => void setEnabled(entry.id, (event.target as HTMLInputElement).checked)} />
                                <span>${entry.enabled ? 'accepted' : 'switched off'}</span>
                            </label>
                            <button type="button" class="btn small danger trust-remove" data-id="${entry.id}"
                                    ?disabled=${!mayManage} @click=${() => void remove(entry.id)}>
                                Remove
                            </button>
                        </div>
                    </div>

                    <dl class="kv">
                        <dt>Subject</dt>
                        <dd>${entry.subject}</dd>

                        <dt>Issued by</dt>
                        <dd>${entry.issuer}</dd>

                        <dt>Valid until</dt>
                        <dd>
                            ${formatTimestamp(entry.notAfter)}
                            <span class="${entry.daysRemaining < 30 ? 'warn' : 'muted'}">
                                (${entry.daysRemaining} day(s))
                            </span>
                        </dd>

                        <dt>Intermediates kept</dt>
                        <dd>${entry.intermediates}</dd>

                        <dt>Added</dt>
                        <dd>${formatTimestamp(entry.addedAt)}</dd>

                        <dt>Thumbprint</dt>
                        <dd><code class="small">${entry.thumbprint}</code></dd>
                    </dl>

                    ${entry.warnings.length === 0 ? nothing : html`
                        <div class="notice warn">
                            <ul>${entry.warnings.map(warning => html`<li>${warning}</li>`)}</ul>
                        </div>
                    `}

                </div>
            `;

        }


        function add(event: SubmitEvent): void {

            event.preventDefault();

            const form = event.currentTarget as HTMLFormElement;

            void accept(form, field(form, 'pem', false), field(form, 'name'));

        }


        async function accept(form: HTMLFormElement, pem: string, name: string): Promise<void> {

            const error = must<HTMLElement>(content, '#add-error');
            error.textContent = '';

            try
            {

                const answer = await api.trust.add(pem, name);

                if (cancelled)
                    return;

                await load(false);

                // A draw leaves a form as it is typed into; this one was
                // taken in, so it is emptied.
                form.reset();

                if (answer.warnings.length > 0)
                    window.alert(`It was accepted, with something to say about it:\n\n${answer.warnings.join('\n\n')}`);

            }
            catch (problem)
            {
                if (!cancelled)
                    error.textContent = errorMessage(problem);
            }

        }


        async function setEnabled(id: string, enabled: boolean): Promise<void> {

            try
            {

                trust = await api.trust.update(id, { enabled });

                if (!cancelled)
                    draw();

            }
            catch (problem)
            {
                if (!cancelled)
                {
                    // The switch back to what the controller has: refused, it
                    // went on saying what had been clicked.
                    draw();
                    window.alert(errorMessage(problem));
                }
            }

        }


        async function remove(id: string): Promise<void> {

            if (!window.confirm(`Stop accepting ${ws.logins} vouched for by this authority? Every one under it will be turned away.`))
                return;

            try
            {

                trust = await api.trust.remove(id);

                if (!cancelled)
                    draw();

            }
            catch (problem)
            {
                if (!cancelled)
                    window.alert(errorMessage(problem));
            }

        }


        async function load(showLoading = true): Promise<void> {

            if (showLoading)
                render(content, html`<div class="loading">Loading ...</div>`);

            try
            {

                const [chains, configuration] = await Promise.all([
                    api.trust.get(),
                    api.allowed()
                ]);

                if (cancelled)
                    return;

                trust  = chains;
                server = configuration;

                draw();

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">${errorMessage(problem)}</div>`);
            }

        }


        // An authority pasted but not yet accepted is work like any other. The
        // switches in the list are in no form: they take effect when flipped.
        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        void load();

        return () => { cancelled = true; release(); };

    }

};
