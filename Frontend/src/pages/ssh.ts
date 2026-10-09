import { nodeAPI, type SSHConfiguration, type SSHUpdate } from '../api/client';
import { auth } from '../auth';
import { config } from '../config';
import { must } from '../html';
import type { Page } from '../router';
import { mayButNot, reloadButton, shell } from '../shell';
import { errorMessage, whileSaving } from '../ui';
import { typedSinceDrawn, unsaved } from '../unsaved';
import { html, nothing, render, repeat, type TemplateResult } from '../view';

/**
 * The SSH server the command line is served over.
 *
 * Whether it runs, on which port and whether passwords open it is saved to
 * the configuration file and made at once: a new port is bound before the old
 * one is let go, and a port that is taken leaves the server where it was. A
 * session typed at over SSH ends when the server moves, which the page asks
 * about before it sends. A switch on the command line - --no-ssh, --ssh-port -
 * wins over the file, as it does at a start, and the page says so.
 *
 * Beside that, what a person looking after the node wants to compare or copy:
 * the host key, as a client shows it the first time and as a known_hosts file
 * takes it; who is connected now; the keys every account may sign in with;
 * what the server allows; and what it offers to encrypt with.
 */

const api = nodeAPI();

/**
 * When something began, as a person reads it: the date and the time, to the
 * minute, in this browser's time zone and words - as the log and every other
 * page say a moment. In UTC and unsaid, a session begun at 03:38 read 01:38
 * (found by the gateway). Made for each moment, because a format keeps the
 * time zone it was made in.
 */
export function when(Iso: string): string {

    const date = new Date(Iso);

    return Number.isNaN(date.getTime())
               ? Iso
               : new Intl.DateTimeFormat([], { dateStyle: 'medium', timeStyle: 'short' }).format(date);

}

/**
 * Whether a change of the settings moves the server - another port, switched
 * off or on, passwords told otherwise - which ends every session over SSH.
 */
export function movesTheServer(Now: SSHConfiguration, Update: SSHUpdate): boolean {

    const enabled   = Now.commandLine.enabled ?? Update.enabled   ?? Now.enabled;
    const port      = Now.commandLine.port    ?? Update.port      ?? Now.port;
    const passwords = Update.passwords ?? Now.passwords;

    return enabled !== Now.enabled || (enabled && (port !== Now.port || passwords !== Now.passwords));

}


export const sshPage: Page = {

    title: 'SSH server',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/ssh',
            title:     'SSH server',
            subtitle:  `The SSH server the command line of this ${config.nodeName} is served over.`,
            actions:   reloadButton(() => load())
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        const mayChange = auth.can('ssh', 'edit');

        let cancelled = false;
        let current: SSHConfiguration | null = null;


        function draw(): void {

            if (current === null)
                return;

            const ssh = current;

            render(content, html`

                ${mayChange ? nothing : html`
                    <div class="notice">
                        ${mayButNot('look at the SSH server', 'change it')}
                    </div>
                `}

                <div class="cards stacked">
                    ${settingsCard(ssh)}
                    ${hostKeysCard(ssh)}
                    ${sessionsCard(ssh)}
                    ${accountsCard(ssh)}
                    ${limitsCard(ssh)}
                    ${algorithmsCard(ssh)}
                </div>

            `);

        }


        /** Whether it runs, where, and whether passwords open it - and the form that changes them. */
        function settingsCard(ssh: SSHConfiguration): TemplateResult {

            const switches = [
                ...(ssh.commandLine.enabled === false ? [ html`<code>--no-ssh</code> keeps it off` ] : []),
                ...(ssh.commandLine.port    !== undefined ? [ html`<code>--ssh-port ${ssh.commandLine.port}</code> keeps it on that port` ] : [])
            ];

            return html`
                <section class="card" id="ssh-settings">

                    <h2><i class="fa-solid fa-terminal"></i> Server</h2>

                    <p class="ssh-state">
                        ${ssh.enabled && ssh.url !== null
                              ? html`<span class="chip ok">serving</span> <code id="ssh-url">${ssh.url}</code>`
                              : html`<span class="chip">off</span> The command line is not served over SSH.`}
                        <span class="muted" id="ssh-connections">${ssh.connections} connection(s) open</span>
                    </p>

                    ${switches.length === 0 ? nothing : html`
                        <div class="notice" id="command-line-wins">
                            The command line this ${config.nodeName} was started with wins over what is saved here:
                            ${switches.map((said, at) => html`${at > 0 ? '; ' : ''}${said}`)}. What is saved takes effect at
                            the next start without it.
                        </div>
                    `}

                    <form id="ssh-form" class="form-stack" @submit=${onSave}>

                        <label class="checkbox">
                            <input type="checkbox" name="enabled" ?checked=${ssh.configured.enabled ?? ssh.enabled} ?disabled=${!mayChange} />
                            Serve the command line over SSH
                        </label>

                        <label>Port
                            <input type="number" name="port" min="1" max="65535"
                                   value="${ssh.configured.port ?? ssh.port ?? ''}"
                                   placeholder="${ssh.defaultPort ?? ''}" ?disabled=${!mayChange} />
                            <span class="hint">
                                On ${ssh.listenAddress}${ssh.defaultPort !== null ? html` - ${ssh.defaultPort} where nothing says otherwise, 20000 above the web interface's` : nothing}.
                            </span>
                        </label>

                        <label class="checkbox">
                            <input type="checkbox" name="passwords" ?checked=${ssh.configured.passwords ?? ssh.passwords} ?disabled=${!mayChange} />
                            Let an account's password open it as well as its keys
                            <span class="hint">Off, only a key an account was given signs in - which a password typed somewhere else cannot give away.</span>
                        </label>

                        <div class="form-actions">
                            <button type="submit" class="btn primary" ?disabled=${!mayChange}>Save</button>
                            <span id="form-note"  class="form-notice" role="status"></span>
                            <span id="form-error" class="form-error"  role="alert"></span>
                        </div>

                        <span class="hint">Saved to <span class="path">${ssh.file}</span>, and in effect at once.</span>

                    </form>

                </section>
            `;

        }


        /** The host key, as a client compares it and as a known_hosts file takes it. */
        function hostKeysCard(ssh: SSHConfiguration): TemplateResult {

            return html`
                <section class="card" id="ssh-host-keys">

                    <h2><i class="fa-solid fa-key"></i> Host key</h2>

                    <p class="hint">
                        What a client is shown the first time it connects - PuTTY, OpenSSH - to compare before it
                        says yes. A new one would be another machine to every client that knew this one.
                    </p>

                    ${ssh.hostKeys.length === 0
                          ? html`<p class="hint">None yet: it is made the first time the SSH server runs.</p>`
                          : repeat(ssh.hostKeys, key => key.fingerprint, key => html`
                              <dl class="facts host-key" data-host-key="${key.fingerprint}">
                                  <dt>Type</dt>         <dd>${key.algorithm}</dd>
                                  <dt>Fingerprint</dt>  <dd><code class="fingerprint">${key.fingerprint}</code></dd>
                                  <dt>Kept in</dt>      <dd><span class="path">${key.file}</span></dd>
                                  <dt>known_hosts</dt>
                                  <dd>
                                      <code class="known-hosts">${key.knownHosts}</code>
                                      <button type="button" class="btn small" data-copy="known-hosts"
                                              @click=${(event: Event) => void copy(key.knownHosts, event.currentTarget as HTMLElement)}>Copy</button>
                                  </dd>
                                  <dt>Public key</dt>
                                  <dd>
                                      <code class="public-key">${key.publicKey}</code>
                                      <button type="button" class="btn small" data-copy="public-key"
                                              @click=${(event: Event) => void copy(key.publicKey, event.currentTarget as HTMLElement)}>Copy</button>
                                  </dd>
                              </dl>
                          `)}

                </section>
            `;

        }


        /** Who is connected to the command line now. */
        function sessionsCard(ssh: SSHConfiguration): TemplateResult {

            return html`
                <section class="card" id="ssh-sessions">

                    <h2><i class="fa-solid fa-users"></i> Sessions</h2>

                    ${ssh.sessions.length === 0
                          ? html`<p class="hint">Nobody is at the command line over SSH.</p>`
                          : html`
                            <div class="table-scroll">
                              <table class="records">
                                  <thead><tr><th>Account</th><th>From</th><th>Since</th><th>Key</th></tr></thead>
                                  <tbody>
                                      ${repeat(ssh.sessions, session => session.id, session => html`
                                          <tr data-session="${session.id}">
                                              <td>${session.account}</td>
                                              <td>${session.from}</td>
                                              <td>${when(session.since)}</td>
                                              <td>${session.key !== null ? html`<code>${session.key}</code>` : html`<span class="muted">a password</span>`}</td>
                                          </tr>
                                      `)}
                                  </tbody>
                              </table>
                            </div>
                          `}

                </section>
            `;

        }


        /** The keys every account may sign in with - and the accounts that have none. */
        function accountsCard(ssh: SSHConfiguration): TemplateResult {

            const withKeys    = ssh.accounts.filter(account => account.keys.length > 0);
            const withoutKeys = ssh.accounts.filter(account => account.keys.length === 0);

            return html`
                <section class="card" id="ssh-keys">

                    <h2><i class="fa-solid fa-id-badge"></i> Keys of the accounts</h2>

                    <p class="hint">
                        The public halves an account may sign in with. They are given on the command line -
                        <code>sshKeys</code>, or <code>--authorize-ssh-key</code> at a start.
                    </p>

                    ${withKeys.length === 0 ? html`<p class="hint">No account has a key yet, so nobody can sign in with one.</p>` : html`
                        <div class="table-scroll">
                          <table class="records">
                              <thead><tr><th>Account</th><th>Key</th><th>Called</th><th>Given</th></tr></thead>
                              <tbody>
                                  ${withKeys.flatMap(account => account.keys.map(key => html`
                                      <tr data-key="${key.fingerprint}">
                                          <td>${account.account}</td>
                                          <td>${key.algorithm}<br /><code class="muted">${key.fingerprint}</code></td>
                                          <td>${key.label ?? key.comment}${key.label !== null && key.comment.length > 0 ? html`<br /><span class="muted">${key.comment}</span>` : nothing}</td>
                                          <td>${when(key.created)}${key.createdBy !== null ? html`<br /><span class="muted">by ${key.createdBy}</span>` : nothing}</td>
                                      </tr>
                                  `))}
                              </tbody>
                          </table>
                        </div>
                    `}

                    ${withoutKeys.length === 0 ? nothing : html`
                        <p class="hint" id="accounts-without-keys">Without a key: ${withoutKeys.map(account => account.account).join(', ')}.</p>
                    `}

                </section>
            `;

        }


        /** What the server allows. */
        function limitsCard(ssh: SSHConfiguration): TemplateResult {

            const limits = ssh.limits;

            return html`
                <section class="card" id="ssh-limits">

                    <h2><i class="fa-solid fa-gauge"></i> Limits</h2>

                    <dl class="facts">
                        <dt>Signing in</dt>              <dd>within ${limits.loginGraceTime} s, at most ${limits.maxAuthTries} tries</dd>
                        <dt>Connections</dt>             <dd>at most ${limits.maxConnections}, ${limits.maxUnauthenticated} of them not signed in yet - ${limits.maxUnauthenticatedPerAddress} from one address</dd>
                        <dt>Sessions</dt>                <dd>at most ${limits.maxSessions} on a connection</dd>
                        <dt>Is the client still there</dt><dd>${limits.clientAliveInterval !== null ? `asked every ${limits.clientAliveInterval} s, let go after ${limits.clientAliveCountMax} unanswered` : 'never asked'}</dd>
                    </dl>

                </section>
            `;

        }


        /** What the server offers to agree on a key and to encrypt and sign with, in the order it prefers them. */
        function algorithmsCard(ssh: SSHConfiguration): TemplateResult {

            const lists: [ string, string[] ][] = [
                [ 'Key exchange',  ssh.algorithms.keyExchange ],
                [ 'Host key',      ssh.algorithms.hostKey     ],
                [ 'Encryption',    ssh.algorithms.cipher      ],
                [ 'Integrity',     ssh.algorithms.mac         ],
                [ 'Compression',   ssh.algorithms.compression ]
            ];

            return html`
                <section class="card" id="ssh-algorithms">

                    <h2><i class="fa-solid fa-shield-halved"></i> Algorithms</h2>

                    <p class="hint">What the server offers, the one it prefers first; a client takes the first it knows too.</p>

                    <dl class="facts">
                        ${lists.map(([ name, offered ]) => html`
                            <dt>${name}</dt>
                            <dd class="chips" data-algorithms="${name}">${offered.map(one => html`<span class="chip">${one}</span>`)}</dd>
                        `)}
                    </dl>

                </section>
            `;

        }


        /** Copy a line, and say so on the button for a moment. */
        async function copy(Text: string, Button: HTMLElement): Promise<void> {

            try
            {
                await navigator.clipboard.writeText(Text);
                Button.textContent = 'Copied';
            }
            catch
            {
                Button.textContent = 'Select it and copy';
            }

            setTimeout(() => { Button.textContent = 'Copy'; }, 2000);

        }


        function onSave(event: SubmitEvent): void {

            event.preventDefault();

            const form  = event.currentTarget as HTMLFormElement;
            const data  = new FormData(form);
            const typed = String(data.get('port') ?? '').trim();

            const update: SSHUpdate = {
                enabled:    data.get('enabled')   !== null,
                passwords:  data.get('passwords') !== null,
                // An emptied field is the port the file has, not none.
                ...(typed.length > 0 ? { port: Number(typed) } : {})
            };

            if (update.port !== undefined && !(Number.isInteger(update.port) && update.port >= 1 && update.port <= 65535)) {
                must<HTMLElement>(content, '#form-error').textContent = 'A port is a whole number from 1 to 65535.';
                return;
            }

            const sessions = current!.sessions.length;

            if (sessions > 0 && movesTheServer(current!, update) &&
                !confirm(`The SSH server starts anew for this, and ${sessions} session(s) over SSH end - yours too, if you are at the command line.\n\nGo on?`))
                return;

            void save(update, form);

        }


        async function save(update: SSHUpdate, form: HTMLFormElement): Promise<void> {

            const note = must<HTMLElement>(content, '#form-note');

            note.textContent = '';
            must<HTMLElement>(content, '#form-error').textContent = '';

            try
            {
                // The answer is the server as it now stands: the page shows what
                // the node made of it, not what the form sent.
                current = await whileSaving(content, note, () => api.ssh.save(update));

                draw();
                form.reset();

                must<HTMLElement>(content, '#form-note').textContent = current.notice ?? 'Saved, and in effect.';
            }
            catch (problem)
            {
                must<HTMLElement>(content, '#form-error').textContent = errorMessage(problem);
            }

        }


        async function load(): Promise<void> {

            try
            {

                const loaded = await api.ssh.get();

                if (cancelled)
                    return;

                current = loaded;

                // Loaded anew - Reload - is what the node has, the form too.
                draw();
                content.querySelector<HTMLFormElement>('#ssh-form')?.reset();

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`
                        <div class="error-box">The SSH server could not be loaded: ${errorMessage(problem)}</div>
                    `);
            }

        }

        const release = unsaved.heldBy(() => typedSinceDrawn(content.querySelector('#ssh-form')));

        void load();

        return () => { cancelled = true; release(); };

    }

};
