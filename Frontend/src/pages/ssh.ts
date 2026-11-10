import { nodeAPI, type SSHAccessRule, type SSHConfiguration, type SSHUpdate } from '../api/client';
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
 * Whether the node's files are served over SFTP as well is saved the same way,
 * and does not move the server: the next session that asks is served or
 * refused, and the sessions of SFTP open end when it is switched off - which
 * the page asks about first.
 *
 * The access rules say who may sign in, from where and to which of the node's
 * addresses, and use what - the first that matches deciding, and never letting
 * in more than the accounts do anyway. They are edited as the command line's
 * sshAccessRules writes them, one a line, and saved the same way: in effect at
 * once, and asked again of every session open.
 *
 * Beside that, what a person looking after the node wants to compare or copy:
 * the host key, as a client shows it the first time and as a known_hosts file
 * takes it; the folders SFTP shows and what each needs; who is connected now;
 * the keys every account may sign in with; what the server allows; and what it
 * offers to encrypt with.
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
 * off or on, passwords or strict KEX told otherwise - which ends every session
 * over SSH.
 */
export function movesTheServer(Now: SSHConfiguration, Update: SSHUpdate): boolean {

    const enabled   = Now.commandLine.enabled ?? Update.enabled   ?? Now.enabled;
    const port      = Now.commandLine.port    ?? Update.port      ?? Now.port;
    const passwords = Update.passwords ?? Now.passwords;
    const strictKex = Update.strictKex ?? Now.strictKex;

    return enabled !== Now.enabled || (enabled && (port !== Now.port || passwords !== Now.passwords || strictKex !== Now.strictKex));

}

/**
 * How many sessions of SFTP a change ends by switching SFTP off - without
 * moving the server, which would end every session anyway.
 */
export function sftpSessionsEnding(Now: SSHConfiguration, Update: SSHUpdate): number {

    return Now.sftp && Update.sftp === false && !movesTheServer(Now, Update)
               ? Now.sessions.filter(session => session.kind === 'sftp').length
               : 0;

}


/**
 * A rule as the command line writes it, and as the node reads it back:
 * "deny principal=account:* service=shell local=10.10.0.1 # the device network".
 */
export function ruleLine(Rule: SSHAccessRule): string {

    return [
        Rule.action,
        ...(Rule.principal    !== undefined ? [ `principal=${Rule.principal}`           ] : []),
        ...(Rule.service      !== undefined ? [ `service=${Rule.service}`               ] : []),
        ...(Rule.source       !== undefined ? [ `source=${Rule.source.join(',')}`       ] : []),
        ...(Rule.localAddress !== undefined ? [ `local=${Rule.localAddress.join(',')}`  ] : []),
        ...(Rule.authMethod   !== undefined ? [ `auth=${Rule.authMethod.join(',')}`     ] : []),
        ...(Rule.comment      !== undefined ? [ `# ${Rule.comment}`                     ] : [])
    ].join(' ');

}

/**
 * The rules typed, one a line - empty lines left out - as the node is sent them.
 */
export function typedRules(Text: string): string[] {

    return Text.split(/\r?\n/).map(line => line.trim()).filter(line => line.length > 0);

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
                    ${accessRulesCard(ssh)}
                    ${hostKeysCard(ssh)}
                    ${sftpCard(ssh)}
                    ${sessionsCard(ssh)}
                    ${accountsCard(ssh)}
                    ${limitsCard(ssh)}
                    ${algorithmsCard(ssh)}
                </div>

            `);

        }


        /** Whether it runs, where, whether passwords open it and whether it serves SFTP - and the form that changes them. */
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
                              ? html`<span class="chip ok">serving</span> <code id="ssh-url">${ssh.url}</code>
                                     ${ssh.sftp ? html`<span class="chip ok" id="sftp-served">and SFTP</span>` : nothing}`
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

                        <label class="checkbox">
                            <input type="checkbox" name="strictKex" ?checked=${ssh.configured.strictKex ?? ssh.strictKex} ?disabled=${!mayChange} />
                            Turn away a client without strict KEX
                            <span class="hint">
                                Strict KEX keeps Terrapin (CVE-2023-48795) from cutting messages off the start of a connection.
                                OpenSSH has it since 9.6, PuTTY since 0.80; an older client is turned away before it signs in.
                            </span>
                        </label>

                        <label class="checkbox">
                            <input type="checkbox" name="sftp" ?checked=${ssh.configured.sftp ?? ssh.sftpByDefault} ?disabled=${!mayChange} />
                            Serve this ${config.nodeName}'s files over SFTP as well
                            <span class="hint">
                                The folders below, each as an account's roles let it read or write - and nothing else of the machine.
                                Off, a client asking for SFTP - sftp, scp, WinSCP - is refused.
                            </span>
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


        /** Who may sign in, from where and to where, and use what - and the form that changes it. */
        function accessRulesCard(ssh: SSHConfiguration): TemplateResult {

            const anybody = (Text: string) => html`<span class="muted">${Text}</span>`;

            return html`
                <section class="card" id="ssh-access-rules">

                    <h2><i class="fa-solid fa-filter"></i> Access rules</h2>

                    <p class="hint">
                        Who may sign in over SSH, from where and to which of this ${config.nodeName}'s addresses, and use what.
                        The first rule that matches decides; where none does, the accounts, their roles and keys decide alone.
                        A rule can only restrict: <code>allow</code> lets on to what the accounts let in anyway, <code>deny</code> refuses.
                    </p>

                    ${ssh.accessRules.length === 0
                          ? html`<p class="hint" id="no-access-rules">No rules: the accounts, their roles and keys decide alone.</p>`
                          : html`
                            <div class="table-scroll">
                              <table class="records" id="access-rules">
                                  <thead><tr><th>#</th><th>Does</th><th>Who</th><th>Service</th><th>From</th><th>To</th><th>Signed in with</th><th>Why</th></tr></thead>
                                  <tbody>
                                      ${ssh.accessRules.map((rule, at) => html`
                                          <tr data-rule="${at + 1}">
                                              <td>${at + 1}</td>
                                              <td><span class="chip ${rule.action === 'deny' ? 'bad' : 'ok'}">${rule.action}</span></td>
                                              <td>${rule.principal                ?? anybody('anybody')}</td>
                                              <td>${rule.service                  ?? anybody('everything')}</td>
                                              <td>${rule.source?.join(', ')       ?? anybody('anywhere')}</td>
                                              <td>${rule.localAddress?.join(', ') ?? anybody('any address')}</td>
                                              <td>${rule.authMethod?.join(', ')   ?? anybody('any way')}</td>
                                              <td>${rule.comment                  ?? nothing}</td>
                                          </tr>
                                      `)}
                                  </tbody>
                              </table>
                            </div>
                          `}

                    ${!mayChange ? nothing : html`
                        <form id="access-rules-form" class="form-stack" @submit=${onSaveRules}>

                            <label>The rules, one a line
                                <textarea name="rules" rows="${Math.max(4, ssh.accessRules.length + 2)}" spellcheck="false" autocomplete="off"
                                          .defaultValue=${ssh.accessRules.map(ruleLine).join('\n')}></textarea>
                                <span class="hint">
                                    As <code>sshAccessRules</code> writes them at the command line:
                                    <code>deny principal=account:* service=shell local=10.10.0.1 # the device network</code>.
                                    The conditions are <code>principal=</code>, <code>service=</code> (shell, sftp, subsystem:&lt;name&gt;),
                                    <code>source=</code> and <code>local=</code> (addresses or networks, separated by commas) and <code>auth=</code>.
                                </span>
                            </label>

                            <div class="form-actions">
                                <button type="submit" class="btn primary">Save the rules</button>
                                <span id="rules-note"  class="form-notice" role="status"></span>
                                <span id="rules-error" class="form-error"  role="alert"></span>
                            </div>

                        </form>
                    `}

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


        /** The folders SFTP shows, and what reading and writing each needs. */
        function sftpCard(ssh: SSHConfiguration): TemplateResult {

            return html`
                <section class="card" id="ssh-sftp">

                    <h2><i class="fa-solid fa-folder-tree"></i> Files over SFTP</h2>

                    <p class="hint">
                        ${ssh.sftp && ssh.enabled
                              ? 'Served: an account sees the folders its roles let it read or write, and nothing else.'
                              : 'Not served now. Switched on, an account sees the folders its roles let it read or write, and nothing else.'}
                        An upload is checked before it takes the place of anything.
                    </p>

                    ${ssh.sftpAreas.length === 0
                          ? html`<p class="hint">There is nothing to show: this ${config.nodeName} writes no log files, and has no folders of its own.</p>`
                          : html`
                            <div class="table-scroll">
                              <table class="records">
                                  <thead><tr><th>Folder</th><th>Read by</th><th>Written by</th></tr></thead>
                                  <tbody>
                                      ${repeat(ssh.sftpAreas, area => area.path, area => html`
                                          <tr data-sftp-area="${area.path}">
                                              <td><code>${area.path}</code></td>
                                              <td>${area.read  !== null ? html`whoever may <code>${area.read}</code>`  : 'anybody signed in'}</td>
                                              <td>${area.write !== null ? html`whoever may <code>${area.write}</code>` : 'nobody'}</td>
                                          </tr>
                                      `)}
                                  </tbody>
                              </table>
                            </div>
                          `}

                </section>
            `;

        }


        /** Who is connected now: at the command line, with SFTP, or with a subsystem the kind serves - an account, or one of the logins a kind lets in besides. */
        function sessionsCard(ssh: SSHConfiguration): TemplateResult {

            return html`
                <section class="card" id="ssh-sessions">

                    <h2><i class="fa-solid fa-users"></i> Sessions</h2>

                    ${ssh.sessions.length === 0
                          ? html`<p class="hint">Nobody is connected over SSH.</p>`
                          : html`
                            <div class="table-scroll">
                              <table class="records">
                                  <thead><tr><th>Who</th><th>At</th><th>From</th><th>Since</th><th>Key</th></tr></thead>
                                  <tbody>
                                      ${repeat(ssh.sessions, session => session.id, session => html`
                                          <tr data-session="${session.id}">
                                              <td>${session.account}${session.principal !== undefined && session.principal !== 'account'
                                                                          ? html` <span class="muted">(${session.principal})</span>`
                                                                          : nothing}</td>
                                              <td>${session.kind === 'sftp'      ? 'SFTP'
                                                  : session.kind === 'subsystem' ? html`${session.label ?? session.subsystem} <span class="muted">(${session.subsystem})</span>`
                                                  :                                'the command line'}</td>
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
                        <code>sshKeys</code>, or <code>--authorize-ssh-key</code> at a start - or by the account itself, on its
                        own page. A key switched off lets nobody in until it is switched on again.
                    </p>

                    ${withKeys.length === 0 ? html`<p class="hint">No account has a key yet, so nobody can sign in with one.</p>` : html`
                        <div class="table-scroll">
                          <table class="records">
                              <thead><tr><th>Account</th><th>Key</th><th>Called</th><th>Given</th></tr></thead>
                              <tbody>
                                  ${withKeys.flatMap(account => account.keys.map(key => html`
                                      <tr data-key="${key.fingerprint}">
                                          <td>${account.account}</td>
                                          <td>${key.algorithm}${key.isDisabled ? html` <span class="chip">off</span>` : nothing}<br /><code class="muted">${key.fingerprint}</code></td>
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
                        ${limits.byKind !== undefined ? html`
                        <dt>Of each kind</dt>            <dd id="ssh-limits-by-kind">${Object.entries(limits.byKind).map(([ kind, each ], n) => html`${n > 0 ? ', ' : ''}<span data-kind=${kind}>${kind} ${each.connections} of ${each.maxConnections}</span>`)} open - ssh.maxConnections</dd>` : ''}
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
                strictKex:  data.get('strictKex') !== null,
                sftp:       data.get('sftp')      !== null,
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

            const sftpSessions = sftpSessionsEnding(current!, update);

            if (sftpSessions > 0 &&
                !confirm(`SFTP is switched off for this, and ${sftpSessions} session(s) of it end.\n\nGo on?`))
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


        function onSaveRules(event: SubmitEvent): void {

            event.preventDefault();

            const form     = event.currentTarget as HTMLFormElement;
            const rules    = typedRules(String(new FormData(form).get('rules') ?? ''));
            const sessions = current!.sessions.length;

            if (sessions > 0 &&
                !confirm(`The rules are asked of the ${sessions} session(s) over SSH open now as well, and a session they refuse ends - yours too, if you are at the command line.\n\nGo on?`))
                return;

            void saveRules(rules, form);

        }


        async function saveRules(Rules: string[], form: HTMLFormElement): Promise<void> {

            const note = must<HTMLElement>(content, '#rules-note');

            note.textContent = '';
            must<HTMLElement>(content, '#rules-error').textContent = '';

            try
            {
                current = await whileSaving(content, note, () => api.ssh.save({ accessRules: Rules }));

                draw();
                form.reset();

                must<HTMLElement>(content, '#rules-note').textContent = current.notice ?? 'Saved, and in effect.';
            }
            catch (problem)
            {
                must<HTMLElement>(content, '#rules-error').textContent = errorMessage(problem);
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
                content.querySelector<HTMLFormElement>('#access-rules-form')?.reset();

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`
                        <div class="error-box">The SSH server could not be loaded: ${errorMessage(problem)}</div>
                    `);
            }

        }

        const release = unsaved.heldBy(() => typedSinceDrawn(content.querySelector('#ssh-form')) ||
                                             typedSinceDrawn(content.querySelector('#access-rules-form')));

        void load();

        return () => { cancelled = true; release(); };

    }

};
