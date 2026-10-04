import { nodeAPI, type DNSConfiguration, type DNSQueryResult, type DNSServer, type DNSUpdate } from '../api/client';
import { auth } from '../auth';
import { config } from '../config';
import { html as stringHTML, must } from '../html';
import type { Page } from '../router';
import { mayButNot, shell } from '../shell';
import { errorMessage, formatValue, humanizeKey, numberField, numberFrom, whileSaving } from '../ui';
import { typedSinceDrawn, unsaved } from '../unsaved';
import { html, live, nothing, render, repeat, type TemplateResult } from '../view';
import { allServersTake, entryOf, isEncrypted, oneServerTakes, sentOf } from './dnsServers';
import { keysOf, pinsIn, saysAnything, withPins, type StoreOffers } from './pins';
import { certificateVerdictView, heldToView, judgementView, pinsFieldset, readPinsFieldset, shownView, storeOffers } from './pinViews';

/**
 * How this node resolves names.
 *
 * Everything on this page takes effect the moment it is saved, for everything
 * inside the node that resolves anything - the name servers included, which
 * are exchanged in the client rather than in a copy of it. Nothing here waits
 * for a restart.
 *
 * Switching name resolution off takes the servers away from the client, which
 * is what off means: a query then fails at once instead of quietly going to
 * whatever the machine happens to have configured.
 *
 * A name server asked over TLS or HTTPS shows a certificate, and its row says
 * what the node made of it and what it is held to; a dialog changes the
 * latter in the list on screen, which is saved with everything else.
 *
 * Drawn by view.ts: a draw changes only what differs, so what is typed into
 * the settings stays while the list of servers is edited above them, and the
 * other way round.
 */

const api = nodeAPI();

export const dnsPage: Page = {

    title: 'DNS client',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/dns',
            title:     'DNS client',
            subtitle:  `How this ${config.nodeName} resolves names.`,
            actions:   stringHTML`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        // Reload throws a draft away just as thoroughly as "Discard changes"
        // does, and from the opposite corner of the screen, so it asks first.
        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => {
            if (unsaved.mayBeLost())
                void load();
        });

        const mayChange  = auth.can('dns', 'edit');
        const mayTest    = auth.can('dns', 'run');

        let cancelled    = false;
        let current: DNSConfiguration | null = null;

        /** The servers on screen; edited as a list and sent as one value. */
        let servers: DNSServer[] = [];

        /**
         * Which row is which server's: a row keeps its server across a draw,
         * so that removing the one above does not leave what was typed into
         * this one in the row of the next.
         */
        const keys    = new WeakMap<DNSServer, number>();
        let   nextKey = 0;

        function keyOf(server: DNSServer): number {
            let key = keys.get(server);
            if (key === undefined)
                keys.set(server, key = nextKey++);
            return key;
        }

        /**
         * The roots and server certificates the store keeps for the name
         * servers, to be picked in a server's dialog and to name a pinned
         * fingerprint by - or null where this person may not read the store.
         */
        let offers: StoreOffers | null = null;

        /**
         * What was last typed into the test, and which record types are
         * picked: the dialog is made anew for every lookup, and these carry
         * from one to the next.
         */
        let testName: string = '';
        let testTypes: string[] = ['A', 'AAAA'];


        function draw(): void {

            if (current === null)
                return;

            const configuration = current;

            render(content, html`

                ${mayChange ? nothing : html`
                    <div class="notice">
                        ${mayButNot('look at the name resolution', 'change it')}
                    </div>
                `}

                <div class="cards stacked">

                    <section class="card">

                        <h2><i class="fa-solid fa-power-off"></i> Name resolution</h2>

                        <label class="switch">
                            <input type="checkbox" id="enabled"
                                   .checked=${live(configuration.enabled)}
                                   ?disabled=${!mayChange}
                                   @change=${(event: Event) => void save({ enabled: (event.target as HTMLInputElement).checked })} />
                            <span>${configuration.enabled ? 'switched on' : 'switched off'}</span>
                        </label>

                        <p class="hint">
                            Switched off, this ${config.nodeName} asks nobody: the name servers are taken away from
                            the client, so anything that tries to resolve a name fails at once and says
                            why, instead of falling back to whatever this machine has configured.
                        </p>

                    </section>

                    <section class="card" id="name-servers">
                        ${serversView(configuration)}
                    </section>

                    <section class="card">

                        <h2><i class="fa-solid fa-sliders"></i> Settings</h2>

                        <form id="dns-form" class="form-stack" @submit=${onSave}>

                            <label class="checkbox">
                                <input type="checkbox" name="useCache" ?checked=${configuration.settings.useCache} ?disabled=${!mayChange} />
                                Use the cache
                                <span class="hint">Answer from what was already asked, for as long as its time to live says.</span>
                            </label>

                            <label class="checkbox">
                                <input type="checkbox" name="dnssecOK" ?checked=${configuration.settings.dnssecOK} ?disabled=${!mayChange} />
                                DNSSEC OK
                                <span class="hint">Ask the server for the signatures, by setting the DO bit.</span>
                            </label>

                            <label class="checkbox">
                                <input type="checkbox" name="followCNAMEs" ?checked=${configuration.settings.followCNAMEs} ?disabled=${!mayChange} />
                                Follow CNAMEs
                            </label>

                            <label>Recursion desired
                                <select name="recursionDesired" ?disabled=${!mayChange}>
                                    <option value=""      ?selected=${configuration.settings.recursionDesired === null}>leave it to the server</option>
                                    <option value="true"  ?selected=${configuration.settings.recursionDesired === true}>yes</option>
                                    <option value="false" ?selected=${configuration.settings.recursionDesired === false}>no</option>
                                </select>
                            </label>

                            <label>Query timeout in seconds
                                <input type="number" name="queryTimeoutSeconds" min="0.1" max="${configuration.limits.maxQueryTimeout}"
                                       step="0.1" value="${configuration.settings.queryTimeoutSeconds}" ?disabled=${!mayChange} />
                            </label>

                            <label>Maximum CNAME follows
                                <input type="number" name="maxCNAMEFollows" min="0" max="255" value="${configuration.settings.maxCNAMEFollows}" ?disabled=${!mayChange} />
                            </label>

                            <label>Maximum retries
                                <input type="number" name="maxRetries" min="0" max="255" value="${configuration.settings.maxRetries}" ?disabled=${!mayChange} />
                            </label>

                            <div class="form-actions">
                                <button type="submit" class="btn primary" ?disabled=${!mayChange}>Save</button>
                                <span id="form-note"  class="form-notice" role="status"></span>
                                <span id="form-error" class="form-error"  role="alert"></span>
                            </div>

                            <span class="hint">Saved to <span class="path">${configuration.file}</span>, and in effect at once.</span>

                        </form>

                    </section>

                    <section class="card">

                        <h2><i class="fa-solid fa-vial"></i> Test</h2>

                        <p class="hint">
                            Ask for a name - or an address, which is turned around and asked as a reverse
                            lookup. Every step is written to the log, so the Logs page of anybody watching
                            shows it too.
                        </p>

                        <div class="form-actions">
                            <button type="button" class="btn primary" id="look-up" ?disabled=${!mayTest} @click=${() => lookUp(null)}>
                                Look something up
                            </button>
                        </div>

                        <p class="hint">
                            ${mayTest
                                  ? html`
                                        This asks the way the ${config.nodeName} asks for anything: all of the servers
                                        above at once, and the first usable answer wins. To find out what one
                                        particular server says, use the button on its own row.
                                    `
                                  : html`Looking something up needs a role that may run queries.`}
                        </p>

                    </section>

                    <section class="card">
                        <h2><i class="fa-solid fa-circle-info"></i> Fixed when the client was made</h2>
                        <div class="kv-list">
                            ${Object.entries(configuration.fixed).map(([key, value]) => html`
                                <div class="kv">
                                    <span class="k">${humanizeKey(key)}</span>
                                    <span class="v">${formatValue(value)}</span>
                                </div>
                            `)}
                        </div>
                        <p class="hint">Changing these means making another client, which means restarting the ${config.nodeName}.</p>
                    </section>

                </div>

            `);

        }


        /** The name servers, one row each - and under a row over TLS or HTTPS, its certificate. */
        function serversView(configuration: DNSConfiguration): TemplateResult {

            return html`

                <h2><i class="fa-solid fa-server"></i> Name servers</h2>

                <div class="server-list" id="servers">
                    ${servers.length === 0
                          ? html`<p class="muted small">No name server configured.</p>`
                          : repeat(servers, keyOf, (server, index) => serverView(server, index))}
                </div>

                <div class="form-actions">
                    <button type="button" id="add-server" class="btn"
                            ?disabled=${!mayChange || servers.length >= configuration.limits.maxServers}
                            @click=${addServer}>
                        Add a server
                    </button>
                    <span class="hint">At most ${configuration.limits.maxServers}. They are asked in parallel; the first usable answer wins.</span>
                </div>

            `;

        }


        /** One name server: its address, port and transport, and what can be done with it. */
        function serverView(server: DNSServer, index: number): TemplateResult {

            const configuration  = current!;
            const encrypted      = isEncrypted(server.transport);

            return html`
                <div class="server-entry">

                    <div class="server-row" data-index="${index}">
                        <input type="text" data-field="address" data-index="${index}"
                               value="${server.address}" placeholder="address or host name"
                               ?disabled=${!mayChange}
                               @input=${(event: Event) => { server.address = (event.target as HTMLInputElement).value; }} />
                        <input type="number" data-field="port" data-index="${index}"
                               value="${server.port ?? ''}" min="1" max="65535" class="port"
                               ?disabled=${!mayChange}
                               @input=${(event: Event) => { server.port = numberFrom((event.target as HTMLInputElement).value); }} />
                        <select data-field="transport" data-index="${index}" ?disabled=${!mayChange}
                                @change=${(event: Event) => changeTransport(server, (event.target as HTMLSelectElement).value)}>
                            ${configuration.limits.transports.map(transport => html`
                                <option value="${transport}" ?selected=${transport === server.transport}>${transport}</option>
                            `)}
                        </select>
                        ${encrypted
                              ? html`<button type="button" class="btn small" data-pins="${index}"
                                             title="What its certificate is held to" aria-label="What its certificate is held to"
                                             ?disabled=${!mayChange}
                                             @click=${() => editPins(server)}>
                                         <i class="fa-solid fa-certificate"></i>
                                     </button>`
                              : nothing}
                        <button type="button" class="btn small" data-ask="${index}"
                                title="Ask this server, and only this one"
                                ?disabled=${!mayTest}
                                @click=${() => lookUp(servers.indexOf(server))}>Test</button>
                        <button type="button" class="btn small danger" data-remove="${index}"
                                ?disabled=${!mayChange}
                                @click=${() => removeServer(server)}>Remove</button>
                    </div>

                    ${encrypted
                          ? certificateView(server)
                          : saysAnything(pinsIn(server))
                                ? html`<div class="server-certificate small">
                                           <span class="chip warn">
                                               held to a certificate, which ${server.transport} does not show: saved, it lets go of that
                                           </span>
                                       </div>`
                                : nothing}

                </div>
            `;

        }


        function addServer(): void {
            servers.push({ address: '', port: 53, transport: 'UDP', queryTimeoutSeconds: null });
            draw();
        }

        function removeServer(server: DNSServer): void {
            const index = servers.indexOf(server);
            if (index >= 0) {
                servers.splice(index, 1);
                draw();
            }
        }

        /** Drawn again, because whether a row has a certificate to show depends on it. */
        function changeTransport(server: DNSServer, transport: string): void {
            server.transport = transport;
            draw();
        }


        /**
         * What the node made of a server's certificate, and what the list on
         * screen holds it to.
         *
         * The node's word only for the server as the node has it: a row
         * whose address, port or transport was changed and not saved is
         * another server, whose certificate nobody has looked at yet.
         */
        function certificateView(server: DNSServer): TemplateResult {

            const saved    = asTheNodeHasIt(server);
            const pins     = pinsIn(server);
            const changed  = JSON.stringify(keysOf(pins)) !== JSON.stringify(keysOf(pinsIn(saved ?? {})));

            return html`
                <div class="server-certificate small">
                    ${saved === undefined
                          ? html`<span class="muted">not saved yet</span>`
                          : html`${certificateVerdictView(saved.judgement, saved.known)}
                                 ${shownView(saved.judgement, saved.known, offers?.nameOf)}`}
                    ${heldToView(pins, offers?.nameOf, changed)}
                </div>
            `;

        }


        /** The server as the node has it, where it has one at that address, port and transport. */
        function asTheNodeHasIt(server: DNSServer): DNSServer | undefined {

            return current?.servers.find(other => other.address   === server.address &&
                                                  other.port      === server.port    &&
                                                  other.transport === server.transport);

        }


        /**
         * Say what one server's certificate is held to, in a dialog - into the
         * list on screen, which "Save" below sends with everything else: the
         * list is one value to the node, and this is one more change to it.
         */
        function editPins(server: DNSServer): void {

            const saved   = asTheNodeHasIt(server);
            const name    = server.address.includes(':') ? `[${server.address}]:${server.port}` : `${server.address}:${server.port}`;
            const dialog  = document.createElement('dialog');

            dialog.className = 'test-dialog server-dialog';

            document.body.appendChild(dialog);

            /** Shut it and take it away - both, as not every browser fires "close". */
            const dismiss = (): void => { dialog.close(); dialog.remove(); };

            function take(event: SubmitEvent): void {

                event.preventDefault();

                const pins = readPinsFieldset(event.currentTarget as HTMLFormElement);

                if (pins.error !== undefined) {
                    must<HTMLElement>(dialog, '#pins-error').textContent = pins.error;
                    return;
                }

                const index = servers.indexOf(server);

                if (index >= 0) {
                    const held = withPins(server, pins.draft);
                    keys.set(held, keyOf(server));
                    servers[index] = held;
                }

                dismiss();
                draw();

            }

            render(dialog, html`

                <h2><i class="fa-solid fa-certificate"></i> ${name} over ${server.transport}</h2>

                <form id="pins-form" class="form-stack" @submit=${take}>

                    ${pinsFieldset(pinsIn(server), {
                          service:  'dns',
                          shown:    saved === undefined
                                        ? null
                                        : {
                                              name,
                                              certificate:  saved.judgement?.certificate ?? saved.known?.certificate ?? null,
                                              root:         saved.judgement?.root        ?? saved.known?.root        ?? null
                                          },
                          offers
                      })}

                    <div class="form-actions">
                        <button type="submit" class="btn primary">Take it into the list</button>
                        <button type="button" class="btn" id="pins-cancel" @click=${dismiss}>Cancel</button>
                        <span id="pins-error" class="form-error" role="alert"></span>
                    </div>

                    <span class="hint">The ${config.nodeName} is told when the list is saved, with "Save" under the settings.</span>

                </form>

            `);


            dialog.addEventListener('close',  dismiss);
            dialog.addEventListener('cancel', dismiss);

            dialog.showModal();

        }


        function onSave(event: SubmitEvent): void {

            event.preventDefault();

            const form = event.currentTarget as HTMLFormElement;
            const data = new FormData(form);
            const tri  = String(data.get('recursionDesired') ?? '');

            void save({
                // The servers travel with the settings, because the form is
                // where somebody presses Save after editing either - each
                // with what it is held to and what the page showed it held
                // to, and with nothing else of what the node
                // only said about it.
                servers:              servers.filter(server => server.address.trim().length > 0).map(sentOf),
                useCache:             data.get('useCache')     !== null,
                dnssecOK:             data.get('dnssecOK')     !== null,
                followCNAMEs:         data.get('followCNAMEs') !== null,
                recursionDesired:     tri === '' ? null : tri === 'true',
                // An emptied field is not given, which the node reads as
                // "keep what you have" - not 0, which it refuses for the
                // timeout, the whole save with it (the energy meter's).
                queryTimeoutSeconds:  numberField(form, 'queryTimeoutSeconds'),
                maxCNAMEFollows:      numberField(form, 'maxCNAMEFollows'),
                maxRetries:           numberField(form, 'maxRetries')
            }, form);

        }


        /**
         * Tell the node, and show what it took.
         *
         * @param form  the settings, where they were what was saved: drawn as
         *              the node now has them. The switch above them saves only
         *              itself, and leaves what is typed into the settings - and
         *              the list of servers as it is being edited - where it is.
         */
        async function save(update: DNSUpdate, form?: HTMLFormElement): Promise<void> {

            const note = must<HTMLElement>(content, '#form-note');

            note.textContent = '';

            must<HTMLElement>(content, '#form-error').textContent = '';

            try
            {
                // The answer is the whole configuration as it now stands, so
                // the page shows what the node took rather than what the
                // form sent.
                current = await whileSaving(content, note, () => api.dns.save(update));

                if (form !== undefined)
                    servers = current.servers.map(server => ({ ...server }));

                draw();

                // A draw leaves a form as it is typed into; this one was saved,
                // so it goes back to what it says now - the node's answer.
                form?.reset();

                must<HTMLElement>(content, '#form-note').textContent = 'Saved, and in effect.';
            }
            catch (problem)
            {
                must<HTMLElement>(content, '#form-error').textContent = errorMessage(problem);

                // A switch the node did not take shows what the node has.
                draw();
            }

        }


        /**
         * What came back, as it was shown on the page before this moved into a
         * dialog.
         *
         * A function rather than a block inside the dialog, because it is the
         * one part of this that is worth reading on its own: it is what
         * somebody actually looks at, and the dialog around it is plumbing.
         */
        function resultView(result: DNSQueryResult): TemplateResult {

            return html`
                <div class="query-result ${result.ok ? 'ok' : 'bad'}">

                    ${result.turnedAround ? html`<div class="notice">${result.turnedAround}</div>` : nothing}

                    <div class="kv-list">
                        <div class="kv"><span class="k">Asked for</span><span class="v">${result.name}</span></div>
                        <div class="kv"><span class="k">Record types</span><span class="v">${result.recordTypes.join(', ')}</span></div>
                        ${result.asked
                              ? html`<div class="kv"><span class="k">Asked of</span><span class="v">${result.asked}</span></div>`
                              : nothing}
                        ${result.error
                              ? html`<div class="kv"><span class="k">Error</span><span class="v">${result.error}</span></div>`
                              : html`
                                  <div class="kv"><span class="k">Response code</span><span class="v">${result.responseCode ?? '-'}</span></div>
                                  <div class="kv"><span class="k">Answered by</span><span class="v">${result.server ?? '-'}</span></div>
                                  <div class="kv"><span class="k">Took</span><span class="v">${result.runtime_ms ?? '-'} ms</span></div>
                                  ${result.dnssec ? html`<div class="kv"><span class="k">DNSSEC</span><span class="v">${result.dnssec}</span></div>` : nothing}
                              `}
                    </div>

                    ${result.answers.length === 0
                          ? html`<p class="muted small">No records came back.</p>`
                          : html`
                              <div class="table-scroll">
                                  <table class="records">
                                      <thead>
                                          <tr><th>Name</th><th>Type</th><th>TTL</th><th>Value</th></tr>
                                      </thead>
                                      <tbody>
                                          ${result.answers.map(record => html`
                                              <tr>
                                                  <td>${record.name}</td>
                                                  <td>${record.type}</td>
                                                  <td>${record.timeToLive}s</td>
                                                  <td class="value">${record.value}</td>
                                              </tr>
                                          `)}
                                      </tbody>
                                  </table>
                              </div>
                              ${result.more ? html`<p class="muted small">and ${result.more} more.</p>` : nothing}
                          `}

                    ${certificatesView(result)}

                </div>
            `;

        }

        /**
         * What was made of the certificate of every server the test reached
         * over TLS or HTTPS - the most likely reason such a server answered
         * nothing, and the one most worth seeing.
         *
         * A test of all servers asks over the connections the node keeps
         * open, and a certificate is looked at when a connection is made: where
         * none was, that is said rather than nothing.
         */
        function certificatesView(result: DNSQueryResult): TemplateResult | typeof nothing {

            const judged = result.certificates ?? [];

            if (judged.length > 0)
                return html`
                    <h3>Certificates</h3>
                    ${judged.map(judgement => judgementView(judgement, offers?.nameOf))}
                `;

            if (result.certificates !== undefined && !result.asked &&
                (current?.servers ?? []).some(server => isEncrypted(server.transport)))
                return html`
                    <p class="muted small">
                        No certificate was looked at: the connections to the name servers over TLS or HTTPS
                        were open already, and a certificate is looked at when a connection is made. The
                        Test of a server's own row makes a new one.
                    </p>
                `;

            return nothing;

        }

        /**
         * The lookup dialog, for all the servers at once or for one of them.
         *
         * A dialog rather than a card on the page, because a lookup is a
         * question somebody asks several times in a row with small changes -
         * another type, another name, the next server - and each answer is a
         * table. On the page that pushed the settings out of sight every time;
         * here the settings stay where they were and the answers replace each
         * other in one place.
         *
         * @param server  the place in the list of the one server to ask, or
         *                null to ask the way the node asks for anything.
         */
        function lookUp(server: number | null): void {

            if (current === null)
                return;

            const configuration = current;
            const asking        = server === null ? null : servers[server];

            if (server !== null && asking === undefined)
                return;

            const dialog = document.createElement('dialog');

            dialog.className = 'test-dialog';

            document.body.appendChild(dialog);

            /** Shut it and take it away - both, as not every browser fires "close". */
            const dismiss = (): void => { dialog.close(); dialog.remove(); };

            let asked: DNSQueryResult | null = null;
            let busy = false;

            function toggleType(recordType: string): void {

                testTypes = testTypes.includes(recordType)
                                ? testTypes.filter(other => other !== recordType)
                                : [...testTypes, recordType];

                paint();

            }

            function paint(): void {

                render(dialog, html`

                    <h2><i class="fa-solid fa-vial"></i> Look something up</h2>

                    <p class="hint">
                        ${asking === null
                              ? html`
                                    Asked the way this ${config.nodeName} asks for anything: all of the configured
                                    servers at once, and the first usable answer wins. If none of them
                                    answers at all, that takes ${allServersTake(current)} seconds to say so.
                                `
                              : html`
                                    Asked of <code>${asking!.address.includes(':')
                                                          ? `[${asking!.address}]:${asking!.port}`
                                                          : `${asking!.address}:${asking!.port}`}</code> over
                                    ${asking!.transport} and of nothing else, and without the cache - an
                                    answer somebody else already fetched says nothing about this server.
                                    One that does not answer at all takes
                                    ${oneServerTakes(current, server!)} seconds to say so.
                                `}
                    </p>

                    <form id="query-form" class="form-stack" @submit=${(event: SubmitEvent) => { event.preventDefault(); void ask(); }}>

                        <label>Name or address
                            <input type="text" name="name" placeholder="example.org" value="${testName}"
                                   ?disabled=${busy}
                                   @input=${(event: Event) => { testName = (event.target as HTMLInputElement).value; }} />
                            <span class="hint">
                                An address is turned around and asked as a reverse lookup, which is what
                                somebody typing one into this box means.
                            </span>
                        </label>

                        <div class="record-types">
                            <span class="k">Record types</span>
                            <div class="chips" id="record-types">
                                ${configuration.limits.recordTypes.map((recordType: string) => html`
                                    <button type="button" class="chip tag-button ${testTypes.includes(recordType) ? 'on' : ''}"
                                            data-type="${recordType}" aria-pressed="${testTypes.includes(recordType)}"
                                            ?disabled=${busy}
                                            @click=${() => toggleType(recordType)}>${recordType}</button>
                                `)}
                            </div>
                        </div>

                        <div class="form-actions">
                            <button type="submit" class="btn primary" ?disabled=${busy}>
                                ${busy ? 'Asking ...' : 'Ask'}
                            </button>
                            <button type="button" class="btn" id="query-close" @click=${dismiss}>Close</button>
                            <span id="query-error" class="form-error" role="alert"></span>
                        </div>

                    </form>

                    ${asked === null ? nothing : resultView(asked)}

                `);

            }

            async function ask(): Promise<void> {

                testName = must<HTMLInputElement>(dialog, 'input[name="name"]').value.trim();

                if (testName.length === 0) {
                    must<HTMLElement>(dialog, '#query-error').textContent = 'A name or an address is needed.';
                    return;
                }

                must<HTMLElement>(dialog, '#query-error').textContent = '';

                // The last answer goes the moment the next question is asked.
                // Left standing under "Asking ...", it read as the answer to
                // the new one - and when that one never came back, it went on
                // reading that way.
                asked = null;
                busy  = true;
                paint();

                try
                {
                    // One server's patience when one is asked, and the
                    // longest of them when all are: they are asked at once,
                    // so it does not add up.
                    asked = await api.dns.query(testName,
                                                testTypes,
                                                server === null
                                                    ? allServersTake(current)
                                                    : oneServerTakes(current, server),
                                                server ?? undefined);
                }
                catch (problem)
                {
                    asked = null;
                    busy  = false;
                    paint();
                    must<HTMLElement>(dialog, '#query-error').textContent = errorMessage(problem);
                    return;
                }

                busy = false;
                paint();

            }

            dialog.addEventListener('close',  dismiss);
            dialog.addEventListener('cancel', dismiss);

            paint();
            dialog.showModal();

            must<HTMLInputElement>(dialog, 'input[name="name"]').focus();

        }


        async function load(): Promise<void> {

            try
            {
                // The store beside the configuration and not after it: it only
                // names fingerprints and offers them in a server's dialog, and
                // a store this person may not read is no reason to show no page.
                const [ loaded, kept ] = await Promise.all([ api.dns.get(), storeOffers('dns') ]);

                if (cancelled)
                    return;

                current = loaded;
                offers  = kept;
                servers = loaded.servers.map(server => ({ ...server }));

                // Loaded anew - Reload - is what the node has, everywhere: the
                // settings too, which a draw on its own would leave as typed.
                draw();
                content.querySelector<HTMLFormElement>('#dns-form')?.reset();
            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`
                        <div class="error-box">The DNS configuration could not be loaded: ${errorMessage(problem)}</div>
                    `);
            }

        }

        // The settings are a form and answer for themselves; the name servers
        // are a list, kept in the page rather than in a form - so it is
        // compared with what the node last said, both as the node would be
        // told them: a pin changed in a dialog and changed back is no change,
        // whichever order its keys came in.
        const release = unsaved.heldBy(
                            () => typedSinceDrawn(content.querySelector('#dns-form')) ||
                                  JSON.stringify(servers.map(entryOf)) !== JSON.stringify((current?.servers ?? []).map(entryOf))
                        );

        void load();

        return () => { cancelled = true; release(); };

    }

};
