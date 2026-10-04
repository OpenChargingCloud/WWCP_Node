import { nodeAPI, type Clock, type NTSConfiguration, type NTSServerEntry, type NTSServerResult, type NTSSyncResult, type NTSTimeSource, type NTSUpdate, type TimeServerTest } from '../api/client';
import { auth } from '../auth';
import { config } from '../config';
import { must } from '../html';
import type { Page } from '../router';
import { mayButNot, reloadButton, shell } from '../shell';
import { errorMessage, formatValue, humanizeKey, numberField, whileSaving } from '../ui';
import { typedSinceDrawn, unsaved } from '../unsaved';
import { html, live, nothing, render, repeat, type TemplateResult } from '../view';
import { nameTaken, readable, sentOf, withServer, withoutServer, type UsualPorts } from './ntsServers';
import { asShown, draftOf, withPins, type StoreOffers } from './pins';
import { certificateVerdictView, heldToView, pinsFieldset, readPinsFieldset, storeOffers } from './pinViews';

/**
 * What the NTS client allows itself when the node has not been told.
 *
 * The node's answer carries the timeout it was configured with, and null
 * where it was configured with none - and it does not repeat what the client
 * then falls back to, which is three seconds. This is only used to work out
 * how long this page waits for a test, and the page allows the node
 * fifteen seconds on top of it, so being wrong here by a few seconds costs
 * nothing at all.
 */
const theClientsOwnTimeout = 3;

const api = nodeAPI();


/**
 * Where this node reads the time: its time servers, and the rules for
 * believing them.
 *
 * The page is the group, because the group is what the clock is checked
 * against. It used to lead with a form for one server "for the detailed test"
 * - and saving that form told the node a lone host name, which it
 * read as a group of one: four servers went down to the one in the form. Now
 * each server is a row with a Test of its own and an Edit, the group is added
 * to at the end of its list, and what the group is held to is a form of its
 * own below it.
 *
 * The cards stand one under the other, read from the top down: what the clock
 * is worth, whether, who, by which rules - and last "Sync now", which puts all
 * of that to work, with what came of it.
 *
 * Every change takes effect at once, and the node is told the whole list
 * each time - which is why the list is only ever changed by exactly one server
 * at a time, from a dialog, and why a change the node refuses leaves the
 * page as it was.
 *
 * Drawn by view.ts: a draw changes only what differs, so that what somebody
 * is typing into the group's policy, or into what counts as legal time, is
 * still there - with its focus - when "Sync now" answers, a server is saved or
 * the other form is.
 */
export const ntsPage: Page = {

    title: 'NTS client',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/nts',
            title:     'NTS client',
            subtitle:  `Where this ${config.nodeName} reads the time, and how it knows the answer is real.`,
            actions:   reloadButton(() => load())
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        const mayChange = auth.can('nts', 'edit');
        const mayTest   = auth.can('nts', 'run');

        let cancelled = false;
        let current: NTSConfiguration | null = null;
        let clock:   Clock            | null = null;
        let syncing = false;

        /**
         * The roots and server certificates the store keeps for the time
         * servers, to be picked in a server's dialog and to name a pinned
         * fingerprint by - or null where this person may not read the store.
         */
        let offers: StoreOffers | null = null;


        /** The ports a server is asked on unless its entry says otherwise. */
        function usualPorts(): UsualPorts {
            return {
                ntsKE:  current?.limits.defaultNTSKEPort ?? 4460,
                ntp:    current?.limits.defaultNTPPort   ?? 123
            };
        }

        /**
         * The list as the node has it, as entries it can be told
         * again - each with what the page showed it held to.
         */
        function entries(): NTSServerEntry[] {
            const usual = usualPorts();
            return (current?.timeSources ?? []).map(source => sentOf(source, usual));
        }


        /** The whole page, from what the node last said. */
        function draw(): void {

            if (current === null)
                return;

            const configuration = current;

            render(content, html`

                ${mayChange ? nothing : html`
                    <div class="notice">
                        ${mayButNot('look at the time servers', 'change them')}
                    </div>
                `}

                <div class="cards stacked">

                    <section class="card" id="nts-clock" ?hidden=${clock === null}>${clock === null ? nothing : clockView(clock)}</section>

                    <section class="card" id="nts-switch">${switchView(configuration)}</section>

                    <section class="card" id="nts-servers">${serversView(configuration)}</section>

                    <section class="card" id="nts-policy">${policyView(configuration)}</section>

                    <section class="card" id="nts-legal">${legalView(configuration)}</section>

                    <section class="card">
                        <h2><i class="fa-solid fa-scale-balanced"></i> Cookie pool policy</h2>

                        <p class="hint">
                            What any new client starts with. Fixed in the client, not in the configuration.
                        </p>
                        <div class="kv-list">
                            ${Object.entries(configuration.policy).map(([key, value]) => html`
                                <div class="kv">
                                    <span class="k">${humanizeKey(key)}</span>
                                    <span class="v">${formatValue(value)}</span>
                                </div>
                            `)}
                        </div>
                    </section>

                    <section class="card" id="nts-sync">${syncView()}</section>

                </div>

            `);

        }


        /**
         * What time it is here and what that is worth.
         *
         * Every word of the verdict comes from the node: whether a time
         * may be called legal depends on a claim its operator made and on how
         * the last check went, and a page that worked that out for itself
         * would sooner or later say "legal" where the node says nothing
         * of the kind.
         */
        function clockView(now: Clock): TemplateResult {

            const why: Record<string, string> = {
                notClaimed:   'nobody has said whose time these servers disseminate',
                ntsOff:       'the time client is switched off',
                neverChecked: 'the clock has not been checked yet',
                stale:        'the last check is too old to count',
                offBy:        'the clock is further out than the tolerance allows'
            };

            return html`

                <h2>
                    <i class="fa-solid fa-hourglass-half"></i> The clock
                    <span class="chip ${now.legal ? 'ok' : 'warn'}">
                        ${now.legal ? 'legal time' : 'unverified'}
                    </span>
                </h2>

                <div class="kv-list">

                    <div class="kv">
                        <span class="k">Here, now</span>
                        <span class="v">${formatValue(now.now)} <span class="muted small">(this ${config.nodeName}'s own clock)</span></span>
                    </div>

                    <div class="kv">
                        <span class="k">Last checked</span>
                        <span class="v">
                            ${now.nts.checkedAt === null
                                  ? 'never'
                                  : html`${formatValue(now.nts.checkedAt)} <span class="muted small">against ${now.nts.lastServer ?? `group '${now.nts.group ?? '-'}'`}${
                                        now.nts.answered !== null && now.nts.asked !== null
                                            ? ` - ${now.nts.answered} of ${now.nts.asked} answered`
                                            : ''}</span>`}
                        </span>
                    </div>

                    <div class="kv">
                        <span class="k">Off by</span>
                        <span class="v">${ms(now.nts.offset_ms, true)}</span>
                    </div>

                    <div class="kv">
                        <span class="k">Authority</span>
                        <span class="v">${now.authority ?? html`<span class="muted">none claimed</span>`}</span>
                    </div>

                </div>

                <p class="hint">
                    ${now.legal
                          ? html`
                              Checked against ${now.nts.lastServer ?? 'the time servers'} within the last
                              ${Math.round(now.maxAgeSeconds / 60)} minutes and within
                              ${now.toleranceSeconds} s of them${authorityOf(now)}.
                            `
                          : html`
                              Unverified: ${why[now.why ?? ''] ?? `the ${config.nodeName} did not say why`}. The
                              time above is still this ${config.nodeName}'s own clock and is still what everything
                              below it is told - it is only not something anybody may call legal.
                            `}
                </p>

            `;

        }


        /** Whether this node asks anybody at all. */
        function switchView(configuration: NTSConfiguration): TemplateResult {

            return html`

                <h2><i class="fa-solid fa-power-off"></i> Time synchronisation</h2>

                <label class="switch">
                    <input type="checkbox" id="enabled"
                           .checked=${live(configuration.enabled)}
                           ?disabled=${!mayChange}
                           @change=${(event: Event) => void switchTo((event.target as HTMLInputElement).checked)} />
                    <span>${configuration.enabled ? 'switched on' : 'switched off'}</span>
                </label>

                <p class="hint">
                    Switched off, this ${config.nodeName} asks its time servers nothing at all - "Sync now" and the
                    tests below are refused rather than quietly doing nothing.
                </p>

                <span id="switch-error" class="form-error" role="alert"></span>

            `;

        }


        /**
         * The synchronisation this page shows: the one just asked for, or the
         * last one the node remembers - and none at all while the next one
         * is being asked for, neither the verdict nor what each server said.
         * Left standing under the spinning button, the last one read as the
         * new answer.
         */
        function shownSync(): NTSSyncResult | null {
            return syncing ? null : current?.result ?? current?.lastSync ?? null;
        }


        /** The time servers, and what each of them said. */
        function serversView(configuration: NTSConfiguration): TemplateResult {

            const sources       = configuration.timeSources ?? [];
            const sync          = shownSync();
            const switchedOn    = sources.filter(source => source.enabled).length;

            return html`

                <h2><i class="fa-solid fa-users"></i> Time servers</h2>

                <div class="time-server-list">
                    ${sources.length === 0
                          ? html`<p class="muted small">No time server configured.</p>`
                          : repeat(sources, source => readable(source.hostname).toLowerCase(),
                                   (source, index) => serverView(source, index, whatItSaid(sync, source), sync !== null))}
                </div>

                <div class="form-actions">
                    <button type="button" id="add-server" class="btn" title="Add a time server"
                            aria-label="Add a time server" ?disabled=${!mayChange} @click=${() => editServer(null)}>
                        <i class="fa-solid fa-plus"></i>
                    </button>
                    <span class="hint">
                        ${configuration.group
                              ? html`
                                    At least ${configuration.group.minServers} of the ${switchedOn} switched on must
                                    answer, and a disagreement of ${configuration.group.maxDeviationSeconds} s or more is
                                    written down. Servers sharing a priority are asked together; a lower priority is
                                    asked first.
                                `
                              : nothing}
                    </span>
                </div>

            `;

        }


        /** What the group is held to, as a form. */
        function policyView(configuration: NTSConfiguration): TemplateResult {

            const settings      = configuration.settings;
            const limits        = configuration.limits;
            const held          = configuration.group?.minServers ?? settings.minServers;
            const off           = !mayChange;

            return html`

                <h2><i class="fa-solid fa-sliders"></i> Group policy</h2>

                <form id="policy-form" class="form-stack" @submit=${savePolicy}>

                    <label>Servers that must answer
                        <input type="number" name="minServers" min="1" max="255" step="1"
                               value="${settings.minServers}" ?disabled=${off} />
                        <span class="hint">
                            ${held < settings.minServers
                                  ? html`Held to ${held} for as long as only ${held} ${held === 1 ? 'is' : 'are'} switched on.`
                                  : html`Two is the fewest that notice a server which is wrong rather than away.`}
                        </span>
                    </label>

                    <label>Agreed deviation in seconds
                        <input type="number" name="maxDeviationSeconds" step="0.001"
                               min="${limits.minDeviation}" max="${limits.maxDeviation}"
                               value="${settings.maxDeviationSeconds}" ?disabled=${off} />
                        <span class="hint">How far apart their answers may be before the disagreement is written into the log.</span>
                    </label>

                    <label>Check the clock every ... seconds
                        <input type="number" name="checkEverySeconds" step="1"
                               min="${limits.minCheckEvery}" max="${limits.maxCheckEvery}"
                               value="${settings.checkEverySeconds}" ?disabled=${off} />
                    </label>

                    <label>Timeout of a test in seconds
                        <input type="number" name="timeoutSeconds" step="0.1" min="0.1" max="${limits.maxTimeout}"
                               value="${settings.timeoutSeconds ?? ''}" placeholder="${theClientsOwnTimeout}" ?disabled=${off} />
                        <span class="hint">What a server's Test allows each step. "Sync now" asks the way the clock check does, with timeouts of its own.</span>
                    </label>

                    <div class="form-actions">
                        <button type="submit" class="btn primary" ?disabled=${off}>Save</button>
                        <span id="policy-note"  class="form-notice" role="status"></span>
                        <span id="policy-error" class="form-error"  role="alert"></span>
                    </div>

                    <span class="hint">Saved to <span class="path">${configuration.file}</span>, and in effect at once.</span>

                </form>

            `;

        }


        /**
         * Whose time counts as legal time, as a form.
         *
         * A statement of its own and not one of the group's rules: no node can
         * find out by itself who stands behind a time server. Naming one is the
         * operator vouching for it, and it is what makes the question "is this
         * legal time" mean anything at all. The node's answer said a page edits
         * these beside the servers, and only the energy meter's did.
         */
        function legalView(configuration: NTSConfiguration): TemplateResult {

            const settings      = configuration.settings;
            const limits        = configuration.limits;
            const off           = !mayChange;

            return html`

                <h2><i class="fa-solid fa-scale-balanced"></i> What counts as legal time</h2>

                <form id="legal-form" class="form-stack" @submit=${saveLegal}>

                    <label>Authority
                        <input type="text" name="legalTimeAuthority" maxlength="${limits.maxAuthorityLength}"
                               value="${settings.legalTimeAuthority ?? ''}" placeholder="PTB" ?disabled=${off} />
                        <span class="hint">Who stands behind the time these servers disseminate. Emptied and saved, nobody is named, and this ${config.nodeName}'s time is never legal time.</span>
                    </label>

                    <label>Tolerance in seconds
                        <input type="number" name="legalTimeToleranceSeconds" step="0.001"
                               min="${limits.minTolerance}" max="${limits.maxTolerance}"
                               value="${settings.legalTimeToleranceSeconds}" ?disabled=${off} />
                        <span class="hint">How far off this ${config.nodeName}'s clock may be found and still keep legal time.</span>
                    </label>

                    <label>Max age of a check in seconds
                        <input type="number" name="legalTimeMaxAgeSeconds" step="1"
                               min="${limits.minMaxAge}" max="${limits.maxMaxAge}"
                               value="${settings.legalTimeMaxAgeSeconds}" ?disabled=${off} />
                    </label>

                    <div class="form-actions">
                        <button type="submit" class="btn primary" ?disabled=${off}>Save</button>
                        <span id="legal-note"  class="form-notice" role="status"></span>
                        <span id="legal-error" class="form-error"  role="alert"></span>
                    </div>

                    <span class="hint">Saved to <span class="path">${configuration.file}</span>, and in effect at once.</span>

                </form>

            `;

        }


        /**
         * The button that asks all the servers, and what the group concluded.
         *
         * A card of its own at the end of the page, below everything it puts
         * to work: the servers, and the rules they are held to.
         */
        function syncView(): TemplateResult {

            const sync = shownSync();

            return html`

                <h2><i class="fa-solid fa-rotate"></i> Synchronisation</h2>

                <div class="sync-bar">
                    <button type="button" id="sync" class="btn primary large" ?disabled=${!mayTest || syncing} @click=${() => void runSync()}>
                        <i class="fa-solid fa-rotate ${syncing ? 'fa-spin' : ''}"></i>
                        ${syncing ? 'Asking the servers ...' : 'Sync now'}
                    </button>
                    <span class="hint">
                        ${mayTest
                              ? html`
                                    Asks every server that is switched on, the way the clock check does: a key
                                    exchange over TLS, then one authenticated NTP request each. Every step goes
                                    into the log. The clock of this ${config.nodeName} is not stepped by it.
                                `
                              : html`Asking the servers needs a role that may run tests.`}
                    </span>
                </div>

                <span id="sync-error" class="form-error" role="alert"></span>

                ${sync === null ? nothing : verdictView(sync)}

            `;

        }


        /**
         * One time server: who it is, what it said last, and what can be done
         * with it.
         *
         * A server switched on can be missing from a synchronisation without
         * anything being wrong with it: the bands are asked in turn, and one
         * with a higher priority is not asked when those before it were
         * enough. Its row says so rather than showing nothing, which looked
         * like a server that had been forgotten.
         */
        function serverView(source:  NTSTimeSource,
                            index:   number,
                            said:    NTSServerResult | undefined,
                            synced:  boolean): TemplateResult {

            const usual  = usualPorts();
            const ports  = source.ntsKEPort !== usual.ntsKE || source.ntpPort !== usual.ntp
                               ? `, ports ${source.ntsKEPort} and ${source.ntpPort}`
                               : '';

            return html`
                <div class="time-server-row ${source.enabled ? '' : 'off'}">

                    <div class="who">
                        <span class="name">${readable(source.hostname)}</span>
                        <span class="muted small">
                            priority ${source.priority}${ports}${source.enabled ? nothing : html`, <strong>switched off</strong>`}
                        </span>
                    </div>

                    <div class="said">
                        ${said === undefined
                              ? synced && source.enabled
                                    ? html`<span class="muted">not asked in the last synchronisation</span>`
                                    : nothing
                              : said.ok
                                    ? html`<span class="answer ok">${ms(said.offset_ms, true)}, round trip ${ms(said.roundTrip_ms)}</span>`
                                    : html`<span class="answer bad">${said.error ?? (said.authenticated === false
                                                                                           ? 'answered, but the answer did not authenticate'
                                                                                           : 'no answer')}</span>`}
                        <span class="muted small">
                            ${source.lastExchange
                                  ? html`${formatValue(source.cookies)} cookie(s), ${source.aeadAlgorithm ?? ''}, exchanged ${formatValue(source.lastExchange)}`
                                  : 'not asked yet'}
                        </span>
                    </div>

                    <div class="root-ca">
                        ${source.rootCA
                              ? html`
                                    <span class="ca-name" title="${source.rootCA.subject}">
                                        <span class="muted small">Root CA</span> ${source.rootCA.name}
                                    </span>
                                    <span class="fingerprint" title="SHA-256 fingerprint of the root CA">${fingerprintView(source.rootCA.fingerprint)}</span>
                                `
                              : html`<span class="muted small">Root CA: no key exchange yet</span>`}
                        <span class="server-certificate small">
                            ${heldToView(draftOf(source.heldTo), offers?.nameOf)}
                            ${source.judgement || source.known && !source.rootCA
                                  ? certificateVerdictView(source.judgement, source.known)
                                  : nothing}
                        </span>
                    </div>

                    <div class="actions">
                        <button type="button" class="btn small" data-test="${index}"
                                title="Ask this server, and only this one" ?disabled=${!mayTest}
                                @click=${() => void testServer(readable(source.hostname))}>
                            <i class="fa-solid fa-list-check"></i> Test
                        </button>
                        <button type="button" class="btn small" data-edit="${index}" ?disabled=${!mayChange}
                                @click=${() => editServer(index)}>
                            <i class="fa-solid fa-pen"></i> Edit
                        </button>
                    </div>

                </div>
            `;

        }


        /**
         * A fingerprint that breaks in the middle and nowhere else.
         *
         * Two halves of 32 read against a pinned fingerprint far better than a
         * line broken wherever the column happens to end - and at every width
         * the column has, they are the same two halves. The break is a <wbr>
         * rather than a space, so that copying it copies the fingerprint.
         */
        function fingerprintView(fingerprint: string): TemplateResult {
            return html`${(fingerprint.match(/.{1,32}/g) ?? [fingerprint]).map(part => html`${part}<wbr>`)}`;
        }


        /** What the group concluded, in one line under the button that asked. */
        function verdictView(sync: NTSSyncResult): TemplateResult {

            const group = sync.group;

            return html`
                <div class="query-result sync-verdict ${sync.ok ? 'ok' : 'bad'}">
                    <strong>${sync.ok ? 'Succeeded:' : 'Failed:'}</strong>
                    ${sync.ok && group
                          ? html`${group.answered} of ${sync.servers?.length ?? 0} server(s) answered
                                 (${group.required} required), offset ${ms(group.offset_ms, true)},
                                 spread ${ms(group.spread_ms)}`
                          : html`${sync.error ?? 'no reason was given'}`}
                    <span class="muted small">
                        - ${formatValue(sync.at)}${sync.runtime_ms ? `, ${sync.runtime_ms} ms` : ''}
                    </span>
                    ${group?.deviationExceeded
                          ? html`<div class="small">The servers disagree by more than the agreed deviation - the log says by how much.</div>`
                          : nothing}
                </div>
            `;

        }


        /** What one server said in a synchronisation, if it was asked in it. */
        function whatItSaid(sync:    NTSSyncResult | null,
                            source:  NTSTimeSource): NTSServerResult | undefined {

            const name = readable(source.hostname).toLowerCase();

            return sync?.servers?.find(server => readable(server.hostname).toLowerCase() === name);

        }


        /**
         * Add a time server, or change or delete one, in a dialog.
         *
         * A dialog rather than fields in the row: a server has five things
         * that can be said about it and what its certificate is held to
         * besides, and the list is for reading which servers there are. And
         * the node is told the whole list when this is saved, so
         * the dialog is also where it becomes clear that exactly one server is
         * being changed.
         *
         * @param index  the server's place in the list, or null to add one.
         */
        function editServer(index: number | null): void {

            if (current === null)
                return;

            const configuration  = current;
            const list           = entries();
            const shown          = index === null ? null : configuration.timeSources?.[index] ?? null;
            const usual          = usualPorts();

            if (index !== null && shown === null)
                return;

            const dialog = document.createElement('dialog');

            dialog.className = 'test-dialog server-dialog';

            document.body.appendChild(dialog);

            /** Shut it and take it away - both, as not every browser fires "close". */
            const dismiss = (): void => { dialog.close(); dialog.remove(); };

            const error  = (): HTMLElement => must<HTMLElement>(dialog, '#server-error');

            /**
             * Tell the node the list with the one change in it, and close
             * only when it took it. What it refuses - a server below the
             * quorum, the last one - is said in the dialog, and the list the
             * page shows is still the one the node has.
             */
            async function tell(servers: NTSServerEntry[]): Promise<void> {

                error().textContent = '';

                try
                {
                    current = await whileSaving(dialog, null, () => api.nts.save({ servers }));
                }
                catch (problem)
                {
                    error().textContent = errorMessage(problem);
                    return;
                }

                dismiss();

                if (!cancelled)
                    draw();

                // The clock names the group and what it rests on.
                await refreshClock();

            }

            function take(event: SubmitEvent): void {

                event.preventDefault();

                const form      = event.currentTarget as HTMLFormElement;
                const data      = new FormData(form);
                const hostname  = readable(String(data.get('hostname') ?? '').trim());
                const ntsKE     = String(data.get('ntsKEPort') ?? '').trim();
                const ntp       = String(data.get('ntpPort')   ?? '').trim();
                const priority  = Number(data.get('priority')  ?? 0);

                if (hostname.length === 0) {
                    error().textContent = 'A host name is needed.';
                    return;
                }

                if (nameTaken(list, hostname, index)) {
                    error().textContent = `${hostname} is in the list already.`;
                    return;
                }

                // What it is held to is in the dialog as well, so that it is
                // saved as it is shown - kept where nobody touched it, which is
                // what the entry lost before this was here, and kept under a
                // new name too, where it is to be seen and emptied.
                const pins = readPinsFieldset(form);

                if (pins.error !== undefined) {
                    error().textContent = pins.error;
                    return;
                }

                const entry: NTSServerEntry = { hostname };

                if (priority !== 0)                                      entry.priority   = priority;
                if (ntsKE.length > 0 && Number(ntsKE) !== usual.ntsKE)  entry.ntsKEPort  = Number(ntsKE);
                if (ntp.length   > 0 && Number(ntp)   !== usual.ntp)    entry.ntpPort    = Number(ntp);
                if (data.get('enabled') === null)                        entry.enabled    = false;

                // And what the dialog showed it held to, so that the
                // node changes only what was changed here - see asShown.
                if (shown !== null)
                    entry.pinsAsShown = asShown(shown.heldTo);

                void tell(withServer(list, index, withPins(entry, pins.draft)));

            }

            function remove(): void {

                if (shown === null || index === null)
                    return;

                if (!confirm(`Delete ${readable(shown.hostname)}?\n\n` +
                             `It is taken out of the list, and out of ${configuration.file}.`))
                    return;

                void tell(withoutServer(list, index));

            }

            render(dialog, html`

                <h2><i class="fa-solid fa-clock"></i> ${shown === null ? 'A new time server' : readable(shown.hostname)}</h2>

                <form id="server-form" class="form-stack" @submit=${take}>

                    <label>Host name
                        <input type="text" name="hostname" placeholder="ptbtime1.ptb.de"
                               value="${shown === null ? '' : readable(shown.hostname)}" />
                        <span class="hint">
                            A name and not an address: the key exchange checks the server's TLS certificate
                            against it.
                        </span>
                    </label>

                    <label>Priority
                        <input type="number" name="priority" min="0" max="255" step="1"
                               value="${shown?.priority ?? 0}" />
                        <span class="hint">A lower priority is asked first; servers sharing one are asked together.</span>
                    </label>

                    <label>NTS-KE port
                        <input type="number" name="ntsKEPort" min="1" max="65535" placeholder="${usual.ntsKE}"
                               value="${shown !== null && shown.ntsKEPort !== usual.ntsKE ? shown.ntsKEPort : ''}" />
                    </label>

                    <label>NTP port
                        <input type="number" name="ntpPort" min="1" max="65535" placeholder="${usual.ntp}"
                               value="${shown !== null && shown.ntpPort !== usual.ntp ? shown.ntpPort : ''}" />
                        <span class="hint">Left empty, the usual ones: ${usual.ntsKE} and ${usual.ntp}.</span>
                    </label>

                    <label class="checkbox">
                        <input type="checkbox" name="enabled" ?checked=${shown === null || shown.enabled} />
                        Ask this server
                        <span class="hint">Switched off, it stays in the list and is not asked.</span>
                    </label>

                    ${pinsFieldset(draftOf(shown?.heldTo), {
                          service:  'nts',
                          shown:    shown === null
                                        ? null
                                        : {
                                              name:         readable(shown.hostname),
                                              certificate:  shown.certificate ?? shown.judgement?.certificate ?? shown.known?.certificate ?? null,
                                              root:         shown.rootCA?.fingerprint ?? shown.judgement?.root ?? shown.known?.root ?? null
                                          },
                          offers
                      })}

                    <div class="form-actions">
                        <button type="submit" class="btn primary">Save</button>
                        <button type="button" class="btn" id="server-cancel" @click=${dismiss}>Cancel</button>
                        ${shown === null
                              ? nothing
                              : html`<button type="button" class="btn danger" id="server-delete" @click=${remove}>
                                         <i class="fa-solid fa-trash"></i> Delete
                                     </button>`}
                        <span id="server-error" class="form-error" role="alert"></span>
                    </div>

                </form>

            `);


            dialog.addEventListener('close',  dismiss);
            dialog.addEventListener('cancel', dismiss);

            dialog.showModal();

            must<HTMLInputElement>(dialog, 'input[name="hostname"]').focus();

        }


        /**
         * Ask one time server everything, in a dialog, line by line.
         *
         * "Sync now" answers whether the group has a time; this answers where
         * one server got to, which is the question somebody has when it did
         * not. The steps are the ones the exchange actually has - the name, the
         * TCP connection, the TLS handshake, the key exchange, the
         * authenticated request - and each is timed, so a server that is merely
         * slow can be told from one that is refusing.
         *
         * @param host  which server, asked on the ports it is configured with.
         *              Sent as it is read, without the root's dot, because the
         *              node writes it into the log as it was sent.
         */
        async function testServer(host: string): Promise<void> {

            const dialog = document.createElement('dialog');

            dialog.className = 'test-dialog';

            render(dialog, html`
                <h2>Asking ${readable(host)}</h2>
                <div class="test-steps" id="test-steps">
                    <div class="loading">Name, key exchange, authenticated time request ...</div>
                </div>
                <div class="form-actions">
                    <button type="button" class="btn" id="test-close" disabled @click=${() => dismiss()}>Close</button>
                </div>
            `);

            document.body.appendChild(dialog);
            dialog.showModal();

            // Both halves explicitly: a browser the charging station's pages
            // were tried in fired no close event at all.
            const dismiss = (): void => { dialog.close(); dialog.remove(); };

            dialog.addEventListener('close',  dismiss);
            dialog.addEventListener('cancel', dismiss);

            const close = must<HTMLButtonElement>(dialog, '#test-close');

            let result: TimeServerTest;

            try
            {
                result = await api.nts.test(current?.settings.timeoutSeconds ?? theClientsOwnTimeout, host);
            }
            catch (problem)
            {
                render(must<HTMLElement>(dialog, '#test-steps'), html`
                    <div class="error-box">The test could not be run: ${errorMessage(problem)}</div>
                `);
                close.disabled = false;
                close.focus();
                return;
            }

            render(must<HTMLElement>(dialog, '#test-steps'), html`
                <div class="${result.ok ? 'notice' : 'error-box'}">
                    ${result.ok
                          ? html`${readable(result.host)} answered. ${result.runtime_ms} ms altogether.`
                          : html`${readable(result.host)} did not answer. ${result.runtime_ms} ms altogether.`}
                </div>
                <ol class="test-log">
                    ${result.steps.map(step => html`
                        <li class="level-${step.level}">
                            <span class="at">+${step.at_ms} ms</span>
                            <span class="text">${step.text}</span>
                        </li>
                    `)}
                </ol>
            `);

            close.disabled = false;
            close.focus();

        }


        function savePolicy(event: SubmitEvent): void {

            event.preventDefault();

            const form     = event.currentTarget as HTMLFormElement;
            const timeout  = numberField(form, 'timeoutSeconds');

            // An emptied field is not given, which the node reads as
            // "keep what you have" - not 0, which it refuses, and the
            // whole save with it (the energy meter's).
            const update: NTSUpdate = {
                minServers:           numberField(form, 'minServers'),
                maxDeviationSeconds:  numberField(form, 'maxDeviationSeconds'),
                checkEverySeconds:    numberField(form, 'checkEverySeconds')
            };

            // Left empty, the client's own is what a test allows.
            if (!Number.isNaN(timeout))
                update.timeoutSeconds = timeout;

            void saveForm(form, '#nts-policy', '#policy-note', '#policy-error', update);

        }


        function saveLegal(event: SubmitEvent): void {

            event.preventDefault();

            const form       = event.currentTarget as HTMLFormElement;
            const authority  = String(new FormData(form).get('legalTimeAuthority') ?? '').trim();

            // Only what this form says, which the node lays over the rest.
            void saveForm(form, '#nts-legal', '#legal-note', '#legal-error', {
                // An emptied field takes the authority away rather than
                // naming one called "".
                legalTimeAuthority:         authority.length > 0 ? authority : null,
                legalTimeToleranceSeconds:  numberField(form, 'legalTimeToleranceSeconds'),
                legalTimeMaxAgeSeconds:     numberField(form, 'legalTimeMaxAgeSeconds')
            });

        }


        /** Switch the whole thing on or off. */
        async function switchTo(on: boolean): Promise<void> {

            const error = must<HTMLElement>(content, '#switch-error');

            error.textContent = '';

            try
            {
                current = await whileSaving(must<HTMLElement>(content, '#nts-switch'), null,
                                            () => api.nts.save({ enabled: on }));
            }
            catch (problem)
            {
                // Back to what the node has, which is not what the box
                // says now that somebody has clicked it.
                draw();
                must<HTMLElement>(content, '#switch-error').textContent = errorMessage(problem);
                return;
            }

            draw();

            // Whether the time may be called legal depends on it.
            await refreshClock();

        }


        /**
         * Tell the node what one of the two forms says - what the group is
         * held to, or what counts as legal time - and show what it took.
         * Only what that form says: the node lays it over the rest, and the
         * other form keeps what is typed into it.
         */
        async function saveForm(Form:     HTMLFormElement,
                                Card:     string,
                                NoteAt:   string,
                                ErrorAt:  string,
                                Update:   NTSUpdate): Promise<void> {

            must<HTMLElement>(content, NoteAt). textContent = '';
            must<HTMLElement>(content, ErrorAt).textContent = '';

            try
            {
                current = await whileSaving(must<HTMLElement>(content, Card), must<HTMLElement>(content, NoteAt),
                                            () => api.nts.save(Update));
            }
            catch (problem)
            {
                must<HTMLElement>(content, ErrorAt).textContent = errorMessage(problem);
                return;
            }

            if (cancelled)
                return;

            draw();

            // A draw leaves a form as it is typed into; this one was saved,
            // so it goes back to what it says now - the node's answer.
            Form.reset();

            must<HTMLElement>(content, NoteAt).textContent = 'Saved, and in effect.';

            // What the clock rests on: the group's rules, and what counts as
            // legal time.
            await refreshClock();

        }


        async function runSync(): Promise<void> {

            // Its own card for the button and the verdict, and the list for
            // what each server said.
            syncing = true;
            draw();

            try
            {
                // The answer carries the whole configuration as well as the
                // result, because an exchange moves the cookies and the record
                // of the last key exchange that each row is showing.
                current = await api.nts.sync(current?.settings.timeoutSeconds ?? theClientsOwnTimeout);
            }
            catch (problem)
            {
                syncing = false;
                draw();
                must<HTMLElement>(content, '#sync-error').textContent = errorMessage(problem);
                return;
            }

            if (cancelled)
                return;

            syncing = false;
            draw();

            // And the clock: an exchange is exactly the thing that turns
            // "never checked" into a number.
            await refreshClock();

        }


        /**
         * The clock card again, which says what the group and the authority
         * make of the time - asked in a try of its own. Asked inside the save
         * or the sync before it, a clock that could not be read reported a
         * save that had been made, or a sync that had run, as failed.
         */
        async function refreshClock(): Promise<void> {

            try
            {
                clock = await api.clock();
            }
            catch
            {
                // The card keeps what it had; the next Reload says why.
                return;
            }

            if (!cancelled)
                draw();

        }


        async function load(): Promise<void> {

            try
            {
                // Together, because they are two halves of one question and a
                // page that showed the time servers without saying whether
                // their answers are any good has said nothing. The store
                // beside them and not after: it only names fingerprints and
                // offers them in the dialog, and a store this person may not
                // read is no reason to show no page.
                const [loaded, now, kept] = await Promise.all([api.nts.get(), api.clock(), storeOffers('nts')]);

                if (!cancelled) {
                    current = loaded;
                    clock   = now;
                    offers  = kept;
                    draw();
                    // Loaded anew - Reload - is what the node has, the forms
                    // too, which a draw on its own would leave as typed.
                    content.querySelectorAll('form').forEach(form => form.reset());
                }
            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`
                        <div class="error-box">The NTS configuration could not be loaded: ${errorMessage(problem)}</div>
                    `);
            }

        }

        const release = unsaved.heldBy(() => typedSinceDrawn(content.querySelector('#policy-form')) ||
                                             typedSinceDrawn(content.querySelector('#legal-form')));

        void load();

        return () => { cancelled = true; release(); };

    }

};


/**
 * Whose time the clock is said to carry, as the end of the sentence that says
 * it is legal - or nothing, where the node names nobody. A node calls its time
 * legal only once somebody is named, and the page does not argue with it; but
 * an answer that said legal and no authority drew "they carry the time of ."
 * (the e-mobility provider's stand-in API).
 */
function authorityOf(now: Clock): string {
    const authority = now.authority?.trim() ?? '';
    return authority.length > 0 ? `, and the operator says they carry the time of ${authority}` : '';
}


/**
 * Milliseconds the way the node's log writes them: one place after a point,
 * and a sign where the number says which way.
 */
function ms(value: number | null | undefined, signed = false): string {

    if (value === null || value === undefined)
        return '-';

    const sign = signed ? (value < 0 ? '-' : '+') : '';

    return `${sign}${Math.abs(value).toFixed(1)} ms`;

}
