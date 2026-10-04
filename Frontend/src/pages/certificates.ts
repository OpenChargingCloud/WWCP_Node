import { nodeAPI, type Certificate, type CertificateStore } from '../api/client';
import { auth } from '../auth';
import { toURL } from '../basePath';
import { config } from '../config';
import { html as stringHTML, must, type HTMLFragment } from '../html';
import type { Page } from '../router';
import { mayButNot, shell } from '../shell';
import { errorMessage, humanizeKey, whileSaving } from '../ui';
import { typedSinceDrawn, unsaved } from '../unsaved';
import { html, nothing, render, repeat, type TemplateResult } from '../view';
import { hasUsages, usageName, usagesOf } from './certificateUsages';

const api = nodeAPI();

/**
 * The largest file this page will offer to import.
 *
 * A certificate chain is a few kilobytes; a megabyte is already somebody who
 * picked the wrong file. Refused here rather than at the node so that the
 * answer is immediate and the browser does not base64 a video first.
 */
const largestImport = 1024 * 1024;


/** What a kind of node says on its certificates page beyond what every node says. */
export interface CertificatesOptions {

    /** "Certificate store" where a kind has a page called "Server certificates" as well. */
    title?:         string;
    subtitle?:      string;

    /** What a kind says under each of the three groups, and what an unencrypted key lets somebody do. */
    hints?:         {
                        believes?:     HTMLFragment;
                        presents?:     HTMLFragment;
                        recognises?:   HTMLFragment;
                        unencrypted?:  HTMLFragment;
                    };

    /** What a usage is called where the node's word is not the one to show: a meter's "modbus" and "web". */
    usageNames?:    Record<string, string>;

    /**
     * What the node's "chosen" names mean, in the words of the row of the
     * certificate chosen - "csmsClientCertificate": "signs in to the CSMS".
     */
    chosen?:        Record<string, { label: string; title?: string }>;

    /** How soon a certificate is worth warning about, in days: 30 unless a kind says otherwise. */
    expiringSoon?:  number;

}


/** What a certificate's state is, as the row says it: the word, and how much it should worry anybody. */
export function stateOf(Entry:         Certificate,
                        ExpiringSoon:  number,
                        Now:           number = Date.now()): { text: string; tone: '' | 'warn' | 'bad' } {

    const days = Math.floor((new Date(Entry.notAfter).getTime() - Now) / 86400000);

    return Entry.expired          ? { text: 'expired',            tone: 'bad'  }
         : Entry.notYetValid      ? { text: 'not yet valid',      tone: 'warn' }
         : !Entry.active          ? { text: 'switched off',       tone: ''     }
         : days <= ExpiringSoon   ? { text: `${days} day(s) left`, tone: 'warn' }
         :                          { text: 'on',                 tone: ''     };

}

/**
 * What the node has chosen this certificate for, as the row says it - in the
 * kind's words where it has them, and in the node's own name otherwise.
 */
export function marksOf(Entry:   Certificate,
                        Chosen:  Record<string, string | null> | undefined,
                        Words:   CertificatesOptions['chosen'] = {}): { label: string; title: string }[] {

    return Object.entries(Chosen ?? {}).
                  filter(([ , id ]) => id === Entry.id).
                  map(([ name ]) => ({
                      label:  Words[name]?.label ?? humanizeKey(name),
                      title:  Words[name]?.title ?? `Chosen by this ${config.nodeName}; deleted only once another one is`
                  }));

}

/**
 * What is said above the roots where a kind of node says nothing of its own:
 * what every kind of root is, as each card's heading says it - not a server's
 * roots alone, which a vehicle's V2G, contract and OEM roots are not, nor a
 * CSMS's roots for the stations connecting to it - and, where there are TLS
 * roots among them, that a server may chain to the roots this machine trusts
 * as well.
 */
export function believedHint(NodeName:      string,
                             TrustAnchors:  readonly string[]): HTMLFragment {

    return stringHTML`
        Trust anchors: the roots a certificate shown to this ${NodeName} has to chain to, each kind for
        what its card says it is for. Every switched-on root of a kind is believed at once.
        ${TrustAnchors.includes('tlsRoot')
              ? stringHTML`A server's certificate may chain to the roots this machine trusts as well.`
              : ''}
    `;

}


/**
 * This node's own certificate store: everything it believes, what it presents
 * in TLS itself, and the servers it recognises.
 *
 * A **root** is believed: any number of each kind may be on at once, and
 * switching one off changes which chains are accepted from the next
 * connection on. An **identity** is presented, with its private key. The
 * **server certificates** are neither: kept so that a time server or a name
 * server can be held to one of them by its fingerprint, on the NTS and the DNS
 * page. Which kinds a node keeps is the node's to say, and the page shows
 * what it says.
 *
 * A kind that is told what it is for - the time servers, the name servers,
 * the listeners an identity is shown on - is told when it is imported and can
 * be told again. What each kind may be told is the node's to say too.
 *
 * Certificates arrive two ways and both are first class. "Import" uploads a
 * file and copies it in; "Re-read the directory" picks up whatever somebody
 * put there by hand. Either way the store ends up the same, because the store
 * is the directory.
 *
 * Drawn by view.ts: a change to one certificate draws the page again and
 * changes only what differs, so that the import above the cards, half filled
 * in, keeps its file, its kind and its label - a switch clicked below it used
 * to take them with it.
 */
export function certificatesPage(Options: CertificatesOptions = {}): Page {

    const title         = Options.title ?? 'Certificates';
    const expiringSoon  = Options.expiringSoon ?? 30;

    return {

        title,

        render({ root }) {

            const content = shell(root, {
                active:    '/configuration/certificates',
                title,
                subtitle:  Options.subtitle ?? `The roots this ${config.nodeName} believes, what it presents, and the servers it recognises.`,
                actions:   stringHTML`<button type="button" id="reload" class="btn small">Reload</button>`
            });

            render(content, html`<div class="loading">Loading ...</div>`);

            // Reload throws what is typed into a form away as thoroughly as
            // leaving the page does, and from the opposite corner of the
            // screen, so it asks first.
            must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => {
                if (unsaved.mayBeLost())
                    void load();
            });

            const mayChange = auth.can('certificates', 'edit');

            let cancelled = false;
            let current: CertificateStore | null = null;

            /** The kind the import is for; undefined for the first one, as the form is drawn. */
            let importKind: string | undefined;


            /** The whole page, from what the node last said. */
            function draw(): void {

                if (current === null)
                    return;

                const store = current;

                render(content, html`

                    ${store.keysAreUnencrypted ? html`
                        <div class="notice">
                            The private keys in this store are <strong>not encrypted</strong>. Anybody who can read
                            <code>${store.directory}</code>
                            ${Options.hints?.unencrypted ?? html`can take this ${config.nodeName}'s identity.`}
                        </div>` : nothing}

                    ${mayChange ? nothing : html`
                        <div class="notice">
                            ${mayButNot('look at the store', 'change it')}
                        </div>
                    `}

                    <section class="card">
                        <h2><i class="fa-solid fa-certificate"></i> The store</h2>
                        <p class="hint">
                            One file per certificate below <code>${store.directory}</code>, with
                            <code>index.json</code> beside them recording what each one is called, whether it is
                            switched on and what it is kept for. Certificates already in that directory are read
                            again at every start, so copying one in is a way to install it.
                        </p>
                        <div class="form-actions">
                            <button type="button" id="rescan" class="btn" ?disabled=${!mayChange} @click=${() => void rescan()}>
                                Re-read the directory
                            </button>
                            <span id="store-note"  class="form-notice" role="status"></span>
                            <span id="store-error" class="form-error"  role="alert"></span>
                        </div>
                    </section>

                    ${mayChange ? importCard() : nothing}

                    <div id="kinds">${kindsView(store)}</div>

                `);

            }


            /** The three groups of the store, each kind a card. */
            function kindsView(store: CertificateStore): TemplateResult {

                return html`

                    <h2>What this ${config.nodeName} believes</h2>
                    <p class="hint">
                        ${Options.hints?.believes ?? believedHint(config.nodeName, store.trustAnchors)}
                    </p>
                    ${repeat(store.trustAnchors, kind => kind, kind => kindCard(kind))}

                    <h2>What this ${config.nodeName} presents</h2>
                    <p class="hint">
                        ${Options.hints?.presents ?? html`
                            What it shows of itself in TLS, with its private key, where a server asks it for a
                            certificate.
                        `}
                    </p>
                    ${repeat(store.credentials, kind => kind, kind => kindCard(kind))}

                    ${store.recognised.length === 0 ? nothing : html`
                        <h2>What this ${config.nodeName} recognises</h2>
                        <p class="hint">
                            ${Options.hints?.recognises ?? html`
                                Neither believed nor presented: the certificates of servers this ${config.nodeName}
                                connects to, kept so that a time server or a name server can be held to one of them
                                by its fingerprint - on the <a href="${toURL('/configuration/nts')}">NTS</a> and the
                                <a href="${toURL('/configuration/dns')}">DNS</a> page, where each server's dialog
                                offers the ones kept for it.
                            `}
                        </p>
                        ${repeat(store.recognised, kind => kind, kind => kindCard(kind))}
                    `}

                `;

            }


            /** The kinds in the order the page shows them, which is the order the import offers them in. */
            function kindsShown(): string[] {
                const store = current!;
                return [ ...store.trustAnchors, ...store.credentials, ...store.recognised ];
            }

            /**
             * The boxes that say what a certificate of this kind is for, one
             * per usage the node offers that kind - the services for a root or
             * a server certificate, the listeners for an identity - with its
             * legend. None ticked for every use, which is what a certificate
             * kept before there were usages is as well, and what the node
             * would refuse to be told as an empty list.
             */
            function usagesFields(kind: string, ticked: readonly string[] | null | undefined): TemplateResult {

                const listeners = current!.credentials.includes(kind);

                return html`
                    <legend>${listeners ? 'Where it is shown' : 'What it is kept for'}</legend>
                    ${repeat(usagesOf(current!, kind), usage => `${kind} ${usage}`, usage => html`
                        <label class="checkbox">
                            <input type="checkbox" name="usage" value="${usage}" ?checked=${ticked?.includes(usage) ?? false} />
                            ${usageName(usage, Options.usageNames)}
                        </label>
                    `)}
                    <span class="hint">None ticked: ${listeners ? 'on every listener' : 'for every use'}.</span>
                `;

            }


            /** The card that puts a new certificate on this node. */
            function importCard(): TemplateResult {

                const store = current!;

                // Drawn as the kind chosen, as the browser would choose it
                // anyway, so that an untouched form is one: a select with no
                // option drawn as selected counts as typed into - see
                // typedSinceDrawn - and leaving the page asked about a draft
                // nobody had begun.
                const first = kindsShown()[0];
                const kind  = importKind ?? first;

                return html`
                    <section class="card">
                        <h2><i class="fa-solid fa-file-import"></i> Import a certificate</h2>
                        <form id="import-form" class="form-stack" @submit=${(event: SubmitEvent) => { event.preventDefault(); void doImport(event.currentTarget as HTMLFormElement); }}>

                            <label>The file
                                <input type="file" name="file" id="import-file" accept=".pem,.crt,.cer,.der,.p12,.pfx" />
                            </label>
                            <p class="hint">
                                PEM, DER or PKCS#12, copied into the store rather than referenced where it is.
                                A certificate this ${config.nodeName} <em>presents</em> has to bring its private key,
                                so a PEM for one holds the key beside the certificate - which is how
                                <code>openssl</code> writes a whole credential into one file.
                            </p>

                            <label>What it is for
                                <select name="kind" id="import-kind" @change=${(event: Event) => { importKind = (event.target as HTMLSelectElement).value; draw(); }}>
                                    ${kindsShown().map(offered => html`
                                        <option value="${offered}" ?selected=${offered === first}>${store.kinds[offered]!.description}</option>
                                    `)}
                                </select>
                            </label>

                            <fieldset class="usages" id="import-usages" ?hidden=${kind === undefined || !hasUsages(store, kind)}>
                                ${kind === undefined ? nothing : usagesFields(kind, null)}
                            </fieldset>

                            <label>What opens it, if it is a protected PKCS#12
                                <input type="password" name="password" autocomplete="off" />
                            </label>
                            <p class="hint">
                                Used once, to read the file. The store keeps what it holds without a password, so
                                this is not written down anywhere.
                            </p>

                            <label>What to call it
                                <input type="text" name="label" maxlength="120" placeholder="its common name" />
                            </label>

                            <div class="form-actions">
                                <button type="submit" class="btn primary">Import</button>
                                <span id="import-note"  class="form-notice" role="status"></span>
                                <span id="import-error" class="form-error"  role="alert"></span>
                            </div>

                        </form>
                    </section>
                `;

            }


            /**
             * One kind, and everything in the store of that kind - with a line
             * of its own for what went wrong with one of them, so that a
             * refusal is said where the button was that asked, and not at the
             * top of a long page.
             */
            function kindCard(kind: string): TemplateResult {

                const store    = current!;
                const entries  = store.certificates[kind] ?? [];

                return html`
                    <section class="card" data-kind="${kind}">
                        <h3>${store.kinds[kind]!.description}</h3>

                        <div class="form-actions">
                            <span class="form-notice" role="status" data-note-of="${kind}"></span>
                            <span class="form-error"  role="alert"  data-error-of="${kind}"></span>
                        </div>

                        ${entries.length === 0
                            ? html`<p class="hint">None.</p>`
                            : html`
                              <div class="table-scroll">
                                <table class="records">
                                    <thead>
                                        <tr>
                                            <th>Name</th>
                                            <th>Subject</th>
                                            <th>Key</th>
                                            <th>Valid until</th>
                                            <th>State</th>
                                            <th></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${repeat(entries, entry => entry.id, entry => row(entry))}
                                    </tbody>
                                </table>
                              </div>
                            `}

                    </section>
                `;

            }


            /** One certificate. */
            function row(entry: Certificate): TemplateResult {

                const state  = stateOf(entry, expiringSoon);
                const usages = hasUsages(current!, entry.kind);
                const off    = !mayChange;

                return html`
                    <tr>
                        <td>
                            ${entry.label}
                            ${marksOf(entry, current!.chosen, Options.chosen).map(mark => html`
                                <span class="chip on" title="${mark.title}">${mark.label}</span>
                            `)}
                            <br /><code class="muted" title="SHA-256: ${entry.thumbprint}">${entry.id}</code>
                            ${usages
                                  ? html`<br /><span class="chips usages-of">
                                             ${entry.usages === null || entry.usages === undefined
                                                   ? html`<span class="chip">for every use</span>`
                                                   : entry.usages.map(usage => html`<span class="chip">${usageName(usage, Options.usageNames)}</span>`)}
                                         </span>`
                                  : nothing}
                        </td>
                        <td>
                            ${entry.subject}
                            ${entry.chainLength > 0 ? html`<br /><span class="muted">+${entry.chainLength} sub-CA(s)</span>` : nothing}
                        </td>
                        <td>
                            ${entry.keyAlgorithm}
                            ${entry.hasPrivateKey ? html`<br /><span class="muted">with private key</span>` : nothing}
                        </td>
                        <td>${new Date(entry.notAfter).toISOString().slice(0, 10)}</td>
                        <td><span class="chip ${state.tone}">${state.text}</span></td>
                        <td>
                            <button type="button" class="btn small" data-toggle="${entry.id}" ?disabled=${off}
                                    @click=${() => void toggle(entry.id)}>
                                ${entry.active ? 'Switch off' : 'Switch on'}
                            </button>
                            <button type="button" class="btn small" data-rename="${entry.id}" ?disabled=${off}
                                    @click=${() => void rename(entry.id)}>
                                Rename
                            </button>
                            ${usages
                                  ? html`<button type="button" class="btn small" data-usages="${entry.id}" ?disabled=${off}
                                                 @click=${() => editUsages(entry.id)}>Uses</button>`
                                  : nothing}
                            <button type="button" class="btn small danger" data-remove="${entry.id}" ?disabled=${off}
                                    @click=${() => void remove(entry.id)}>
                                Delete
                            </button>
                        </td>
                    </tr>
                `;

            }


            async function doImport(form: HTMLFormElement): Promise<void> {

                const note  = must<HTMLElement>(content, '#import-note');
                const error = must<HTMLElement>(content, '#import-error');

                note.textContent  = '';
                error.textContent = '';

                const chosen = must<HTMLInputElement>(content, '#import-file').files?.[0];

                if (chosen === undefined) {
                    error.textContent = 'Choose a file first.';
                    return;
                }

                if (chosen.size > largestImport) {
                    error.textContent = `That file is ${Math.round(chosen.size / 1024)} kB, and a certificate is a few. ` +
                                        'This is almost certainly not the file you meant.';
                    return;
                }

                // Every field read before anything is held still: whileSaving
                // disables them, and a disabled field is not in a FormData.
                const data     = new FormData(form);
                const kind     = String(data.get('kind'));
                const password = String(data.get('password') ?? '');
                const label    = String(data.get('label')    ?? '').trim();
                const usages   = hasUsages(current!, kind) ? data.getAll('usage').map(String) : [];

                let imported: Certificate;

                try
                {
                    imported = await whileSaving(content, note, async () => api.certificates.import({
                                   kind,
                                   content:   await base64Of(chosen),
                                   password:  password.length > 0 ? password : undefined,
                                   label:     label.length    > 0 ? label    : undefined,
                                   // Left out for every use; the node refuses
                                   // a certificate for no use.
                                   usages:    usages.length   > 0 ? usages   : undefined
                               }));
                }
                catch (problem)
                {
                    // What was chosen and typed stays where it was: the file,
                    // the kind, the label - and the password, which somebody
                    // who mistyped it wants to correct, not to type again with
                    // everything else. The page was redrawn here, and all of
                    // it was gone (the energy meter kept it).
                    error.textContent = errorMessage(problem);
                    return;
                }

                if (cancelled)
                    return;

                current    = await api.certificates.get();
                importKind = undefined;

                draw();

                // A draw leaves a form as it is typed into; this one was
                // imported, so it goes back to an empty one - the first kind,
                // no file, no label.
                form.reset();

                must<HTMLElement>(content, '#import-note').textContent = `Imported ${imported.label}, and switched on.`;

            }


            async function toggle(id: string): Promise<void> {

                const entry = everything().find(one => one.id === id);

                if (entry !== undefined)
                    await change(entry, () => api.certificates.update(id, { active: !entry.active }));

            }


            async function rename(id: string): Promise<void> {

                const entry = everything().find(one => one.id === id);

                if (entry === undefined)
                    return;

                // The label is one of the things about a stored certificate
                // that are somebody's to decide; everything else on the row is
                // read out of the file and is not up for editing.
                const given = prompt('What should this certificate be called?\n\n' +
                                     'Leave it empty for its own common name.', entry.label);

                if (given !== null)
                    await change(entry, () => api.certificates.update(id, { label: given.trim().length > 0 ? given.trim() : null }));

            }


            /**
             * Say again what a certificate is for, in a dialog.
             *
             * A dialog with a Save rather than boxes in the row that save on
             * every click: each change is a line in the log, and taking the
             * last tick away on the way to another one would have made the
             * certificate one for every use in between.
             */
            function editUsages(id: string): void {

                const entry = everything().find(one => one.id === id);

                if (entry === undefined)
                    return;

                const services = usagesOf(current!, entry.kind).every(usage => usage === 'dns' || usage === 'nts');

                const dialog = document.createElement('dialog');

                dialog.className = 'test-dialog server-dialog';

                document.body.appendChild(dialog);

                // Both halves explicitly: a browser the charging station's
                // pages were tried in fired no close event at all.
                const dismiss = (): void => { dialog.close(); dialog.remove(); };

                function save(event: SubmitEvent): void {

                    event.preventDefault();

                    const ticked = new FormData(event.currentTarget as HTMLFormElement).getAll('usage').map(String);

                    void (async () => {

                        try
                        {
                            // None ticked is every use again, which the node is
                            // told as null: a list with nothing in it would be
                            // a certificate for no use, and is refused.
                            await whileSaving(dialog, null, () => api.certificates.update(id, { usages: ticked.length > 0 ? ticked : null }));
                        }
                        catch (problem)
                        {
                            must<HTMLElement>(dialog, '#usages-error').textContent = errorMessage(problem);
                            return;
                        }

                        dismiss();

                        await reloadKinds();

                    })();

                }

                render(dialog, html`

                    <h2><i class="fa-solid fa-certificate"></i> ${entry.label}</h2>

                    <form id="usages-form" class="form-stack" @submit=${save}>

                        <fieldset class="usages">
                            ${usagesFields(entry.kind, entry.usages)}
                        </fieldset>

                        ${!services ? nothing : html`
                            <p class="hint">
                                ${current!.trustAnchors.includes(entry.kind)
                                      ? html`A root kept for the time servers alone vouches for no name server, and the
                                             other way round - except for a server whose own entry names it: naming it
                                             there says the same, and more narrowly.`
                                      : html`Offered in the dialog of the servers it is kept for, on the NTS and the DNS page.`}
                            </p>
                        `}

                        <div class="form-actions">
                            <button type="submit" class="btn primary">Save</button>
                            <button type="button" class="btn" id="usages-cancel" @click=${dismiss}>Cancel</button>
                            <span id="usages-error" class="form-error" role="alert"></span>
                        </div>

                    </form>

                `);

                dialog.addEventListener('close',  dismiss);
                dialog.addEventListener('cancel', dismiss);

                dialog.showModal();

            }


            async function remove(id: string): Promise<void> {

                const entry = everything().find(one => one.id === id);

                if (entry === undefined)
                    return;

                // The file goes with it, and there is no copy anywhere else.
                // Asked once, naming what is about to go.
                if (!confirm(`Delete ${entry.label}?\n\nIts file is deleted from the store as well, and ` +
                             `a certificate with a private key cannot be put back without that key.`))
                    return;

                await change(entry, () => api.certificates.remove(id));

            }


            /** Everything in the store, flattened - for finding one by its handle. */
            function everything(): Certificate[] {
                return Object.values(current?.certificates ?? {}).flat();
            }


            /**
             * One change to one certificate, with the page held still while it
             * is made, and then the store's cards redrawn from what the node
             * says now. A refusal - a certificate the node uses, which it does
             * not let go of until another one is chosen - is said on the card
             * of that certificate's kind, and brought into view.
             */
            async function change(Entry: Certificate, Doing: () => Promise<unknown>): Promise<void> {

                for (const said of content.querySelectorAll<HTMLElement>('[data-error-of], [data-note-of], #store-note, #store-error'))
                    said.textContent = '';

                const note = content.querySelector<HTMLElement>(`[data-note-of="${Entry.kind}"]`);

                try
                {
                    await whileSaving(content, note, Doing);
                }
                catch (problem)
                {
                    const said = content.querySelector<HTMLElement>(`[data-error-of="${Entry.kind}"]`);

                    if (said !== null) {
                        said.textContent = errorMessage(problem);
                        said.scrollIntoView({ block: 'nearest' });
                    }

                    return;
                }

                await reloadKinds();

            }


            /** The store again, and the page drawn again - the import above the cards left as it is. */
            async function reloadKinds(): Promise<void> {

                try
                {
                    const loaded = await api.certificates.get();

                    if (cancelled)
                        return;

                    current = loaded;
                    draw();
                }
                catch (problem)
                {
                    if (!cancelled)
                        must<HTMLElement>(content, '#store-error').textContent =
                            `The store could not be read again: ${errorMessage(problem)}`;
                }

            }


            async function rescan(): Promise<void> {

                const note  = must<HTMLElement>(content, '#store-note');
                const error = must<HTMLElement>(content, '#store-error');

                note.textContent  = '';
                error.textContent = '';

                try
                {
                    const loaded = await whileSaving(content, note, () => api.certificates.reload());

                    if (cancelled)
                        return;

                    current = loaded;
                    draw();

                    must<HTMLElement>(content, '#store-note').textContent =
                        `The directory was read again: ${everything().length} certificate(s).`;
                }
                catch (problem)
                {
                    must<HTMLElement>(content, '#store-error').textContent = errorMessage(problem);
                }

            }


            async function load(): Promise<void> {

                try
                {
                    const loaded = await api.certificates.get();

                    if (!cancelled) {
                        current    = loaded;
                        importKind = undefined;
                        draw();
                        // Loaded anew - Reload - is an empty import, as the
                        // node's store is.
                        content.querySelector<HTMLFormElement>('#import-form')?.reset();
                    }
                }
                catch (problem)
                {
                    if (!cancelled)
                        render(content, html`
                            <div class="error-box">The certificate store could not be loaded: ${errorMessage(problem)}</div>
                        `);
                }

            }

            // A file chosen, or a name typed, for an import not yet made is a
            // draft like any other page's: leaving asks first.
            const release = unsaved.heldBy(() => typedSinceDrawn(content.querySelector('#import-form')));

            void load();

            return () => { cancelled = true; release(); };

        }

    };

}


/**
 * One file's bytes, base64-encoded.
 *
 * Through a data: URL rather than by walking the bytes, because the browser's
 * own encoder is the one that will not get a 3-megabyte string wrong. The
 * prefix up to the comma is the media type the reader chose and is dropped.
 */
function base64Of(file: File): Promise<string> {

    return new Promise((resolve, reject) => {

        const reader = new FileReader();

        reader.onerror = () => reject(new Error(`'${file.name}' could not be read.`));

        reader.onload  = () => {

            const asURL = String(reader.result ?? '');
            const comma = asURL.indexOf(',');

            if (comma < 0) {
                reject(new Error(`'${file.name}' could not be read.`));
                return;
            }

            resolve(asURL.slice(comma + 1));

        };

        reader.readAsDataURL(file);

    });

}
