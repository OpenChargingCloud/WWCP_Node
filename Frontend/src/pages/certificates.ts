import { nodeAPI, type Certificate, type CertificateStore } from '../api/client';
import { auth } from '../auth';
import { toURL } from '../basePath';
import { config } from '../config';
import { must, type HTMLFragment } from '../html';
import type { Page } from '../router';
import { mayButNot, reloadButton, shell } from '../shell';
import { errorMessage, humanizeKey, whileSaving } from '../ui';
import { anyFormTypedSinceDrawn, unsaved } from '../unsaved';
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


/** What a kind of node says in a place of the page: a fragment of html.ts, or a template of view.ts. */
export type Said = HTMLFragment | TemplateResult;

/** What a kind of node says, or says from what the store says: a sentence that holds only while the web interface is served over plain HTTP, say. */
export type SaidOf<S> = Said | ((store: S) => Said);

/** What a kind of node says about one kind of certificate: its card's heading, icon and hint, and what a certificate of it is for. */
export interface KindWords {
    /** The card's heading; the store's description of the kind where this is left out. */
    title?:  string;
    /** A Font Awesome class for the card's heading. */
    icon?:   string;
    /** Said under the heading. */
    hint?:   Said;
    /** Said in the dialog that says what one of this kind is for. */
    uses?:   Said;
}

/** What a section of a kind of node's own on this page gets to work with. */
export interface SectionContext<S extends CertificateStore = CertificateStore> {
    /** The store as the node last said it. */
    store():     S;
    /** Whether the person signed in may change the store. */
    mayChange:   boolean;
    /** The element the page draws into - to hold still with whileSaving() while a section's change is made. */
    page:        HTMLElement;
    /** Draw the page again from what is known, after something of the section's own changed. */
    draw():      void;
    /** Ask the node for the store, and every section for its own, again - and draw. */
    reload():    Promise<void>;
}

/**
 * A part of the page a kind of node adds: a card or several, at the end of
 * one of the three groups - the meter's signing requests below what it
 * presents, the roles its clients may have below what it believes.
 */
export interface CertificatesSection<S extends CertificateStore = CertificateStore> {
    /** At the end of which group it stands. */
    below:  'believes' | 'presents' | 'recognises';
    /**
     * What it needs beside the store, asked whenever the store is: as the
     * page is loaded, and after every change. A refusal is the page's: it
     * says it could not be loaded, as for the store.
     */
    load?():  Promise<unknown>;
    /** The section, drawn with the page - by comparing, so that what is typed into it outlives the rest being drawn. */
    draw(store: S):  TemplateResult;
    /**
     * Forget what it was told on the page - a choice that picks a hint, say -
     * as the page is loaded anew: Reload empties every form, and a section's
     * own choices go with them. Its forms are emptied by the page.
     */
    reset?():  void;
}

/** What a kind of node says on its certificates page beyond what every node says. */
export interface CertificatesOptions<S extends CertificateStore = CertificateStore> {

    /** "Certificate store" where a kind has a page called "Server certificates" as well. */
    title?:         string;
    subtitle?:      string;

    /**
     * What a kind says under each of the three groups, what an unencrypted key
     * lets somebody do, and what the import adds under its file - each said,
     * or said from the store.
     */
    hints?:         {
                        believes?:     SaidOf<S>;
                        presents?:     SaidOf<S>;
                        recognises?:   SaidOf<S>;
                        unencrypted?:  SaidOf<S>;
                        importing?:    SaidOf<S>;
                    };

    /** What a kind of node calls each kind of certificate, the icon and hint of its card, and what one of it is for. */
    kinds?:         Record<string, KindWords>;

    /** What a usage is called where the node's word is not the one to show: a meter's "modbus" and "web". */
    usageNames?:    Record<string, string>;

    /**
     * What the node's "chosen" names mean, in the words of the row of the
     * certificate chosen - "csmsClientCertificate": "signs in to the CSMS".
     */
    chosen?:        Record<string, { label: string; title?: string }>;

    /** How soon a certificate is worth warning about, in days: 30 unless a kind says otherwise. */
    expiringSoon?:  number;

    /** What is to be said at the top of the page, from what the store says: a listener with nothing to show, say. */
    notices?(store: S):  Said[];

    /** What else a certificate's row says, as chips beside its name: where an identity is shown now, and where next. */
    rowChips?(entry: Certificate, store: S):  Said[];

    /** The sections a kind of node adds, made anew whenever the page is opened, so that what they keep is the page's. */
    sections?(context: SectionContext<S>):  CertificatesSection<S>[];

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
                             TrustAnchors:  readonly string[]): TemplateResult {

    return html`
        Trust anchors: the roots a certificate shown to this ${NodeName} has to chain to, each kind for
        what its card says it is for. Every switched-on root of a kind is believed at once.
        ${TrustAnchors.includes('tlsRoot')
              ? html`A server's certificate may chain to the roots this machine trusts as well.`
              : nothing}
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
 *
 * A kind of node says what it calls its kinds and what their cards add
 * (kinds), what the top of the page is to say (notices), what a row says
 * beside a certificate's name (rowChips), and what sections it adds of its
 * own (sections) - the energy meter its signing requests and its clients'
 * roles, which had kept a page of 1258 lines of its own for them.
 */
export function certificatesPage<S extends CertificateStore = CertificateStore>(Options: CertificatesOptions<S> = {}): Page {

    const title         = Options.title ?? 'Certificates';
    const expiringSoon  = Options.expiringSoon ?? 30;

    return {

        title,

        render({ root }) {

            const content = shell(root, {
                active:    '/configuration/certificates',
                title,
                subtitle:  Options.subtitle ?? `The roots this ${config.nodeName} believes, what it presents, and the servers it recognises.`,
                actions:   reloadButton(() => load())
            });

            render(content, html`<div class="loading">Loading ...</div>`);

            const mayChange = auth.can('certificates', 'edit');

            let cancelled = false;
            let current: S | null = null;

            /** The kind the import is for; undefined for the first one, as the form is drawn. */
            let importKind: string | undefined;

            /** What the kind of node adds, for as long as the page is open. */
            const sections = Options.sections?.({
                                 store:      () => current!,
                                 mayChange,
                                 page:       content,
                                 draw:       () => draw(),
                                 reload:     () => reloadKinds()
                             }) ?? [];

            /** What a kind of node says in a place of the page, from the store where it says it from the store. */
            function hint(name: keyof NonNullable<CertificatesOptions<S>['hints']>, store: S): Said | undefined {
                const said = Options.hints?.[name];
                return typeof said === 'function' ? said(store) : said;
            }

            /** The store, and what every section needs beside it - asked together. */
            async function fetched(): Promise<S> {
                const [ store ] = await Promise.all([ api.certificates.get() as Promise<S>, ...sections.map(section => section.load?.()) ]);
                return store;
            }

            /** The sections at the end of one group. */
            function sectionsBelow(group: CertificatesSection['below'], store: S): TemplateResult[] {
                return sections.filter(section => section.below === group).map(section => section.draw(store));
            }


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
                            ${hint('unencrypted', store) ?? html`can take this ${config.nodeName}'s identity.`}
                        </div>` : nothing}

                    ${mayChange ? nothing : html`
                        <div class="notice">
                            ${mayButNot('look at the store', 'change it')}
                        </div>
                    `}

                    ${(Options.notices?.(store) ?? []).map(notice => html`<div class="notice">${notice}</div>`)}

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


            /** The three groups of the store, each kind a card - and the sections the kind of node adds, each at the end of its group. */
            function kindsView(store: S): TemplateResult {

                return html`

                    <h2>What this ${config.nodeName} believes</h2>
                    <p class="hint">
                        ${hint('believes', store) ?? believedHint(config.nodeName, store.trustAnchors)}
                    </p>
                    ${repeat(store.trustAnchors, kind => kind, kind => kindCard(kind))}
                    ${sectionsBelow('believes', store)}

                    <h2>What this ${config.nodeName} presents</h2>
                    <p class="hint">
                        ${hint('presents', store) ?? html`
                            What it shows of itself in TLS, with its private key, where a server asks it for a
                            certificate.
                        `}
                    </p>
                    ${repeat(store.credentials, kind => kind, kind => kindCard(kind))}
                    ${sectionsBelow('presents', store)}

                    ${store.recognised.length === 0 ? nothing : html`
                        <h2>What this ${config.nodeName} recognises</h2>
                        <p class="hint">
                            ${hint('recognises', store) ?? html`
                                Neither believed nor presented: the certificates of servers this ${config.nodeName}
                                connects to, kept so that a time server or a name server can be held to one of them
                                by its fingerprint - on the <a href="${toURL('/configuration/nts')}">NTS</a> and the
                                <a href="${toURL('/configuration/dns')}">DNS</a> page, where each server's dialog
                                offers the ones kept for it.
                            `}
                        </p>
                        ${repeat(store.recognised, kind => kind, kind => kindCard(kind))}
                    `}
                    ${sectionsBelow('recognises', store)}

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
                                ${hint('importing', store) ?? nothing}
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
                const words    = Options.kinds?.[kind];

                return html`
                    <section class="card" data-kind="${kind}">
                        <h3>${words?.icon ? html`<i class="fa-solid ${words.icon}"></i> ` : nothing}${words?.title ?? store.kinds[kind]!.description}</h3>

                        ${words?.hint ? html`<p class="hint">${words.hint}</p>` : nothing}

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
                const chips  = Options.rowChips?.(entry, current!) ?? [];

                return html`
                    <tr>
                        <td>
                            ${entry.label}
                            ${marksOf(entry, current!.chosen, Options.chosen).map(mark => html`
                                <span class="chip on" title="${mark.title}">${mark.label}</span>
                            `)}
                            <br /><code class="muted" title="SHA-256: ${entry.thumbprint}">${entry.id}</code>
                            ${chips.length > 0 ? html`<br /><span class="chips row-chips">${chips}</span>` : nothing}
                            ${usages
                                  ? html`<br /><span class="chips usages-of">
                                             ${entry.usages === null || entry.usages === undefined
                                                   ? html`<span class="chip">${current!.credentials.includes(entry.kind) ? 'on every listener' : 'for every use'}</span>`
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

                current    = await fetched();
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

                        ${Options.kinds?.[entry.kind]?.uses
                              ? html`<p class="hint">${Options.kinds[entry.kind]!.uses}</p>`
                              : !services ? nothing : html`
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


            /** The store again, and what the sections need, and the page drawn again - the import above the cards left as it is. */
            async function reloadKinds(): Promise<void> {

                try
                {
                    const loaded = await fetched();

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
                    const loaded = await whileSaving(content, note, () => api.certificates.reload()) as S;

                    await Promise.all(sections.map(section => section.load?.()));

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
                    const loaded = await fetched();

                    if (!cancelled) {
                        current    = loaded;
                        importKind = undefined;
                        sections.forEach(section => section.reset?.());
                        draw();
                        // Loaded anew - Reload - is what the node has: every
                        // form empty, the import and a section's alike.
                        content.querySelectorAll('form').forEach(form => form.reset());
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
            // draft like any other page's: leaving asks first - and so is what
            // is typed into a section's form, a request half filled in or a
            // certificate pasted for one (the energy meter's).
            const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

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
