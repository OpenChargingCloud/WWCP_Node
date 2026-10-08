import { ApiError, nodeAPI, type Certificate, type CertificateGroup, type CertificateStore,
         type CertificatesUploaded, type InspectedCertificate } from '../api/client';
import { auth } from '../auth';
import { toURL } from '../basePath';
import { config } from '../config';
import { must } from '../html';
import { appendText, pemBox } from '../pemBox';
import type { Page } from '../router';
import { mayButNot, reloadButton, shell } from '../shell';
import { rememberTab, tabFromURL, tabsView, type Tab } from '../tabs';
import { errorMessage, humanizeKey, whileSaving } from '../ui';
import { anyFormTypedSinceDrawn, unsaved } from '../unsaved';
import { html, nothing, render, repeat, type TemplateResult } from '../view';
import { usageName, usagesOf } from './certificateUsages';

const api = nodeAPI();

/**
 * The largest file this page will offer to read.
 *
 * A certificate chain is a few kilobytes; a megabyte is already somebody who
 * picked the wrong file. Refused here rather than at the node so that the
 * answer is immediate and the browser does not base64 a video first.
 */
const largestImport = 1024 * 1024;

/** How long the upload waits after the last key before it asks the node what the box holds. */
const inspectAfter_ms = 350;

/** What a usage or a kind made up may be called, as the node checks it too. */
const usageNamePattern = /^[a-z][a-z0-9_-]{0,31}$/;
const kindNamePattern  = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/;


/** What a kind of node says in a place of the page: a template of view.ts. */
export type Said = TemplateResult;

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
     * lets somebody do, and what the upload adds under its box - each said, or
     * said from the store.
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
 * Every certificate of the store once, with every kind it is kept as, in the
 * order asked for: by name - its label, which is its common name unless
 * somebody said otherwise - or by its fingerprint.
 */
export function certificatesOf(Store:   CertificateStore,
                               Order:   'name' | 'fingerprint' = 'name',
                               Filter:  string = ''): { id: string; entries: Certificate[] }[] {

    const kindsInOrder = [ ...Store.trustAnchors, ...Store.credentials, ...Store.recognised ];
    const byId         = new Map<string, Certificate[]>();

    for (const kind of kindsInOrder)
        for (const entry of Store.certificates[kind] ?? [])
            byId.set(entry.id, [ ...(byId.get(entry.id) ?? []), entry ]);

    const wanted = Filter.trim().toLowerCase();

    return [ ...byId.entries() ].
               map(([ id, entries ]) => ({ id, entries })).
               filter(({ entries }) => wanted.length === 0 ||
                                       entries.some(entry => [ entry.label, entry.subject, entry.thumbprint, entry.kind, entry.description ].
                                                                 some(said => (said ?? '').toLowerCase().includes(wanted)))).
               sort((one, other) => Order === 'fingerprint'
                                        ? one.entries[0]!.thumbprint.localeCompare(other.entries[0]!.thumbprint)
                                        : one.entries[0]!.label.localeCompare(other.entries[0]!.label, undefined, { sensitivity: 'base' }) ||
                                          one.entries[0]!.thumbprint.localeCompare(other.entries[0]!.thumbprint));

}

/**
 * Enter in a field that adds something to a list - a usage, a kind made up -
 * adds it, rather than sending the form it is in: a browser sends a form on
 * Enter in any of its text fields, and the upload went out half told.
 */
function onEnter(Event: KeyboardEvent, Add: () => void): void {
    if (Event.key === 'Enter') {
        Event.preventDefault();
        Add();
    }
}

/** A SHA-256 fingerprint as people compare it: pairs of digits, in capitals, between colons. */
export function fingerprintOf(Thumbprint: string): string {
    return (Thumbprint.toUpperCase().match(/.{1,2}/g) ?? []).join(':');
}


/** The tabs of the page: what it keeps by kind, everything by name, and the upload. */
const allTabs: readonly Tab[] = [
    { id: 'usage',   label: 'By usage',          icon: 'fa-layer-group' },
    { id: 'all',     label: 'All certificates',  icon: 'fa-list'        },
    { id: 'upload',  label: 'Upload',            icon: 'fa-file-import' }
];


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
 * what it says - and one certificate may be kept as several kinds at once.
 *
 * Three tabs. **By usage** is the store kind by kind, each kind a card - and
 * the sections a kind of node adds, each at the end of its group. **All
 * certificates** is every certificate once, by name or by fingerprint, with
 * every kind it is kept as: switched, told what it is for and taken out kind
 * by kind, or deleted as a whole. **Upload** is a box for certificates as text
 * - typed, pasted, or dropped files on, which the node turns into PEM - and
 * the kinds every certificate in it is to be kept as, a kind or a usage made
 * up among them. The node is asked what the box holds as it is filled, and the
 * page says it certificate by certificate before anything goes in.
 *
 * Drawn by view.ts: a change to one certificate draws the page again and
 * changes only what differs, so that the upload, half filled in, keeps its
 * text, its kinds and its label - in a tab not shown as well, since every tab
 * is drawn and only the one shown is visible.
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

        render({ root, url }) {

            const content = shell(root, {
                active:    '/configuration/certificates',
                title,
                subtitle:  Options.subtitle ?? `The roots this ${config.nodeName} believes, what it presents, and the servers it recognises.`,
                actions:   reloadButton(() => load())
            });

            render(content, html`<div class="loading">Loading ...</div>`);

            const mayChange = auth.can('certificates', 'edit');
            const tabs      = mayChange ? allTabs : allTabs.filter(tab => tab.id !== 'upload');

            let cancelled = false;
            let current: S | null = null;

            /** The tab shown. */
            let shown = tabFromURL(tabs, url);

            /** The order of the list of all certificates, and what it is narrowed to. */
            let order:   'name' | 'fingerprint' = 'name';
            let narrow   = '';

            // What the upload has been told and found, for as long as the page
            // is open: the box itself holds its text.
            let found:           InspectedCertificate[] = [];
            let foundProblem:    string | null          = null;
            let ticked                                  = new Set<string>();
            let madeUp:          { kind: string; group: CertificateGroup }[] = [];
            let usagesTicked:    Record<string, Set<string>> = {};
            let usagesMadeUp:    Record<string, string[]>    = {};
            let uploaded:        CertificatesUploaded | null = null;
            let inspection                              = 0;
            let inspectTimer:    ReturnType<typeof setTimeout> | undefined;

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

            /** What a kind is called on the page: the kind of node's word, or the store's description. */
            function kindName(kind: string): string {
                return Options.kinds?.[kind]?.title ?? current?.kinds[kind]?.description ?? kind;
            }

            /** The group a kind is in, as the store says, or as the list it is in says. */
            function groupOf(kind: string): CertificateGroup {
                const store = current!;
                return store.kinds[kind]?.group
                    ?? (store.trustAnchors.includes(kind) ? 'trustAnchor'
                      : store.credentials. includes(kind) ? 'credential'
                      :                                     'recognised');
            }

            /** Every kind the certificate with this id is kept as. */
            function registrationsOf(id: string): Certificate[] {
                return everything().filter(entry => entry.id === id);
            }


            /** Show another tab, and keep it in the address. */
            function show(id: string): void {
                shown = id;
                rememberTab(tabs, id);
                draw();
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

                    ${tabsView(tabs, shown, show, 'The certificate store')}

                    <section class="tab-panel" role="tabpanel" id="panel-usage" aria-labelledby="tab-usage" ?hidden=${shown !== 'usage'}>
                        <p class="hint store-where">
                            One file per certificate and kind below <code>${store.directory}</code>, with
                            <code>index.json</code> beside them recording what each one is called, whether it is
                            switched on and what it is kept for. A certificate copied into a kind's directory is
                            taken in at the next start.
                        </p>
                        <span id="store-error" class="form-error" role="alert"></span>
                        <div id="kinds">${kindsView(store)}</div>
                    </section>

                    <section class="tab-panel" role="tabpanel" id="panel-all" aria-labelledby="tab-all" ?hidden=${shown !== 'all'}>
                        ${allView(store)}
                    </section>

                    ${mayChange ? html`
                        <section class="tab-panel" role="tabpanel" id="panel-upload" aria-labelledby="tab-upload" ?hidden=${shown !== 'upload'}>
                            ${uploadView(store)}
                        </section>` : nothing}

                `);

            }


            // -----------------------------------------------------------------
            // By usage
            // -----------------------------------------------------------------

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


            /** The usages a row says a certificate is marked for. */
            function usagesChips(entry: Certificate): TemplateResult | typeof nothing {

                const offered = usagesOf(current!, entry.kind);

                if (offered.length === 0 && (entry.usages === null || entry.usages === undefined))
                    return nothing;

                return html`<span class="chips usages-of">
                    ${entry.usages === null || entry.usages === undefined
                          ? html`<span class="chip">${current!.credentials.includes(entry.kind) ? 'on every listener' : 'for every use'}</span>`
                          : entry.usages.map(usage => html`<span class="chip">${usageName(usage, Options.usageNames)}</span>`)}
                </span>`;

            }


            /** One certificate as one kind. */
            function row(entry: Certificate): TemplateResult {

                const state   = stateOf(entry, expiringSoon);
                const off     = !mayChange;
                const chips   = Options.rowChips?.(entry, current!) ?? [];
                const usages  = usagesChips(entry);
                const others  = registrationsOf(entry.id).filter(other => other.kind !== entry.kind);
                const key     = `${entry.id}:${entry.kind}`;

                return html`
                    <tr>
                        <td>
                            ${entry.label}
                            ${marksOf(entry, current!.chosen, Options.chosen).map(mark => html`
                                <span class="chip on" title="${mark.title}">${mark.label}</span>
                            `)}
                            <br /><code class="muted" title="SHA-256: ${entry.thumbprint}">${entry.id}</code>
                            ${chips.length > 0 ? html`<br /><span class="chips row-chips">${chips}</span>` : nothing}
                            ${usages === nothing ? nothing : html`<br />${usages}`}
                            ${others.length === 0 ? nothing : html`
                                <br /><span class="chips also-as">
                                    ${others.map(other => html`<span class="chip" title="${kindName(other.kind)}">also ${other.kind}</span>`)}
                                </span>`}
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
                        <td>${actions(entry, key, off, others.length > 0, `[data-error-of="${entry.kind}"]`, `[data-note-of="${entry.kind}"]`)}</td>
                    </tr>
                `;

            }


            /** What may be done to a certificate as one kind: switched, renamed, told its usages, taken out. */
            function actions(entry:   Certificate,
                             key:     string,
                             off:     boolean,
                             others:  boolean,
                             error:   string,
                             note:    string): TemplateResult {

                return html`
                    <button type="button" class="btn small" data-toggle="${key}" ?disabled=${off}
                            @click=${() => void toggle(entry, error, note)}>
                        ${entry.active ? 'Switch off' : 'Switch on'}
                    </button>
                    <button type="button" class="btn small" data-rename="${key}" ?disabled=${off}
                            @click=${() => void rename(entry, error, note)}>
                        Rename
                    </button>
                    <button type="button" class="btn small" data-usages="${key}" ?disabled=${off}
                            @click=${() => editUsages(entry)}>
                        Uses
                    </button>
                    <button type="button" class="btn small danger" data-remove="${key}" ?disabled=${off}
                            @click=${() => void remove(entry, error, note)}>
                        ${others ? 'Remove' : 'Delete'}
                    </button>
                `;

            }


            // -----------------------------------------------------------------
            // All certificates
            // -----------------------------------------------------------------

            /** Every certificate once, by name or by fingerprint, with every kind it is kept as. */
            function allView(store: S): TemplateResult {

                const listed = certificatesOf(store, order, narrow);
                const total  = certificatesOf(store).length;

                return html`

                    <div class="list-controls">
                        <span class="segmented" role="radiogroup" aria-label="Order">
                            <label class="checkbox"><input type="radio" name="order" value="name"        .checked=${order === 'name'}
                                                           @change=${() => { order = 'name';        draw(); }} /> by name</label>
                            <label class="checkbox"><input type="radio" name="order" value="fingerprint" .checked=${order === 'fingerprint'}
                                                           @change=${() => { order = 'fingerprint'; draw(); }} /> by fingerprint</label>
                        </span>
                        <input type="search" id="all-filter" placeholder="Narrow down: a name, a subject, a fingerprint, a kind"
                               .value=${narrow} @input=${(event: Event) => { narrow = (event.target as HTMLInputElement).value; draw(); }} />
                        <span class="muted">${listed.length === total ? `${total} certificate(s)` : `${listed.length} of ${total} certificate(s)`}</span>
                    </div>

                    ${listed.length === 0
                          ? html`<p class="hint">${total === 0 ? 'None.' : 'None that matches.'}</p>`
                          : repeat(listed, one => one.id, one => certificateCard(one.id, one.entries))}

                `;

            }


            /** One certificate, and every kind it is kept as. */
            function certificateCard(id: string, entries: Certificate[]): TemplateResult {

                const first  = entries[0]!;
                const off    = !mayChange;
                const marks  = marksOf(first, current!.chosen, Options.chosen);

                return html`
                    <article class="card certificate-card" data-certificate="${id}">

                        <h3>
                            ${first.label}
                            ${marks.map(mark => html`<span class="chip on" title="${mark.title}">${mark.label}</span>`)}
                        </h3>

                        <div class="certificate-facts">
                            <span>${first.subject}</span>
                            <span class="muted">${[ first.keyAlgorithm + (entries.some(entry => entry.hasPrivateKey) ? ', with private key' : ''),
                                                    ...(first.chainLength > 0 ? [ `+${first.chainLength} sub-CA(s)` ] : []),
                                                    `valid ${new Date(first.notBefore ?? first.notAfter).toISOString().slice(0, 10)} ` +
                                                    `to ${new Date(first.notAfter).toISOString().slice(0, 10)}` ].join(', ')}</span>
                            <code class="fingerprint" title="SHA-256">${fingerprintOf(first.thumbprint)}</code>
                        </div>

                        <div class="table-scroll">
                            <table class="records registrations">
                                <thead>
                                    <tr><th>Kept as</th><th>For</th><th>State</th><th></th></tr>
                                </thead>
                                <tbody>
                                    ${repeat(entries, entry => entry.kind, entry => {
                                        const state = stateOf(entry, expiringSoon);
                                        const usages = usagesChips(entry);
                                        return html`
                                            <tr data-kind="${entry.kind}">
                                                <td>${kindName(entry.kind)}${entry.custom ? html` <span class="chip" title="A kind made up: a mark the node acts on by itself not at all">made up</span>` : nothing}</td>
                                                <td>${usages === nothing ? html`<span class="muted">-</span>` : usages}</td>
                                                <td><span class="chip ${state.tone}">${state.text}</span></td>
                                                <td>
                                                    <button type="button" class="btn small" data-toggle="${id}:${entry.kind}" ?disabled=${off}
                                                            @click=${() => void toggle(entry, `[data-error-of-certificate="${id}"]`, `[data-note-of-certificate="${id}"]`)}>
                                                        ${entry.active ? 'Switch off' : 'Switch on'}
                                                    </button>
                                                    <button type="button" class="btn small" data-usages="${id}:${entry.kind}" ?disabled=${off}
                                                            @click=${() => editUsages(entry)}>Uses</button>
                                                    ${entries.length > 1 ? html`
                                                        <button type="button" class="btn small danger" data-remove="${id}:${entry.kind}" ?disabled=${off}
                                                                @click=${() => void remove(entry, `[data-error-of-certificate="${id}"]`, `[data-note-of-certificate="${id}"]`)}>
                                                            Remove
                                                        </button>` : nothing}
                                                </td>
                                            </tr>
                                        `;
                                    })}
                                </tbody>
                            </table>
                        </div>

                        <div class="form-actions">
                            <button type="button" class="btn small" data-rename-certificate="${id}" ?disabled=${off}
                                    @click=${() => void rename(first, `[data-error-of-certificate="${id}"]`, `[data-note-of-certificate="${id}"]`)}>
                                Rename
                            </button>
                            <button type="button" class="btn small danger" data-delete-certificate="${id}" ?disabled=${off}
                                    @click=${() => void deleteWhole(first, `[data-error-of-certificate="${id}"]`, `[data-note-of-certificate="${id}"]`)}>
                                Delete
                            </button>
                            <span class="form-notice" role="status" data-note-of-certificate="${id}"></span>
                            <span class="form-error"  role="alert"  data-error-of-certificate="${id}"></span>
                        </div>

                    </article>
                `;

            }


            // -----------------------------------------------------------------
            // Upload
            // -----------------------------------------------------------------

            /** The kinds an upload offers, in the order the page shows them, the ones made up here after the store's. */
            function kindsOffered(): { kind: string; group: CertificateGroup; madeUpHere: boolean }[] {

                const store = current!;

                return [
                    ...[ ...store.trustAnchors, ...store.credentials, ...store.recognised ].map(kind => ({ kind, group: groupOf(kind), madeUpHere: false })),
                    ...madeUp.filter(one => store.kinds[one.kind] === undefined).map(one => ({ ...one, madeUpHere: true }))
                ];

            }

            /**
             * Why the certificates in the box cannot be kept as a kind - where
             * none of them can; one that can is reason enough to offer it.
             */
            function whyNot(kind: string): string | null {

                if (found.length === 0)
                    return null;

                const reasons = found.map(certificate => certificate.unsuitable[kind]);

                return reasons.every(reason => reason !== undefined) ? reasons[0]! : null;

            }

            /** The usages a ticked kind is offered: the store's for it, then the ones made up here. */
            function usagesOffered(kind: string): string[] {
                return [ ...new Set([ ...(current!.kinds[kind]?.usages ?? []), ...(usagesMadeUp[kind] ?? []) ]) ];
            }


            /** The upload: the box, what is in it, the kinds to keep it as, and what went in. */
            function uploadView(store: S): TemplateResult {

                const groups: { group: CertificateGroup; heading: string }[] = [
                    { group: 'trustAnchor', heading: `Believed by this ${config.nodeName}` },
                    { group: 'credential',  heading: `Presented by this ${config.nodeName}` },
                    { group: 'recognised',  heading: `Recognised by this ${config.nodeName}` }
                ];

                const offered = kindsOffered();

                return html`
                    <section class="card">
                        <h2><i class="fa-solid fa-file-import"></i> Upload certificates</h2>

                        <form id="import-form" class="form-stack" @submit=${(event: SubmitEvent) => { event.preventDefault(); void doUpload(event.currentTarget as HTMLFormElement); }}>

                            <label for="upload-pem">Certificates, as text</label>
                            ${pemBox({
                                id:         'upload-pem',
                                name:       'pem',
                                rows:       12,
                                onFiles:    (files, box) => void readFiles(files, box),
                                onChanged:  () => inspectSoon()
                            })}
                            <p class="hint">
                                PEM - any number of certificates, and the private keys of the ones this
                                ${config.nodeName} presents. A file dropped on the box or chosen - PEM, DER or PKCS#12 -
                                is read by the ${config.nodeName} and put into the box as PEM, its key included; a
                                certificate it <em>presents</em> has to bring its key. A leaf, the sub-CAs above it and
                                its key are one certificate; several roots one after the other are several.
                                ${hint('importing', store) ?? nothing}
                            </p>
                            <span id="upload-files-note" class="form-error" role="alert"></span>

                            <label>What opens it, if it is a protected PKCS#12 or an encrypted key
                                <input type="password" name="password" autocomplete="off" @input=${() => inspectSoon()} />
                            </label>

                            <div id="upload-found" aria-live="polite">${foundView()}</div>

                            <fieldset class="usages upload-kinds" id="upload-kinds">
                                <legend>What to keep it as</legend>
                                ${groups.map(({ group, heading }) => {
                                    const inGroup = offered.filter(one => one.group === group);
                                    return inGroup.length === 0 ? nothing : html`
                                        <div class="kind-group" data-group="${group}">
                                            <span class="kind-group-heading">${heading}</span>
                                            ${repeat(inGroup, one => one.kind, one => kindChoice(one.kind, one.madeUpHere))}
                                        </div>
                                    `;
                                })}
                                <div class="make-up" id="upload-make-up">
                                    <span class="kind-group-heading">A kind of your own</span>
                                    <input type="text" id="make-up-name" maxlength="32" placeholder="backendRoot" aria-label="Its name"
                                           @keydown=${(event: KeyboardEvent) => onEnter(event, () => makeUpKind())} />
                                    <select id="make-up-group" aria-label="Its group">
                                        <option value="trustAnchor" selected>believed - a root</option>
                                        <option value="credential">presented - with its key</option>
                                        <option value="recognised">recognised - somebody else's</option>
                                    </select>
                                    <button type="button" class="btn small" id="make-up-add" @click=${() => makeUpKind()}>Add</button>
                                    <span class="hint">A mark for a configuration or code to name later; this ${config.nodeName} acts on it by itself not at all.</span>
                                    <span class="form-error" role="alert" id="make-up-error"></span>
                                </div>
                            </fieldset>

                            <label>What to call it, where the box holds one certificate
                                <input type="text" name="label" maxlength="120" placeholder="its common name" ?disabled=${found.length > 1} />
                            </label>

                            <div class="form-actions">
                                <button type="submit" class="btn primary">Import</button>
                                <span id="import-note"  class="form-notice" role="status"></span>
                                <span id="import-error" class="form-error"  role="alert"></span>
                            </div>

                            <div id="upload-result">${resultView()}</div>

                        </form>
                    </section>
                `;

            }


            /** One kind to keep the certificates as, and - ticked - what they are for as it. */
            function kindChoice(kind: string, madeUpHere: boolean): TemplateResult {

                const refused  = whyNot(kind);
                const on       = ticked.has(kind) && refused === null;
                const usages   = usagesOffered(kind);

                return html`
                    <div class="kind-choice" data-kind-choice="${kind}">
                        <label class="checkbox" title="${refused ?? ''}">
                            <input type="checkbox" name="kind" value="${kind}" .checked=${on} ?disabled=${refused !== null}
                                   @change=${(event: Event) => {
                                       if ((event.target as HTMLInputElement).checked) ticked.add(kind); else ticked.delete(kind);
                                       draw();
                                   }} />
                            ${madeUpHere ? html`${kind} <span class="chip">made up</span>` : kindName(kind)}
                        </label>
                        ${refused === null ? nothing : html`<span class="hint unsuitable">${refused}</span>`}
                        ${!on ? nothing : html`
                            <div class="kind-usages" data-usages-of="${kind}">
                                ${repeat(usages, usage => usage, usage => html`
                                    <label class="checkbox">
                                        <input type="checkbox" name="usage-${kind}" value="${usage}" .checked=${usagesTicked[kind]?.has(usage) ?? false}
                                               @change=${(event: Event) => {
                                                   const set = usagesTicked[kind] ??= new Set();
                                                   if ((event.target as HTMLInputElement).checked) set.add(usage); else set.delete(usage);
                                               }} />
                                        ${usageName(usage, Options.usageNames)}
                                    </label>
                                `)}
                                <span class="add-usage">
                                    <input type="text" maxlength="32" placeholder="another usage" aria-label="Another usage for ${kindName(kind)}" data-new-usage="${kind}"
                                           @keydown=${(event: KeyboardEvent) => onEnter(event, () => addUsage(kind, event.currentTarget as HTMLElement))} />
                                    <button type="button" class="btn small" data-add-usage="${kind}" @click=${(event: Event) => addUsage(kind, event.currentTarget as HTMLElement)}>Add</button>
                                </span>
                                <span class="hint">None ticked: ${current!.credentials.includes(kind) ? 'on every listener' : 'for every use'}.</span>
                                <span class="form-error" role="alert" data-usage-error="${kind}"></span>
                            </div>
                        `}
                    </div>
                `;

            }


            /** What the box holds, certificate by certificate, as the node says. */
            function foundView(): TemplateResult | typeof nothing {

                if (foundProblem !== null)
                    return html`<p class="form-error">${foundProblem}</p>`;

                if (found.length === 0)
                    return nothing;

                return html`
                    <p class="hint">The box holds ${found.length} certificate(s):</p>
                    <ul class="found-certificates">
                        ${repeat(found, certificate => certificate.id, certificate => html`
                            <li data-found="${certificate.id}">
                                <strong>${certificate.label}</strong>
                                <code class="muted" title="SHA-256: ${certificate.thumbprint}">${certificate.id}</code>
                                ${certificate.chainLength > 0 ? html`<span class="chip">+${certificate.chainLength} sub-CA(s)</span>` : nothing}
                                ${certificate.hasPrivateKey ? html`<span class="chip">with private key</span>` : nothing}
                                ${certificate.selfSigned ? html`<span class="chip">self-signed</span>` : nothing}
                                ${certificate.inStoreAs.length > 0 ? html`<span class="chip on">in the store as ${certificate.inStoreAs.join(', ')}</span>` : nothing}
                                <span class="muted">valid until ${new Date(certificate.notAfter).toISOString().slice(0, 10)}</span>
                            </li>
                        `)}
                    </ul>
                `;

            }


            /** What the last upload did, certificate by certificate. */
            function resultView(): TemplateResult | typeof nothing {

                if (uploaded === null)
                    return nothing;

                const byId = new Map<string, Certificate[]>();

                for (const entry of uploaded.imported)
                    byId.set(entry.id, [ ...(byId.get(entry.id) ?? []), entry ]);

                return html`
                    <ul class="upload-result">
                        ${[ ...byId.values() ].map(entries => html`
                            <li class="went-in">${entries[0]!.label}: kept as ${entries.map(entry => kindName(entry.kind)).join(', ')}</li>
                        `)}
                        ${uploaded.refused.map(refused => html`
                            <li class="refused" data-refused="${refused.id}"><strong>${refused.label}</strong>: ${refused.error}</li>
                        `)}
                    </ul>
                `;

            }


            /** Ask the node what the box holds, once the typing has stopped. */
            function inspectSoon(): void {
                clearTimeout(inspectTimer);
                inspectTimer = setTimeout(() => void inspectNow(), inspectAfter_ms);
            }

            /** Ask the node what the box holds now - and forget an answer to an earlier question. */
            async function inspectNow(): Promise<void> {

                const box      = content.querySelector<HTMLTextAreaElement>('#upload-pem');
                const password = content.querySelector<HTMLInputElement>('#import-form [name="password"]')?.value ?? '';
                const text     = box?.value.trim() ?? '';
                const asked    = ++inspection;

                if (text.length === 0) {
                    found        = [];
                    foundProblem = null;
                    draw();
                    return;
                }

                try
                {
                    const answer = await api.certificates.inspect({ pem: text, password: password.length > 0 ? password : undefined });

                    if (cancelled || asked !== inspection)
                        return;

                    found        = answer.certificates;
                    foundProblem = null;
                }
                catch (problem)
                {
                    if (cancelled || asked !== inspection)
                        return;

                    found        = [];
                    foundProblem = passwordWanted(problem)
                                       ? 'What is in the box opens only with its password: type it below.'
                                       : errorMessage(problem);
                }

                draw();

            }

            /** Whether the node said that a file or a key opens only with a password. */
            function passwordWanted(problem: unknown): boolean {
                return problem instanceof ApiError && (problem.body as { passwordWanted?: boolean } | undefined)?.passwordWanted === true;
            }


            /**
             * Files chosen or dropped: each read by the node and put into the
             * box as PEM - or why not, file by file.
             */
            async function readFiles(files: File[], box: HTMLTextAreaElement): Promise<void> {

                const said     = must<HTMLElement>(content, '#upload-files-note');
                const password = content.querySelector<HTMLInputElement>('#import-form [name="password"]')?.value ?? '';
                const problems: string[] = [];

                said.textContent = '';

                for (const file of files)
                {

                    if (file.size > largestImport) {
                        problems.push(`'${file.name}' is ${Math.round(file.size / 1024)} kB, and a certificate is a few - almost certainly not the file you meant.`);
                        continue;
                    }

                    try
                    {
                        const answer = await api.certificates.inspect({ content:   await base64Of(file),
                                                                        password:  password.length > 0 ? password : undefined });

                        if (cancelled)
                            return;

                        appendText(box, answer.pem);
                    }
                    catch (problem)
                    {
                        problems.push(passwordWanted(problem)
                                          ? `'${file.name}' opens only with its password: type it below, and drop it again.`
                                          : `'${file.name}': ${errorMessage(problem)}`);
                    }

                }

                if (!cancelled)
                    must<HTMLElement>(content, '#upload-files-note').textContent = problems.join(' ');

            }


            /** A kind of one's own, added to the kinds offered and ticked. */
            function makeUpKind(): void {

                const name  = must<HTMLInputElement>(content, '#make-up-name');
                const group = must<HTMLSelectElement>(content, '#make-up-group').value as CertificateGroup;
                const error = must<HTMLElement>(content, '#make-up-error');
                const kind  = name.value.trim();

                error.textContent = '';

                if (!kindNamePattern.test(kind)) {
                    error.textContent = 'A kind is called by a letter, then letters, digits, \'-\' or \'_\', at most 32 characters.';
                    return;
                }

                if (current!.kinds[kind] === undefined && !madeUp.some(one => one.kind === kind))
                    madeUp = [ ...madeUp, { kind, group } ];

                ticked.add(kind);
                name.value = '';

                draw();

            }


            /** A usage of one's own for a ticked kind, added to what it is offered and ticked. */
            function addUsage(kind: string, button: HTMLElement): void {

                const input = button.parentElement!.querySelector<HTMLInputElement>('input[data-new-usage]')!;
                const error = must<HTMLElement>(content, `[data-usage-error="${kind}"]`);
                const usage = input.value.trim().toLowerCase();

                error.textContent = '';

                if (!usageNamePattern.test(usage)) {
                    error.textContent = 'A usage is called by a letter, then letters, digits, \'-\' or \'_\', at most 32 characters.';
                    return;
                }

                usagesMadeUp[kind] = [ ...new Set([ ...(usagesMadeUp[kind] ?? []), usage ]) ];
                (usagesTicked[kind] ??= new Set()).add(usage);
                input.value = '';

                draw();

            }


            /** The upload: every certificate in the box, as every kind ticked. */
            async function doUpload(form: HTMLFormElement): Promise<void> {

                const note  = must<HTMLElement>(content, '#import-note');
                const error = must<HTMLElement>(content, '#import-error');
                const box   = must<HTMLTextAreaElement>(content, '#upload-pem');

                note.textContent  = '';
                error.textContent = '';

                const text  = box.value.trim();
                const kinds = kindsOffered().filter(one => ticked.has(one.kind) && whyNot(one.kind) === null);

                if (text.length === 0) {
                    error.textContent = 'Paste a certificate into the box, or drop a file on it, first.';
                    return;
                }

                if (kinds.length === 0) {
                    error.textContent = 'Tick at least one kind to keep it as.';
                    return;
                }

                // Every field read before anything is held still: whileSaving
                // disables them, and a disabled field is not in a FormData.
                const data     = new FormData(form);
                const password = String(data.get('password') ?? '');
                const label    = String(data.get('label')    ?? '').trim();

                let done: CertificatesUploaded;

                try
                {
                    done = await whileSaving(content, note, () => api.certificates.upload({
                               kinds:     kinds.map(one => ({
                                              kind:    one.kind,
                                              group:   current!.kinds[one.kind] === undefined ? one.group : undefined,
                                              // Left out for every use; the node refuses a
                                              // certificate for no use.
                                              usages:  (usagesTicked[one.kind]?.size ?? 0) > 0 ? [ ...usagesTicked[one.kind]! ] : undefined
                                          })),
                               pem:       text,
                               password:  password.length > 0 ? password : undefined,
                               label:     label.length    > 0 && found.length <= 1 ? label : undefined
                           }));
                }
                catch (problem)
                {
                    // What was pasted, ticked and typed stays where it was -
                    // and the password, which somebody who mistyped it wants
                    // to correct, not to type again with everything else.
                    const said = problem instanceof ApiError ? problem.body as Partial<CertificatesUploaded> | undefined : undefined;

                    if (said?.refused !== undefined) {
                        uploaded = { imported: said.imported ?? [], refused: said.refused };
                        draw();
                    }

                    must<HTMLElement>(content, '#import-error').textContent = errorMessage(problem);
                    return;
                }

                if (cancelled)
                    return;

                uploaded = done;
                current  = await fetched();

                const all = new Set(done.imported.map(entry => entry.id)).size;

                if (done.refused.length === 0) {

                    // In, every one of them: the upload goes back to an empty
                    // one - the box, and its keys with it, by the form.reset()
                    // below.
                    found        = [];
                    foundProblem = null;
                    ticked       = new Set();
                    madeUp       = [];
                    usagesTicked = {};
                    usagesMadeUp = {};

                    draw();
                    form.reset();

                }
                else
                    draw();

                must<HTMLElement>(content, '#import-note').textContent =
                    done.refused.length === 0
                        ? `Imported ${all} certificate(s), and switched on.`
                        : `Imported ${all} certificate(s); ${done.refused.length} did not go in.`;

            }


            // -----------------------------------------------------------------
            // Changes
            // -----------------------------------------------------------------

            async function toggle(entry: Certificate, error: string, note: string): Promise<void> {
                await change(error, note, () => api.certificates.update(entry.id, { kind: entry.kind, active: !entry.active }));
            }


            async function rename(entry: Certificate, error: string, note: string): Promise<void> {

                // The label is one of the things about a stored certificate
                // that are somebody's to decide; everything else on the row is
                // read out of the file and is not up for editing. It is the
                // certificate's, whichever kinds it is kept as.
                const given = prompt('What should this certificate be called?\n\n' +
                                     'Leave it empty for its own common name.', entry.label);

                if (given !== null)
                    await change(error, note, () => api.certificates.update(entry.id, { label: given.trim().length > 0 ? given.trim() : null }));

            }


            /**
             * Say again what a certificate is for as one kind, in a dialog -
             * among the usages the store offers that kind, or one made up.
             *
             * A dialog with a Save rather than boxes in the row that save on
             * every click: each change is a line in the log, and taking the
             * last tick away on the way to another one would have made the
             * certificate one for every use in between.
             */
            function editUsages(entry: Certificate): void {

                const offered  = [ ...new Set([ ...usagesOf(current!, entry.kind), ...(entry.usages ?? []) ]) ];
                const services = offered.every(usage => usage === 'dns' || usage === 'nts') && offered.length > 0;
                const listener = current!.credentials.includes(entry.kind);

                const dialog = document.createElement('dialog');

                dialog.className = 'test-dialog server-dialog';

                document.body.appendChild(dialog);

                // Both halves explicitly: a browser the charging station's
                // pages were tried in fired no close event at all.
                const dismiss = (): void => { dialog.close(); dialog.remove(); };

                let usages = offered;

                function save(event: SubmitEvent): void {

                    event.preventDefault();

                    const ticked = new FormData(event.currentTarget as HTMLFormElement).getAll('usage').map(String);

                    void (async () => {

                        try
                        {
                            // None ticked is every use again, which the node is
                            // told as null: a list with nothing in it would be
                            // a certificate for no use, and is refused.
                            await whileSaving(dialog, null, () => api.certificates.update(entry.id, { kind: entry.kind, usages: ticked.length > 0 ? ticked : null }));
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

                function another(): void {

                    const input = must<HTMLInputElement>(dialog, '#usages-another');
                    const usage = input.value.trim().toLowerCase();

                    if (!usageNamePattern.test(usage)) {
                        must<HTMLElement>(dialog, '#usages-error').textContent =
                            'A usage is called by a letter, then letters, digits, \'-\' or \'_\', at most 32 characters.';
                        return;
                    }

                    const ticked = new FormData(must<HTMLFormElement>(dialog, '#usages-form')).getAll('usage').map(String);

                    usages = [ ...new Set([ ...usages, usage ]) ];
                    drawDialog([ ...ticked, usage ]);
                    must<HTMLInputElement>(dialog, '#usages-another').value = '';

                }

                function drawDialog(ticked: readonly string[] | null | undefined): void {

                    render(dialog, html`

                        <h2><i class="fa-solid fa-certificate"></i> ${entry.label} - ${kindName(entry.kind)}</h2>

                        <form id="usages-form" class="form-stack" @submit=${save}>

                            <fieldset class="usages">
                                <legend>${listener ? 'Where it is shown' : 'What it is kept for'}</legend>
                                ${repeat(usages, usage => usage, usage => html`
                                    <label class="checkbox">
                                        <input type="checkbox" name="usage" value="${usage}" .checked=${ticked?.includes(usage) ?? false} />
                                        ${usageName(usage, Options.usageNames)}
                                    </label>
                                `)}
                                <span class="add-usage">
                                    <input type="text" id="usages-another" maxlength="32" placeholder="another usage" aria-label="Another usage"
                                           @keydown=${(event: KeyboardEvent) => onEnter(event, another)} />
                                    <button type="button" class="btn small" id="usages-add" @click=${another}>Add</button>
                                </span>
                                <span class="hint">None ticked: ${listener ? 'on every listener' : 'for every use'}.</span>
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

                }

                drawDialog(entry.usages);

                dialog.addEventListener('close',  dismiss);
                dialog.addEventListener('cancel', dismiss);

                dialog.showModal();

            }


            /**
             * Take a certificate out as one kind - or delete it, where that is
             * the only kind it is kept as. Asked once, naming what is about to
             * go.
             */
            async function remove(entry: Certificate, error: string, note: string): Promise<void> {

                const others = registrationsOf(entry.id).filter(other => other.kind !== entry.kind);

                if (others.length === 0) {
                    await deleteWhole(entry, error, note);
                    return;
                }

                if (!confirm(`Take ${entry.label} out as ${kindName(entry.kind)}?\n\n` +
                             `It stays in the store as ${others.map(other => kindName(other.kind)).join(', ')}.`))
                    return;

                await change(error, note, () => api.certificates.remove(entry.id, entry.kind));

            }


            /** Delete a certificate as every kind it is kept as - its files go, and there is no copy anywhere else. */
            async function deleteWhole(entry: Certificate, error: string, note: string): Promise<void> {

                const kinds = registrationsOf(entry.id);

                if (!confirm(`Delete ${entry.label}${kinds.length > 1 ? `, kept as ${kinds.map(one => kindName(one.kind)).join(', ')}` : ''}?\n\n` +
                             `Its file${kinds.length > 1 ? 's are' : ' is'} deleted from the store as well, and ` +
                             `a certificate with a private key cannot be put back without that key.`))
                    return;

                await change(error, note, () => api.certificates.remove(entry.id));

            }


            /** Everything in the store, flattened: each certificate once per kind it is kept as. */
            function everything(): Certificate[] {
                return Object.values(current?.certificates ?? {}).flat();
            }


            /**
             * One change to one certificate, with the page held still while it
             * is made, and then the store drawn again from what the node says
             * now. A refusal - a certificate the node uses, which it does not
             * let go of until another one is chosen - is said where the button
             * was, and brought into view.
             */
            async function change(ErrorAt: string, NoteAt: string, Doing: () => Promise<unknown>): Promise<void> {

                for (const said of content.querySelectorAll<HTMLElement>('[data-error-of], [data-note-of], [data-error-of-certificate], [data-note-of-certificate], #store-error'))
                    said.textContent = '';

                const note = content.querySelector<HTMLElement>(NoteAt);

                try
                {
                    await whileSaving(content, note, Doing);
                }
                catch (problem)
                {
                    const said = content.querySelector<HTMLElement>(ErrorAt);

                    if (said !== null) {
                        said.textContent = errorMessage(problem);
                        said.scrollIntoView({ block: 'nearest' });
                    }

                    return;
                }

                await reloadKinds();

            }


            /** The store again, and what the sections need, and the page drawn again - the upload left as it is. */
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


            async function load(): Promise<void> {

                try
                {
                    const loaded = await fetched();

                    if (!cancelled) {
                        current       = loaded;
                        found         = [];
                        foundProblem  = null;
                        ticked        = new Set();
                        madeUp        = [];
                        usagesTicked  = {};
                        usagesMadeUp  = {};
                        uploaded      = null;
                        sections.forEach(section => section.reset?.());
                        draw();
                        // Loaded anew - Reload - is what the node has: every
                        // form empty, the upload and a section's alike.
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

            // What is pasted, ticked or typed for an upload not yet made is a
            // draft like any other page's: leaving asks first - and so is what
            // is typed into a section's form, a request half filled in or a
            // certificate pasted for one (the energy meter's).
            const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

            void load();

            return () => { cancelled = true; clearTimeout(inspectTimer); release(); };

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
export function base64Of(file: File): Promise<string> {

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
