import { nodeAPI, type CertificateRequests, type CertificateStore, type SigningRequest, type SigningRequestToMake } from './api/client';
import { config } from './config';
import { errorMessage, field, formatTimestamp, whileSaving } from './ui';
import { html, nothing, repeat, type TemplateResult } from './view';

const api = nodeAPI();

/**
 * The keys a node makes for itself, on the pages of its certificate store:
 * the form a key and its signing request are made with, and the keys that
 * still wait for their certificate.
 *
 * A certificate with its key arrives in the store by upload, from wherever it
 * was made. The other way round is the better one where it is to be had: the
 * key is made here and never leaves, a signing request is handed to whoever
 * issues certificates - or sent to the CSMS, by a charging station - and only
 * the certificate travels. Until it comes the key is who the node is going to
 * be, so it stands among what the node presents, with the two things there
 * are to do with it: copy the request, or send it. Once it has come it is an
 * identity like every other on the page, and no key that waits.
 *
 * Drawn by the certificates page, which has the store, the tabs and the
 * upload: a panel of it rather than a page of its own - see pages/certificates.ts.
 * Which kinds a node makes keys for is the node's to say, in "requests" of
 * its store; a node that says nothing is offered nothing.
 */


/** What the tab a key is made on is called in the address: "?tab=request". */
export const requestTabId = 'request';


/** What the panel is drawn into, and by. */
export interface RequestsHost<S extends CertificateStore = CertificateStore> {
    /** The element the page draws into: where the panel finds its own fields, and what is held still while something is saved. */
    page:       HTMLElement;
    /** Whether whoever is signed in may make, send and remove keys: "certificates:run", which is less than changing the store. */
    mayRequest: boolean;
    /** Whether the page has an upload for this person: where it has none, a certificate that came back is brought beside its key. */
    mayUpload:  boolean;
    /** The store as the node last said it. */
    store():    S;
    /** The store as the node says it now, after something of the panel's changed it. */
    took(store: S):  void;
    /** The kinds of this page the node makes keys for. */
    kinds():    string[];
    /** What a kind is called on the page. */
    kindName(kind: string):  string;
    /** Draw the page again. */
    draw():     void;
    /** Whether the page is still open: nothing is said to a page that was left. */
    alive():    boolean;
    /** Show a tab of the page. */
    show(tab: string):  void;
}

/** The keys of one page of the store, drawn where the page has room for them. */
export interface RequestsPanel {
    /** Whether the node makes keys for a kind of this page at all. */
    offered():  boolean;
    /** Making a key: the form, and the request that was just made. */
    form():     TemplateResult;
    /** The keys that wait for their certificate, with what there is to do with them - or nothing, where none waits. */
    waiting():  TemplateResult | typeof nothing;
    /** Whether a certificate that comes without its key may be the answer to a request made here. */
    answers():  boolean;
    /** Forget what was chosen and made on the page, as it is loaded anew. */
    reset():    void;
}


/** The keys a node makes for itself, for a page of its certificate store to draw - see RequestsHost. */
export function requestsPanel<S extends CertificateStore = CertificateStore>(Host: RequestsHost<S>): RequestsPanel {

    const content   = Host.page;
    const mayChange = Host.mayRequest;

    /** Whether a certificate is brought beside the key it is for: for whoever may make keys and has no upload. */
    const bringsHere = mayChange && !Host.mayUpload;

    /** The request that was just made, put in front of somebody straight away. */
    let justMade: { id: string; csr: string } | null = null;

    /**
     * The kind, the kind of key and the template chosen in the form, while
     * they are not the ones the node suggests: what the remarks beside the
     * lists, the role, the names and the usages on offer are about.
     */
    let pickedKind:      string | null = null;
    let picked:          string | null = null;
    let pickedTemplate:  string | null = null;


    const requests = (): CertificateRequests | undefined => Host.store().requests;

    function offered(): boolean {
        return requests() !== undefined && Host.kinds().length > 0;
    }

    function answers(): boolean {
        return offered();
    }

    /** Say something in a place of the page - if the place is still there. */
    function say(selector: string, text: string): void {
        const place = content.querySelector<HTMLElement>(selector);
        if (place !== null)
            place.textContent = text;
    }

    /** Say something beside a key, wherever the page shows it. */
    function sayOf(id: string, what: 'note' | 'error', text: string): void {
        content.querySelectorAll<HTMLElement>(`[data-request="${id}"] [data-request-${what}]`).
                forEach(place => { place.textContent = text; });
    }


    function form(): TemplateResult {

        const made = requests();

        if (made === undefined || !offered())
            return html`<p class="hint">This ${config.nodeName} makes no keys: its identities are brought to it, each with its key.</p>`;

        const kinds        = Host.kinds();
        const kind         = pickedKind !== null && kinds.includes(pickedKind) ? pickedKind : kinds[0]!;
        const info         = Host.store().kinds[kind];
        const algorithmId  = picked ?? made.defaultAlgorithm;
        const chosen       = made.algorithms.find(one => one.id === algorithmId);
        const templates    = made.templates.filter(one => one.page === (info?.page ?? 'identities'));
        const template     = templates.find(one => one.id === pickedTemplate) ?? templates[0];
        const purposes     = made.extendedKeyUsages.filter(one => one.id !== template?.purpose);
        const usages       = info?.hasUsages ? info.usages : [];

        return html`

            <div class="cards">

                <section class="card">

                    <h2><i class="fa-solid fa-key"></i> Make a key and a signing request</h2>

                    <p class="hint">
                        The key is made on this ${config.nodeName} and never leaves it; what is handed to whoever
                        issues certificates is the request. Until its certificate comes back the key waits on
                        the first tab of this page - and is an identity like every other once it has.
                    </p>

                    <form id="request-form" class="form-stack" @submit=${create}>

                        ${kinds.length < 2 ? nothing : html`
                            <label>For
                                <select name="kind" id="request-kind" ?disabled=${!mayChange}
                                        @change=${(event: Event) => { pickedKind = (event.target as HTMLSelectElement).value; pickedTemplate = null; Host.draw(); }}>
                                    ${kinds.map(one => html`<option value="${one}" ?selected=${one === kinds[0]}>${Host.kindName(one)}</option>`)}
                                </select>
                            </label>
                        `}

                        <label>Subject
                            <input type="text" name="subject" maxlength="${made.maxSubjectLength}"
                                   placeholder="${template?.asksForNames ? 'meter7.example.org' : 'cs001.example.org'}"
                                   ?disabled=${!mayChange} />
                            <span class="hint">
                                Who this ${config.nodeName} says it is. Plain text is read as a common name; a full
                                distinguished name is taken as written.
                            </span>
                        </label>

                        <label>Key
                            <select name="algorithm" id="request-algorithm" ?disabled=${!mayChange}
                                    @change=${(event: Event) => pick((event.target as HTMLSelectElement).value)}>
                                ${made.algorithms.map(algorithm => html`
                                    <option value="${algorithm.id}" ?selected=${algorithm.id === made.defaultAlgorithm}>
                                        ${algorithm.name}
                                    </option>
                                `)}
                            </select>
                            <span class="hint" id="request-algorithm-remark">${chosen?.remark ?? nothing}</span>
                        </label>

                        ${templates.length < 2 ? nothing : html`
                            <label>Template
                                <select name="template" id="request-template" ?disabled=${!mayChange}
                                        @change=${(event: Event) => pickTemplate((event.target as HTMLSelectElement).value, templates[0]!.id)}>
                                    ${templates.map(one => html`<option value="${one.id}" ?selected=${one.id === templates[0]!.id}>${one.name}</option>`)}
                                </select>
                                <span class="hint" id="request-template-remark">${template?.remark ?? nothing}</span>
                            </label>
                        `}

                        ${template?.role === undefined ? nothing : html`
                            <label>${template.role.label}
                                <input type="text" name="role" id="request-role" list="request-role-list" autocomplete="off"
                                       maxlength="${template.role.maxLength}"
                                       placeholder="${template.role.roles[0] ?? ''}"
                                       ?disabled=${!mayChange} />
                                <datalist id="request-role-list">
                                    ${template.role.roles.map(role => html`<option value="${role}"></option>`)}
                                </datalist>
                                <span class="hint">
                                    Which role the holder of the certificate may play: one of
                                    ${template.role.roles.join(', ')} - or whatever else its server knows.
                                </span>
                            </label>
                        `}

                        ${template?.asksForNames ? html`
                            <label>Reachable as
                                <input type="text" name="reachableAs" id="request-names" autocomplete="off"
                                       placeholder="meter7.example.org, 192.0.2.7"
                                       ?disabled=${!mayChange} />
                                <span class="hint">
                                    The host names and addresses the certificate is to cover, with a blank or a comma
                                    between: whoever connects believes it for these and for no other.
                                </span>
                            </label>
                        ` : nothing}

                        ${usages.length === 0 ? nothing : html`
                            <fieldset class="usages" id="request-usages">
                                <legend>What it is for</legend>
                                ${usages.map(usage => html`
                                    <label class="checkbox">
                                        <input type="checkbox" name="usage" value="${usage}" ?disabled=${!mayChange} />
                                        ${usage}
                                    </label>
                                `)}
                                <span class="hint">None ticked: for every use. It can be told otherwise once it is an identity.</span>
                            </fieldset>
                        `}

                        <details id="request-asks">

                            <summary>What else the request asks for, and what its certificate is called</summary>

                            <label>Label
                                <input type="text" name="label" autocomplete="off" ?disabled=${!mayChange} />
                                <span class="hint">What the identity is called on this page once its certificate has come; its common name where this is left empty.</span>
                            </label>

                            ${made.keyUsages.length === 0 ? nothing : html`
                                <fieldset class="usages" id="request-key-usages">
                                    <legend>Key usage</legend>
                                    <span class="hint">
                                        A signature is always asked for - that is how either end of TLS proves itself -
                                        and enciphering a key where the key is an RSA one. Beside them:
                                    </span>
                                    ${made.keyUsages.map(usage => {
                                        const fits = usage.algorithms.includes(algorithmId);
                                        return html`
                                            <label class="checkbox" title="${usage.remark}">
                                                <input type="checkbox" name="keyUsage" value="${usage.id}"
                                                       ?disabled=${!(mayChange && fits)} />
                                                ${usage.name} <code>${usage.id}</code>
                                                ${fits ? nothing : html`<span class="hint">not with ${chosen?.name ?? 'this key'}</span>`}
                                            </label>
                                        `;
                                    })}
                                </fieldset>
                            `}

                            ${purposes.length === 0 ? nothing : html`
                                <fieldset class="usages" id="request-purposes">
                                    <legend>Extended key usage</legend>
                                    <span class="hint">
                                        <code>${template?.purpose ?? 'clientAuth'}</code> is always asked for: that is what
                                        a key made to this template is for. Beside it:
                                    </span>
                                    ${purposes.map(purpose => html`
                                        <label class="checkbox" title="${purpose.remark}">
                                            <input type="checkbox" name="extendedKeyUsage" value="${purpose.id}"
                                                   ?disabled=${!mayChange} />
                                            ${purpose.name} <code>${purpose.id}</code>
                                        </label>
                                    `)}
                                    <label>Others, as object identifiers
                                        <input type="text" name="otherExtendedKeyUsages" autocomplete="off"
                                               placeholder="1.3.6.1.4.1.311.20.2.2"
                                               ?disabled=${!mayChange} />
                                        <span class="hint">Any number of them, with a blank or a comma between.</span>
                                    </label>
                                </fieldset>
                            `}

                            <span class="hint">
                                Asked for is not granted: what goes into the certificate is the certificate
                                authority's to decide.
                            </span>

                        </details>

                        <div class="notice">
                            <strong>Making a key and holding it up are two questions.</strong> Every kind here
                            can be generated and made into a signing request that a certificate authority will
                            accept. Whether this ${config.nodeName} can then load the certificate that comes back
                            together with its key depends on the runtime underneath - Ed25519, Ed448 and the
                            post-quantum kinds have no key object in .NET today. Such a certificate is kept beside
                            its key rather than refused, and this page says so.
                        </div>

                        <div class="form-actions">
                            <button type="submit" class="btn primary" ?disabled=${!mayChange}>
                                Make a key and a request
                            </button>
                            <span id="request-note"  class="form-notice" role="status"></span>
                            <span id="request-error" class="form-error"  role="alert"></span>
                        </div>

                        <span class="hint">
                            An RSA 4096 or a post-quantum key takes a few seconds to generate.
                            Written to ${made.directory}, the private key readable by nobody else.
                        </span>

                    </form>

                </section>

                ${justMade !== null ? html`
                    <section class="card">
                        <h2><i class="fa-solid fa-file-export"></i> The request, waiting to be collected</h2>
                        <p class="hint">
                            Hand this to whoever issues certificates for this ${config.nodeName}${made.canBeSentToCSMS
                                ? ', or send it to the CSMS from the key on the first tab'
                                : ''}. It is not a secret - it holds the public half of the key and nothing else -
                            and it stays here until the answer comes back: on the Upload tab, without a key.
                        </p>
                        <textarea id="just-made" class="mono" rows="10" readonly .defaultValue=${justMade.csr}></textarea>
                        <div class="form-actions">
                            <button type="button" id="copy-csr" class="btn small" @click=${copyJustMade}>Copy</button>
                            <span id="copy-note" class="form-notice" role="status"></span>
                        </div>
                    </section>
                ` : nothing}

            </div>

        `;

    }

    /** One key that waits: what it is, and what there is to do with it. */
    function card(entry: SigningRequest): TemplateResult {

        const made = requests()!;

        return html`
            <div class="card request" data-request-card="${entry.id}">

                <div class="request-head">
                    <strong>${entry.label ?? entry.subject}</strong>
                    ${entry.certificate !== undefined
                          ? html`<span class="chip warn">certificate cannot be held up</span>`
                          : html`<span class="chip">${entry.sentToCSMSAt !== undefined ? 'request sent to the CSMS' : 'request out'}</span>`}
                </div>

                <dl class="kv">
                    ${entry.label !== null ? html`<dt>Subject</dt> <dd>${entry.subject}</dd>` : nothing}
                    <dt>Key</dt>            <dd>${entry.algorithmName}</dd>
                    <dt>Identification</dt> <dd><code>${entry.id}</code></dd>
                    <dt>Made</dt>           <dd>${formatTimestamp(entry.createdAt)}</dd>
                    <dt>Asks for</dt>
                    <dd>
                        ${entry.templateName}${entry.role ? html`, as <code>${entry.role}</code>` : nothing}:
                        ${[ ...entry.keyUsages, ...entry.extendedKeyUsages ].join(', ')}
                    </dd>
                    ${entry.reachableAs.length > 0 ? html`<dt>Reachable as</dt> <dd>${entry.reachableAs.join(', ')}</dd>` : nothing}
                    <dt>For</dt>            <dd>${entry.usages === null ? 'every use' : entry.usages.join(', ')}</dd>
                    ${entry.sentToCSMSAt !== undefined ? html`
                        <dt>Sent to the CSMS</dt> <dd>${formatTimestamp(entry.sentToCSMSAt)}</dd>
                    ` : nothing}
                </dl>

                ${entry.certificate === undefined ? nothing : html`
                    <div class="notice">
                        A certificate for ${entry.certificate.subject}, issued by ${entry.certificate.issuer} and valid
                        until ${formatTimestamp(entry.certificate.notAfter)}, came back and is kept beside this key.
                        ${entry.certificate.cannotBeHeldUp}
                    </div>
                `}

                <details>
                    <summary>The signing request</summary>
                    <textarea class="mono" rows="8" readonly data-csr="${entry.id}" .defaultValue=${entry.csr}></textarea>
                </details>

                ${bringsHere && entry.certificate === undefined ? html`
                    <details class="request-answer">
                        <summary>The certificate that came back</summary>
                        <label for="request-answer-${entry.id}">Certificate, as PEM</label>
                        <textarea class="mono" rows="8" id="request-answer-${entry.id}" data-answer="${entry.id}"
                                  autocomplete="off" spellcheck="false"
                                  placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                        <p class="hint">With the certificates above it where they came with it. No key: the key is here.</p>
                        <button type="button" class="btn small primary" data-bring-answer="${entry.id}"
                                @click=${() => void bring(entry)}>
                            Bring in
                        </button>
                    </details>
                ` : nothing}

                <div class="form-actions request-actions" data-request="${entry.id}">
                    <button type="button" class="btn small" data-copy-csr="${entry.id}" @click=${() => copyRequest(entry)}>
                        Copy CSR
                    </button>
                    ${made.canBeSentToCSMS ? html`
                        <button type="button" class="btn small" data-send-csr="${entry.id}"
                                title="Send the signing request to the CSMS, in SignCertificate"
                                ?disabled=${!mayChange}
                                @click=${() => void sendToCSMS(entry.id)}>
                            Send to CSMS
                        </button>
                    ` : nothing}
                    <button type="button" class="btn small danger" data-remove-request="${entry.id}"
                            title="Take the key away for good: its request can be answered by nobody afterwards"
                            ?disabled=${!mayChange}
                            @click=${() => void remove(entry)}>
                        Remove
                    </button>
                    <span class="form-notice" role="status" data-request-note></span>
                    <span class="form-error"  role="alert"  data-request-error></span>
                </div>

            </div>
        `;

    }

    /**
     * The keys of this page that have no certificate yet, among what the
     * node presents: not something it can show anybody, and who it is going
     * to be all the same.
     */
    function waiting(): TemplateResult | typeof nothing {

        const made = requests();

        if (made === undefined || !offered())
            return nothing;

        const kinds = Host.kinds();
        const keys  = made.entries.filter(entry => kinds.includes(entry.kind));

        return html`
            <section class="card" id="waiting-keys">

                <h3><i class="fa-solid fa-hourglass-half"></i> Keys waiting for their certificate</h3>

                <p class="hint">
                    Made on this ${config.nodeName}, each with a private key that never leaves it, and shown to
                    nobody yet: a key becomes an identity when the certificate for it comes back - ${bringsHere
                        ? 'pasted beside the key it is for, without a key.'
                        : 'on the Upload tab, without a key, where it is matched to the key whose request it answers.'}
                    ${keys.length === 0 ? 'None waits.' : html`
                        Copy its signing request for whoever issues certificates${made.canBeSentToCSMS
                            ? ', or send it to the CSMS, which answers with the certificate by itself'
                            : ''}.
                    `}
                    ${mayChange ? html`
                        <button type="button" class="btn small" id="make-a-key" @click=${() => Host.show(requestTabId)}>Make a key</button>
                    ` : nothing}
                </p>

                <span class="form-notice" role="status" id="waiting-note"></span>

                ${keys.length === 0 ? nothing : html`
                    <div class="cards">${repeat(keys, entry => entry.id, entry => card(entry))}</div>
                `}

            </section>
        `;

    }


    /**
     * Say beside the list what is worth knowing about the key chosen from
     * it: the remark is drawn for the kind chosen, not for the one the node
     * suggests - and so are the usages a key of that kind can have.
     */
    function pick(algorithm: string): void {
        picked = algorithm === requests()?.defaultAlgorithm ? null : algorithm;
        Host.draw();
    }

    /** The same for the template: its remark, the role it asks for, and what it is reachable as. */
    function pickTemplate(template: string, suggested: string): void {
        pickedTemplate = template === suggested ? null : template;
        Host.draw();
    }

    function copyJustMade(): void {
        const box = content.querySelector<HTMLTextAreaElement>('#just-made');
        if (box === null)
            return;
        box.select();
        void navigator.clipboard?.writeText(box.value).then(
            () => say('#copy-note', 'Copied.'),
            () => say('#copy-note', 'Select it and copy it by hand.')
        );
    }

    /** The request of a key, on the clipboard - or said where to find it, where the browser has none to offer. */
    function copyRequest(entry: SigningRequest): void {

        sayOf(entry.id, 'error', '');

        const byHand = 'Open the signing request above, select it and copy it by hand.';

        if (navigator.clipboard === undefined) {
            sayOf(entry.id, 'note', byHand);
            return;
        }

        void navigator.clipboard.writeText(entry.csr).then(
            () => sayOf(entry.id, 'note', 'Copied.'),
            () => sayOf(entry.id, 'note', byHand)
        );

    }


    async function create(event: SubmitEvent): Promise<void> {

        event.preventDefault();

        const form  = event.currentTarget as HTMLFormElement;
        const note  = content.querySelector<HTMLElement>('#request-note');

        say('#request-note',  '');
        say('#request-error', '');

        // Read before the page is held still: a disabled field is left out
        // of a FormData - which is also how a usage the kind of key chosen
        // cannot have is left out, ticked or not.
        const data    = new FormData(form);
        const list    = (name: string) => field(form, name).split(/[\s,;]+/).filter(one => one.length > 0);
        const text    = (name: string) => { const said = field(form, name); return said.length > 0 ? said : undefined; };
        const ticked  = data.getAll('usage').map(String);

        const asks: SigningRequestToMake = {
            kind:               data.has('kind')     ? field(form, 'kind')     : Host.kinds()[0],
            subject:            field(form, 'subject'),
            algorithm:          field(form, 'algorithm'),
            template:           data.has('template') ? field(form, 'template') : undefined,
            role:               text('role'),
            keyUsages:          data.getAll('keyUsage').map(String),
            extendedKeyUsages:  [ ...data.getAll('extendedKeyUsage').map(String), ...list('otherExtendedKeyUsages') ],
            reachableAs:        data.has('reachableAs') ? list('reachableAs') : undefined,
            usages:             ticked.length > 0 ? ticked : undefined,
            label:              text('label')
        };

        try
        {
            const made = await whileSaving(content, note, () => api.certificates.requests.create(asks));

            if (!Host.alive())
                return;

            justMade        = { id: made.request.id, csr: made.request.csr };
            picked          = null;
            pickedKind      = null;
            pickedTemplate  = null;

            Host.took(made.store as S);
            Host.draw();

            // Made, so no longer typed: the form is empty again, the kind
            // of key and the template back at the ones the node suggests.
            form.reset();

            say('#request-note', 'Made. The request is below, waiting to be collected.');
        }
        catch (problem)
        {
            if (Host.alive())
                say('#request-error', errorMessage(problem));
        }

    }

    /** The request of a key to the CSMS, which answers whether it will sign it - the certificate comes later, by itself. */
    async function sendToCSMS(id: string): Promise<void> {

        sayOf(id, 'note',  '');
        sayOf(id, 'error', '');

        const note = content.querySelector<HTMLElement>(`[data-request="${id}"] [data-request-note]`);

        try
        {
            const sent = await whileSaving(content, note, () => api.certificates.requests.sendToCSMS(id));

            if (!Host.alive())
                return;

            Host.took(sent.store as S);
            Host.draw();

            sayOf(id, 'note', sent.said);
        }
        catch (problem)
        {
            if (Host.alive())
                sayOf(id, 'error', errorMessage(problem));
        }

    }

    /**
     * The certificate that came back for a key, pasted beside it: what the
     * upload does for whoever has one. The node matches it by its public
     * key, so one pasted beside the wrong key is taken in for the right one.
     */
    async function bring(entry: SigningRequest): Promise<void> {

        sayOf(entry.id, 'note',  '');
        sayOf(entry.id, 'error', '');

        const box  = content.querySelector<HTMLTextAreaElement>(`[data-answer="${entry.id}"]`);
        const text = box?.value.trim() ?? '';

        if (text === '') {
            sayOf(entry.id, 'error', 'Paste the certificate that came back for this key.');
            return;
        }

        const note = content.querySelector<HTMLElement>(`[data-request="${entry.id}"] [data-request-note]`);

        try
        {
            const answer = await whileSaving(content, note, () => api.certificates.requests.answer(text));

            if (!Host.alive())
                return;

            if (justMade !== null && justMade.id === answer.requestId)
                justMade = null;

            if (box !== null)
                box.value = '';

            Host.took(answer.store as S);
            Host.draw();

            // Kept beside its key where this runtime cannot hold it up:
            // taken in, and no identity - the warnings say which.
            say('#waiting-note', [ answer.entry !== null
                                       ? `Taken in: ${answer.entry.label} is an identity of this ${config.nodeName} now.`
                                       : 'Taken in, and kept beside its key.',
                                   ...answer.warnings ].join(' '));
        }
        catch (problem)
        {
            if (Host.alive())
                sayOf(entry.id, 'error', errorMessage(problem));
        }

    }

    async function remove(entry: SigningRequest): Promise<void> {

        sayOf(entry.id, 'note',  '');
        sayOf(entry.id, 'error', '');

        // Its request is out there, and whatever comes back for it is of no
        // use afterwards: asked, as for everything that cannot be undone.
        if (!confirm(`Remove the key ${entry.id} for ${entry.subject}? The certificate its signing request asks for cannot be used afterwards.`))
            return;

        const note = content.querySelector<HTMLElement>(`[data-request="${entry.id}"] [data-request-note]`);

        try
        {
            const store = await whileSaving(content, note, () => api.certificates.requests.remove(entry.id));

            if (!Host.alive())
                return;

            if (justMade?.id === entry.id)
                justMade = null;

            Host.took(store as S);
            Host.draw();
        }
        catch (problem)
        {
            if (Host.alive())
                sayOf(entry.id, 'error', errorMessage(problem));
        }

    }

    function reset(): void {
        picked          = null;
        pickedKind      = null;
        pickedTemplate  = null;
        justMade        = null;
    }

    return { offered, form, waiting, answers, reset };

}
