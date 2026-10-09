import { newAPIKey, nodeAPI, type Account, type AccountAPIKey, type AccountOrganization, type AccountSSHKey, type I18NText } from '../api/client';
import { auth } from '../auth';
import { config } from '../config';
import { must } from '../html';
import type { Page } from '../router';
import { reloadButton, shell } from '../shell';
import { rememberTab, tabFromURL, tabsView, type Tab } from '../tabs';
import { errorMessage, whileSaving } from '../ui';
import { typedSinceDrawn, unsaved } from '../unsaved';
import { html, nothing, render, repeat, type TemplateResult } from '../view';
import { when } from './ssh';

/**
 * The account signed in: who it is - its name, its e-mail address, how to
 * reach it, the organizations it belongs to - and the keys it signs in with
 * besides its password, API keys for a program and SSH keys for the command
 * line, each to add, to switch off and on again, and to remove.
 *
 * Its own and nobody else's: everything here is asked of the HTTPExt API,
 * which keeps the accounts and lets everybody at their own. Opened from the
 * name at the foot of the menu.
 *
 * An API key is made here, in the browser, and shown once, when it is made;
 * the list shows its beginning, which is all anybody needs to tell one from
 * another.
 */

const api = nodeAPI();

const tabs: readonly Tab[] = [
    { id: 'details',  label: 'Details',   icon: 'fa-id-card' },
    { id: 'api-keys', label: 'API keys',  icon: 'fa-key'     },
    { id: 'ssh-keys', label: 'SSH keys',  icon: 'fa-terminal' }
];

/** How much of an API key a list shows, as the command line shows it. */
export const shownOfAKey = 8;

/** The beginning of an API key, as a list shows it. */
export function beginningOf(Key: string): string {
    return Key.length > shownOfAKey ? `${Key.slice(0, shownOfAKey)}...` : Key;
}

/** Words in one language: the first the text has. */
export function firstText(Text: I18NText | undefined): string {
    return Text === undefined ? '' : Object.values(Text)[0] ?? '';
}

/**
 * The same words with one changed: in the language they were in, where they
 * were in one, and in English where there were none.
 */
export function withText(Text: I18NText | undefined, Words: string): I18NText {
    const language = Text !== undefined ? Object.keys(Text)[0] ?? 'en' : 'en';
    return { ...Text, [language]: Words };
}

/** The organizations an account belongs to, and the ones below them, by name. */
export function organizationNames(Organizations: AccountOrganization[]): string[] {
    return Organizations.flatMap(organization => [
               firstText(organization.name) || organization['@id'],
               ...organizationNames(organization._childs ?? [])
           ]);
}

/**
 * The type and the comment of an authorized_keys line: its options first,
 * where it has any - from="...", no-pty - then the type, the key, and what is
 * left is the comment.
 */
export function typeAndComment(Line: string): { type: string; comment: string } {

    const words = Line.trim().match(/(?:[^\s"]+|"[^"]*")+/g) ?? [];
    const at    = words.findIndex(word => /^(ssh-|ecdsa-|sk-|rsa-)/.test(word));

    return at < 0
               ? { type: '', comment: '' }
               : { type: words[at]!, comment: words.slice(at + 2).join(' ') };

}

/** A field emptied is a field not there: the account has no telephone rather than an empty one. */
function setOrDrop(Account: Account, Name: string, Value: string): void {
    if (Value.length > 0)
        Account[Name] = Value;
    else
        delete Account[Name];
}


export const accountPage: Page = {

    title: 'Account',

    render({ root, url }) {

        const content = shell(root, {
            active:    '/account',
            title:     'Your account',
            subtitle:  `Who you are on this ${config.nodeName}, and the keys you sign in with besides your password.`,
            actions:   reloadButton(() => load())
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        const id = auth.user?.username ?? '';

        let cancelled      = false;
        let shown          = tabFromURL(tabs, url);
        let account:        Account | null        = null;
        let organizations:  string[] | null       = null;
        let apiKeys:        AccountAPIKey[]       = [];
        let sshKeys:        AccountSSHKey[]       = [];
        /** The key made last, shown until the page is left or reloaded: it is never shown again. */
        let madeKey:        string | null         = null;


        function show(tab: string): void {
            shown = tab;
            rememberTab(tabs, tab);
            draw();
        }


        function draw(): void {

            if (account === null)
                return;

            render(content, html`

                ${tabsView(tabs, shown, show, 'Your account')}

                <div id="panel-details"  role="tabpanel" aria-labelledby="tab-details"  ?hidden=${shown !== 'details'}>
                    ${detailsCard(account)}
                </div>

                <div id="panel-api-keys" role="tabpanel" aria-labelledby="tab-api-keys" ?hidden=${shown !== 'api-keys'}>
                    ${apiKeysCard()}
                </div>

                <div id="panel-ssh-keys" role="tabpanel" aria-labelledby="tab-ssh-keys" ?hidden=${shown !== 'ssh-keys'}>
                    ${sshKeysCard()}
                </div>

            `);

        }


        /** Who the account is, and the form that changes it. */
        function detailsCard(Account: Account): TemplateResult {

            return html`
                <section class="card" id="account-details">

                    <h2><i class="fa-solid fa-id-card"></i> ${firstText(Account.name) || Account['@id']}</h2>

                    <dl class="facts">
                        <dt>Account</dt>        <dd><code id="account-id">${Account['@id']}</code></dd>
                        <dt>Organizations</dt>  <dd id="account-organizations">${organizations === null
                                                       ? html`<span class="muted">could not be loaded</span>`
                                                       : organizations.length === 0
                                                           ? html`<span class="muted">none</span>`
                                                           : organizations.join(', ')}</dd>
                        ${Account.createdAt   ? html`<dt>Made</dt>              <dd>${when(Account.createdAt)}</dd>`   : nothing}
                        ${Account.lastLoginAt ? html`<dt>Last signed in</dt>    <dd>${when(Account.lastLoginAt)}</dd>` : nothing}
                    </dl>

                    <form id="account-form" class="form-stack" @submit=${onSave}>

                        <label>Name
                            <input type="text" name="name" required value="${firstText(Account.name)}" />
                        </label>

                        <label>E-mail address
                            <input type="email" name="email" required value="${Account.email ?? ''}" />
                        </label>

                        <label>Telephone
                            <input type="tel" name="telephone" value="${Account.telephone ?? ''}" />
                        </label>

                        <label>Mobile phone
                            <input type="tel" name="mobilePhone" value="${Account.mobilePhone ?? ''}" />
                        </label>

                        <label>Homepage
                            <input type="url" name="homepage" value="${Account.homepage ?? ''}" placeholder="https://" />
                        </label>

                        <label>Description
                            <textarea name="description" rows="3" .defaultValue=${firstText(Account.description)}></textarea>
                        </label>

                        <div class="form-actions">
                            <button type="submit" class="btn primary">Save</button>
                            <span id="account-note"  class="form-notice" role="status"></span>
                            <span id="account-error" class="form-error"  role="alert"></span>
                        </div>

                    </form>

                </section>
            `;

        }


        /** The API keys, and the form that makes one. */
        function apiKeysCard(): TemplateResult {

            return html`
                <section class="card" id="account-api-keys">

                    <h2><i class="fa-solid fa-key"></i> API keys</h2>

                    <p class="hint">
                        What a program sends in its <code>API-Key</code> header to act as you. A key switched off opens
                        nothing until it is switched on again; a key removed is gone.
                    </p>

                    ${madeKey === null ? nothing : html`
                        <div class="notice" id="made-key">
                            Your new API key. It is shown here once, and never again - copy it now:
                            <code class="api-key">${madeKey}</code>
                            <button type="button" class="btn small" @click=${(event: Event) => void copy(madeKey!, event.currentTarget as HTMLElement)}>Copy</button>
                        </div>
                    `}

                    ${apiKeys.length === 0
                          ? html`<p class="hint" id="no-api-keys">You have no API key.</p>`
                          : html`
                            <div class="table-scroll">
                              <table class="records">
                                  <thead><tr><th>Key</th><th>Description</th><th>May</th><th>Made</th><th>Valid until</th><th>State</th><th></th></tr></thead>
                                  <tbody>
                                      ${repeat(apiKeys, key => key['@id'], key => html`
                                          <tr data-api-key="${beginningOf(key['@id'])}">
                                              <td><code>${beginningOf(key['@id'])}</code></td>
                                              <td>${firstText(key.description)}</td>
                                              <td>${key.accessRights === 'readOnly' ? 'read' : 'read and write'}</td>
                                              <td>${when(key.created)}</td>
                                              <td>${key.notAfter !== undefined ? when(key.notAfter) : html`<span class="muted">-</span>`}</td>
                                              <td>${key.isDisabled ? html`<span class="chip">off</span>` : html`<span class="chip ok">on</span>`}</td>
                                              <td class="actions">
                                                  <button type="button" class="btn small" data-switch
                                                          @click=${() => void switchAPIKey(key)}>${key.isDisabled ? 'Switch on' : 'Switch off'}</button>
                                                  <button type="button" class="btn small danger" data-remove
                                                          @click=${() => void removeAPIKey(key)}>Remove</button>
                                              </td>
                                          </tr>
                                      `)}
                                  </tbody>
                              </table>
                            </div>
                          `}

                    <form id="api-key-form" class="form-stack" @submit=${onAddAPIKey}>

                        <h3>A new API key</h3>

                        <label>Description
                            <input type="text" name="description" placeholder="What it is for: the billing export" />
                        </label>

                        <label>May
                            <select name="accessRights">
                                <option value="readOnly" selected>read</option>
                                <option value="readWrite">read and write</option>
                            </select>
                        </label>

                        <label>Valid until
                            <input type="date" name="notAfter" />
                            <span class="hint">Left empty, it does not run out.</span>
                        </label>

                        <div class="form-actions">
                            <button type="submit" class="btn primary">Make a key</button>
                            <span id="api-key-error" class="form-error" role="alert"></span>
                        </div>

                    </form>

                </section>
            `;

        }


        /** The SSH keys, and the form that adds one. */
        function sshKeysCard(): TemplateResult {

            return html`
                <section class="card" id="account-ssh-keys">

                    <h2><i class="fa-solid fa-terminal"></i> SSH keys</h2>

                    <p class="hint">
                        The public halves you sign in to the command line over SSH with. A key switched off lets nobody
                        in until it is switched on again; a key removed is gone.
                    </p>

                    ${sshKeys.length === 0
                          ? html`<p class="hint" id="no-ssh-keys">You have no SSH key.</p>`
                          : html`
                            <div class="table-scroll">
                              <table class="records">
                                  <thead><tr><th>Label</th><th>Fingerprint</th><th>Type</th><th>Comment</th><th>Added</th><th>State</th><th></th></tr></thead>
                                  <tbody>
                                      ${repeat(sshKeys, key => key.fingerprint, key => {
                                          const { type, comment } = typeAndComment(key.line);
                                          return html`
                                              <tr data-ssh-key="${key.fingerprint}">
                                                  <td>${key.label ?? html`<span class="muted">-</span>`}</td>
                                                  <td><code>${key.fingerprint}</code></td>
                                                  <td>${type}</td>
                                                  <td>${comment}</td>
                                                  <td>${when(key.created)}</td>
                                                  <td>${key.isDisabled ? html`<span class="chip">off</span>` : html`<span class="chip ok">on</span>`}</td>
                                                  <td class="actions">
                                                      <button type="button" class="btn small" data-switch
                                                              @click=${() => void switchSSHKey(key)}>${key.isDisabled ? 'Switch on' : 'Switch off'}</button>
                                                      <button type="button" class="btn small danger" data-remove
                                                              @click=${() => void removeSSHKey(key)}>Remove</button>
                                                  </td>
                                              </tr>
                                          `;
                                      })}
                                  </tbody>
                              </table>
                            </div>
                          `}

                    <form id="ssh-key-form" class="form-stack" @submit=${onAddSSHKey}>

                        <h3>Another SSH key</h3>

                        <label>Public key
                            <textarea name="line" rows="3" required placeholder="ssh-ed25519 AAAA... you@laptop"></textarea>
                            <span class="hint">One line, as the .pub file beside the key holds it, or as PuTTYgen shows the public key - never the private one.</span>
                        </label>

                        <label>Label
                            <input type="text" name="label" placeholder="Your laptop" />
                        </label>

                        <div class="form-actions">
                            <button type="submit" class="btn primary">Add</button>
                            <span id="ssh-key-error" class="form-error" role="alert"></span>
                        </div>

                    </form>

                </section>
            `;

        }


        /** Copy a key, and say so on the button for a moment. */
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
            const typed = (name: string) => String(data.get(name) ?? '').trim();

            // What GET gave, with what the form changes: SET takes the whole
            // account, and what the page does not show is sent back as it came.
            const changed: Account = { ...account!, name: withText(account!.name, typed('name')), email: typed('email') };

            setOrDrop(changed, 'telephone',    typed('telephone'));
            setOrDrop(changed, 'mobilePhone',  typed('mobilePhone'));
            setOrDrop(changed, 'homepage',     typed('homepage'));

            if (typed('description').length > 0)
                changed.description = withText(account!.description, typed('description'));
            else
                delete changed.description;

            void save(changed, form);

        }


        async function save(changed: Account, form: HTMLFormElement): Promise<void> {

            const note = must<HTMLElement>(content, '#account-note');

            note.textContent = '';
            must<HTMLElement>(content, '#account-error').textContent = '';

            try
            {
                // The answer is the account as it now stands.
                account = await whileSaving(content, note, () => api.account.save(changed));

                draw();
                form.reset();

                must<HTMLElement>(content, '#account-note').textContent = 'Saved.';
            }
            catch (problem)
            {
                must<HTMLElement>(content, '#account-error').textContent = errorMessage(problem);
            }

        }


        function onAddAPIKey(event: SubmitEvent): void {

            event.preventDefault();

            const form      = event.currentTarget as HTMLFormElement;
            const data      = new FormData(form);
            const until     = String(data.get('notAfter') ?? '');
            const error     = must<HTMLElement>(content, '#api-key-error');

            error.textContent = '';

            // The end of the day chosen, in this browser's time zone: a key
            // "valid until the 31st" opens on the 31st.
            const notAfter  = until.length > 0 ? new Date(`${until}T23:59:59`) : null;

            if (notAfter !== null && (Number.isNaN(notAfter.getTime()) || notAfter.getTime() <= Date.now())) {
                error.textContent = 'A key valid until a day that has passed would open nothing.';
                return;
            }

            const key = newAPIKey();

            void (async () => {

                try
                {

                    await api.account.apiKeys.add(id, {
                        key,
                        description:   String(data.get('description') ?? '').trim(),
                        accessRights:  data.get('accessRights') === 'readWrite' ? 'readWrite' : 'readOnly',
                        ...(notAfter !== null ? { notAfter: notAfter.toISOString() } : {})
                    });

                    madeKey = key;
                    form.reset();

                    await loadKeys();

                }
                catch (problem)
                {
                    must<HTMLElement>(content, '#api-key-error').textContent = errorMessage(problem);
                }

            })();

        }


        async function switchAPIKey(Key: AccountAPIKey): Promise<void> {

            const error = must<HTMLElement>(content, '#api-key-error');

            error.textContent = '';

            try
            {
                await api.account.apiKeys.switchTo(id, Key['@id'], !Key.isDisabled);
                await loadKeys();
            }
            catch (problem)
            {
                must<HTMLElement>(content, '#api-key-error').textContent = errorMessage(problem);
            }

        }


        async function removeAPIKey(Key: AccountAPIKey): Promise<void> {

            if (!confirm(`Remove the API key ${beginningOf(Key['@id'])}? A program that uses it is turned away from now on, and it cannot be brought back.`))
                return;

            must<HTMLElement>(content, '#api-key-error').textContent = '';

            try
            {
                await api.account.apiKeys.remove(id, Key['@id']);
                await loadKeys();
            }
            catch (problem)
            {
                must<HTMLElement>(content, '#api-key-error').textContent = errorMessage(problem);
            }

        }


        function onAddSSHKey(event: SubmitEvent): void {

            event.preventDefault();

            const form  = event.currentTarget as HTMLFormElement;
            const data  = new FormData(form);

            must<HTMLElement>(content, '#ssh-key-error').textContent = '';

            void (async () => {

                try
                {
                    await api.account.sshKeys.add(id, String(data.get('line') ?? '').trim(), String(data.get('label') ?? '').trim());
                    form.reset();
                    await loadKeys();
                }
                catch (problem)
                {
                    must<HTMLElement>(content, '#ssh-key-error').textContent = errorMessage(problem);
                }

            })();

        }


        async function switchSSHKey(Key: AccountSSHKey): Promise<void> {

            must<HTMLElement>(content, '#ssh-key-error').textContent = '';

            try
            {
                await api.account.sshKeys.switchTo(id, Key.fingerprint, !Key.isDisabled);
                await loadKeys();
            }
            catch (problem)
            {
                must<HTMLElement>(content, '#ssh-key-error').textContent = errorMessage(problem);
            }

        }


        async function removeSSHKey(Key: AccountSSHKey): Promise<void> {

            if (!confirm(`Remove the SSH key ${Key.label ?? Key.fingerprint}? Nobody signs in with it from now on, and it cannot be brought back - only added again.`))
                return;

            must<HTMLElement>(content, '#ssh-key-error').textContent = '';

            try
            {
                await api.account.sshKeys.remove(id, Key.fingerprint);
                await loadKeys();
            }
            catch (problem)
            {
                must<HTMLElement>(content, '#ssh-key-error').textContent = errorMessage(problem);
            }

        }


        /** The keys anew, after a change: what the node now has. */
        async function loadKeys(): Promise<void> {

            const [ loadedAPIKeys, loadedSSHKeys ] = await Promise.all([ api.account.apiKeys.list(id), api.account.sshKeys.list(id) ]);

            if (cancelled)
                return;

            apiKeys = loadedAPIKeys;
            sshKeys = loadedSSHKeys;

            draw();

        }


        async function load(): Promise<void> {

            try
            {

                const [ loaded, loadedAPIKeys, loadedSSHKeys, loadedOrganizations ] = await Promise.all([
                    api.account.get(id),
                    api.account.apiKeys.list(id),
                    api.account.sshKeys.list(id),
                    // Only shown: an account page without them is still one.
                    api.account.organizations(id).then(organizationNames, () => null)
                ]);

                if (cancelled)
                    return;

                account        = loaded;
                apiKeys        = loadedAPIKeys;
                sshKeys        = loadedSSHKeys;
                organizations  = loadedOrganizations;
                madeKey        = null;

                // Loaded anew - Reload - is what the node has, the forms too.
                draw();

                for (const form of content.querySelectorAll<HTMLFormElement>('form'))
                    form.reset();

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`
                        <div class="error-box">Your account could not be loaded: ${errorMessage(problem)}</div>
                    `);
            }

        }

        const release = unsaved.heldBy(() => typedSinceDrawn(content.querySelector('#account-form'))  ||
                                             typedSinceDrawn(content.querySelector('#api-key-form'))  ||
                                             typedSinceDrawn(content.querySelector('#ssh-key-form')));

        void load();

        return () => { cancelled = true; release(); };

    }

};
