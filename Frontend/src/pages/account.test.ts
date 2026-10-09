/**
 * The account page drawn, in a document of happy-dom, against a stand-in for
 * the HTTPExt API: who the account is, and that a save sends the whole of it
 * back with what was changed; the API keys, shown by their beginning, a new
 * one made here and shown once, switched off and on, and removed after a
 * question; the SSH keys, added, switched and removed the same way.
 */

import { answer, asked, open, refused, said, until, type Asked } from '../../test/node.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { Account, AccountAPIKey, AccountSSHKey } from '../api/client.ts';

const { accountPage, beginningOf, organizationNames, typeAndComment, withText } = await import('./account.ts');
const { fingerprintInURL, newAPIKey } = await import('../api/client.ts');


const theKey = 'AbCdEfGh0123456789abcdefghijklmnopqrstuv';

/** What the stand-in has. */
let account:  Account;
let apiKeys:  AccountAPIKey[];
let sshKeys:  AccountSSHKey[];

function anAccount(): Account {
    return {
        '@id':          'alice',
        '@context':     'https://opendata.social/contexts/UsersAPI/user',
        name:           { en: 'Alice' },
        email:          'alice@example.test',
        telephone:      '+49 9131 123456',
        language:       'en',
        privacyLevel:   'Private',
        createdAt:      '2026-10-01T10:00:00Z',
        isAuthenticated: true,
        isDisabled:     false,
        youCanEdit:     true
    };
}

/** How the stand-in answers, below /ext. */
function node({ method, path, body }: Asked): unknown {

    if (path === '/ext/users/alice' && method === 'GET')
        return account;

    if (path === '/ext/users/alice' && method === 'SET')
        return account = body as Account;

    if (path === '/ext/users/alice/organizations')
        return [ { '@id': 'LocalController', name: { en: 'Local Controller' }, _childs: [ { '@id': 'site-a', name: { en: 'Site A' } } ] } ];

    if (path === '/ext/users/alice/APIKeys' && method === 'GET')
        return apiKeys;

    if (path === '/ext/users/alice/APIKeys' && method === 'ADD') {
        const added = body as AccountAPIKey;
        apiKeys = [ ...apiKeys, added ];
        return added;
    }

    if (path.startsWith('/ext/users/alice/APIKeys/')) {
        const key = decodeURIComponent(path.slice('/ext/users/alice/APIKeys/'.length));
        if (method === 'DELETE') { apiKeys = apiKeys.filter(one => one['@id'] !== key); return {}; }
        if (method === 'SET')    { apiKeys = apiKeys.map(one => one['@id'] === key ? { ...one, isDisabled: (body as { isDisabled: boolean }).isDisabled } : one); return {}; }
    }

    if (path === '/ext/users/alice/SSHKeys' && method === 'GET')
        return sshKeys;

    if (path === '/ext/users/alice/SSHKeys' && method === 'ADD') {
        const { line, label } = body as { line: string; label: string };
        if (line.includes('PRIVATE KEY'))
            return refused(400, '', { description: 'That is a private key.' });
        const added = { fingerprint: 'SHA256:new+key/2', line, label, created: '2026-10-09T09:00:00Z' };
        sshKeys = [ ...sshKeys, added ];
        return added;
    }

    if (path.startsWith('/ext/users/alice/SSHKeys/')) {
        const inURL = path.slice('/ext/users/alice/SSHKeys/'.length);
        const match = (one: AccountSSHKey) => fingerprintInURL(one.fingerprint) === inURL;
        if (method === 'DELETE') { sshKeys = sshKeys.filter(one => !match(one)); return {}; }
        if (method === 'SET')    { sshKeys = sshKeys.map(one => match(one) ? { ...one, isDisabled: (body as { isDisabled: boolean }).isDisabled } : one); return {}; }
    }

    return undefined;

}

async function opened(Path = '/account'): Promise<HTMLElement> {

    account = anAccount();
    apiKeys = [ { '@id': theKey, userId: 'alice', description: { en: 'billing export' }, accessRights: 'readOnly', created: '2026-10-02T10:00:00Z' } ];
    sshKeys = [ { fingerprint: 'SHA256:abc+def/ghi', line: 'from="192.0.2.0/24" ssh-ed25519 AAAAC3key alice@laptop', label: 'laptop', created: '2026-10-03T10:00:00Z' } ];

    return open(accountPage, Path, [], node, root => root.querySelector('#account-form') !== null || root.querySelector('.error-box') !== null);

}

const submit = (root: HTMLElement, form: string) => root.querySelector<HTMLFormElement>(form)!.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));
const field  = <T extends HTMLElement = HTMLInputElement>(root: HTMLElement, form: string, name: string) => root.querySelector<T>(`${form} [name="${name}"]`)!;
const sent   = (method: string, path: string) => asked.filter(one => one.method === method && one.path === path);


describe('what the account page reads', () => {

    it('shows an API key by its beginning, as the command line does', () => {
        assert.equal(beginningOf(theKey), 'AbCdEfGh...');
        assert.equal(beginningOf('short'), 'short');
    });

    it('changes words in the language they were in, and in English where there were none', () => {
        assert.deepEqual(withText({ deu: 'Alt' }, 'Neu'), { deu: 'Neu' });
        assert.deepEqual(withText(undefined, 'New'), { en: 'New' });
    });

    it('names the organizations, and the ones below them', () => {
        assert.deepEqual(organizationNames([ { '@id': 'a', name: { en: 'A' }, _childs: [ { '@id': 'b' } ] } ]), [ 'A', 'b' ]);
    });

    it('finds the type and the comment of a key behind its options, quoted spaces and all', () => {
        assert.deepEqual(typeAndComment('from="192.0.2.0/24, 10.0.0.0/8",no-pty ssh-ed25519 AAAAC3key alice at laptop'),
                         { type: 'ssh-ed25519', comment: 'alice at laptop' });
        assert.deepEqual(typeAndComment('ecdsa-sha2-nistp256 AAAAE2key'), { type: 'ecdsa-sha2-nistp256', comment: '' });
    });

    it('puts a fingerprint into a URL as the HTTPExt API reads it back', () => {
        assert.equal(fingerprintInURL('SHA256:ab+cd/ef'), 'ab-cd_ef');
    });

    it('makes an API key of 40 letters and digits, a new one every time', () => {
        const one = newAPIKey();
        assert.match(one, /^[A-Za-z0-9]{40}$/);
        assert.notEqual(newAPIKey(), one);
    });

});


describe('the account page', () => {

    it('opens from the name at the foot of the menu, and shows who the account is', async () => {

        const root = await opened();

        const who  = root.querySelector<HTMLAnchorElement>('#who');

        assert.ok(who !== null, 'the name at the foot of the menu is no link');
        assert.equal(new URL(who.href).pathname, '/account');
        assert.ok(who.classList.contains('active'), 'the link does not say the page is open');

        assert.equal(root.querySelector('#account-id')?.textContent, 'alice');
        assert.equal(root.querySelector('#account-organizations')?.textContent?.trim(), 'Local Controller, Site A');
        assert.equal(field(root, '#account-form', 'name').value,      'Alice');
        assert.equal(field(root, '#account-form', 'email').value,     'alice@example.test');
        assert.equal(field(root, '#account-form', 'telephone').value, '+49 9131 123456');

        assert.deepEqual(asked.filter(one => !one.path.startsWith('/ext/users/alice')), [], 'asked somebody else than the account itself');

    });

    it('sends the whole account back with what was changed - and what was emptied left out', async () => {

        const root = await opened();

        field(root, '#account-form', 'name').value         = 'Alice Liddell';
        field(root, '#account-form', 'email').value        = 'alice@wonderland.test';
        field(root, '#account-form', 'telephone').value    = '';
        field(root, '#account-form', 'mobilePhone').value  = '+49 170 1234567';
        field<HTMLTextAreaElement>(root, '#account-form', 'description').value = 'Down the rabbit hole';

        submit(root, '#account-form');

        await until(() => root.querySelector('#account-note')?.textContent === 'Saved.', 'the save is not said');

        const set = sent('SET', '/ext/users/alice');

        assert.equal(set.length, 1);

        const body = set[0]!.body as Account;

        assert.deepEqual(body.name,         { en: 'Alice Liddell' });
        assert.equal    (body.email,        'alice@wonderland.test');
        assert.equal    (body.mobilePhone,  '+49 170 1234567');
        assert.deepEqual(body.description,  { en: 'Down the rabbit hole' });
        assert.ok       (!('telephone'  in body), 'an emptied telephone was sent as one');
        assert.ok       (!('youCanEdit' in body), 'what GET says about the asker was sent as part of the account');
        assert.equal    (body['privacyLevel'],    'Private', 'what the page does not show was not sent back');
        assert.equal    (body['isAuthenticated'], true,      'what the page does not show was not sent back');
        assert.equal    (body['@context'],        'https://opendata.social/contexts/UsersAPI/user');

        assert.equal(field(root, '#account-form', 'name').value, 'Alice Liddell', 'the form does not show what was saved');

    });

    it('says why a save was refused', async () => {

        const root = await opened();

        answer(one => one.method === 'SET' ? refused(400, '', { description: 'Invalid e-mail address!' }) : node(one));

        submit(root, '#account-form');

        await until(() => (root.querySelector('#account-error')?.textContent ?? '').length > 0, 'a refusal is not said');

        assert.match(root.querySelector('#account-error')!.textContent!, /Invalid e-mail address/);

    });

    it('opens on the tab the address names', async () => {

        const root = await opened('/account?tab=ssh-keys');

        assert.equal(root.querySelector<HTMLElement>('#panel-ssh-keys')!.hidden, false);
        assert.equal(root.querySelector<HTMLElement>('#panel-details')!.hidden,  true);

    });

});


describe('the API keys of the account', () => {

    it('are shown by their beginning, never the whole key', async () => {

        const root = await opened();
        const row  = root.querySelector('#account-api-keys [data-api-key="AbCdEfGh..."]');

        assert.ok(row !== null, 'the key is not listed');
        assert.match(row.textContent!, /billing export/);
        assert.ok(!root.innerHTML.includes(theKey), 'the whole key is on the page');

    });

    it('makes a new one here, sends it as the HTTPExt API takes one, and shows it once', async () => {

        const root = await opened();

        field(root, '#api-key-form', 'description').value = 'monitoring';
        field<HTMLSelectElement>(root, '#api-key-form', 'accessRights').value = 'readWrite';
        field(root, '#api-key-form', 'notAfter').value = '2099-12-31';

        submit(root, '#api-key-form');

        await until(() => root.querySelector('#made-key') !== null, 'the new key is not shown');

        const add  = sent('ADD', '/ext/users/alice/APIKeys');

        assert.equal(add.length, 1);

        const body = add[0]!.body as Record<string, unknown>;
        const made = root.querySelector('#made-key .api-key')!.textContent!;

        assert.match(made, /^[A-Za-z0-9]{40}$/);
        assert.equal(body['@id'],          made, 'the key shown is not the one sent');
        assert.equal(body['@context'],     'https://opendata.social/contexts/UsersAPI/APIKey');
        assert.equal(body['userId'],       'alice');
        assert.deepEqual(body['description'], { en: 'monitoring' });
        assert.equal(body['accessRights'], 'readWrite');
        assert.ok(typeof body['created'] === 'string' && !Number.isNaN(Date.parse(body['created'] as string)), 'no time it was made');
        assert.equal(new Date(body['notAfter'] as string).getFullYear(), 2099);

        assert.ok(root.querySelector(`#account-api-keys [data-api-key="${made.slice(0, 8)}..."]`) !== null, 'the new key is not listed');

        // Shown once: a reload of the page has it no more.
        root.querySelector<HTMLButtonElement>('#reload')!.click();

        await until(() => root.querySelector('#made-key') === null, 'the new key is still shown after a reload');

    });

    it('refuses a key valid until a day that has passed, and sends nothing', async () => {

        const root = await opened();

        field(root, '#api-key-form', 'notAfter').value = '2001-01-01';

        submit(root, '#api-key-form');

        await until(() => (root.querySelector('#api-key-error')?.textContent ?? '').length > 0, 'nothing is said');

        assert.deepEqual(sent('ADD', '/ext/users/alice/APIKeys'), []);

    });

    it('switches one off and on again', async () => {

        const root = await opened();
        const row  = () => root.querySelector('#account-api-keys [data-api-key="AbCdEfGh..."]')!;

        row().querySelector<HTMLButtonElement>('[data-switch]')!.click();

        await until(() => row().querySelector('.chip')!.textContent === 'off', 'it is not shown off');

        assert.deepEqual(sent('SET', `/ext/users/alice/APIKeys/${theKey}`).map(one => one.body), [ { isDisabled: true } ]);
        assert.equal(row().querySelector('[data-switch]')!.textContent!.trim(), 'Switch on');

        row().querySelector<HTMLButtonElement>('[data-switch]')!.click();

        await until(() => sent('SET', `/ext/users/alice/APIKeys/${theKey}`).length === 2, 'it is not switched on');

        assert.deepEqual(sent('SET', `/ext/users/alice/APIKeys/${theKey}`)[1]!.body, { isDisabled: false });

    });

    it('removes one after asking', async () => {

        const root = await opened();

        root.querySelector<HTMLButtonElement>('#account-api-keys [data-api-key="AbCdEfGh..."] [data-remove]')!.click();

        await until(() => root.querySelector('#no-api-keys') !== null, 'it is still listed');

        assert.equal(sent('DELETE', `/ext/users/alice/APIKeys/${theKey}`).length, 1);
        assert.match(said.join('\n'), /Remove the API key AbCdEfGh\.\.\./, 'nobody was asked');
        assert.ok(!said.join('\n').includes(theKey), 'the question says the whole key');

    });

});


describe('the SSH keys of the account', () => {

    it('are listed with their label, fingerprint, type and comment', async () => {

        const root = await opened();
        const row  = root.querySelector('#account-ssh-keys [data-ssh-key="SHA256:abc+def/ghi"]');

        assert.ok(row !== null);
        assert.match(row.textContent!, /laptop.*SHA256:abc\+def\/ghi.*ssh-ed25519.*alice@laptop/s);

    });

    it('adds one, and says why one was refused', async () => {

        const root = await opened();

        field<HTMLTextAreaElement>(root, '#ssh-key-form', 'line').value = '-----BEGIN OPENSSH PRIVATE KEY-----';

        submit(root, '#ssh-key-form');

        await until(() => (root.querySelector('#ssh-key-error')?.textContent ?? '').length > 0, 'the refusal is not said');

        assert.match(root.querySelector('#ssh-key-error')!.textContent!, /private key/);

        field<HTMLTextAreaElement>(root, '#ssh-key-form', 'line').value = 'ssh-ed25519 AAAAC3new bob@desk';
        field(root, '#ssh-key-form', 'label').value = 'desk';

        submit(root, '#ssh-key-form');

        await until(() => root.querySelector('#account-ssh-keys [data-ssh-key="SHA256:new+key/2"]') !== null, 'the key added is not listed');

        assert.deepEqual(sent('ADD', '/ext/users/alice/SSHKeys').at(-1)!.body, { line: 'ssh-ed25519 AAAAC3new bob@desk', label: 'desk' });

    });

    it('switches one off and on by its fingerprint in a URL, and removes one after asking', async () => {

        const root = await opened();
        const row  = () => root.querySelector('#account-ssh-keys [data-ssh-key="SHA256:abc+def/ghi"]');

        row()!.querySelector<HTMLButtonElement>('[data-switch]')!.click();

        await until(() => row()!.textContent!.includes('Switch on'), 'it is not shown off');

        assert.deepEqual(sent('SET', '/ext/users/alice/SSHKeys/abc-def_ghi').map(one => one.body), [ { isDisabled: true } ]);

        row()!.querySelector<HTMLButtonElement>('[data-remove]')!.click();

        await until(() => root.querySelector('#no-ssh-keys') !== null, 'it is still listed');

        assert.equal(sent('DELETE', '/ext/users/alice/SSHKeys/abc-def_ghi').length, 1);
        assert.match(said.join('\n'), /Remove the SSH key laptop/);

    });

});
