/**
 * The account page drawn, in a document of happy-dom, against a stand-in for
 * the HTTPExt API: who the account is, and that a save sends the whole of it
 * back with what was changed; the API keys, named by their hint and hash with
 * the addresses they are bound to, a new one made here or typed in and shown
 * once, bound to addresses or not, switched off and on, and removed after a
 * question; the SSH
 * keys, added, switched and removed the same way.
 */

import { answer, asked, open, refused, said, until, type Asked } from '../../test/node.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { Account, AccountAPIKey, AccountSSHKey } from '../api/client.ts';

const { accountPage, organizationNames, typeAndComment, withText } = await import('./account.ts');
const { apiKeyName, apiKeyProblem, boundAddresses, boundAddressesProblem, fingerprintInURL, newAPIKey } = await import('../api/client.ts');


/** What the stand-in keeps a key as: the HTTPExt API keeps its SHA-256, here a stand-in for that. */
const keptAs = (Key: string) => `kept0${Key.length}0${[ ...Key ].reverse().join('')}`;

/** A key as the HTTPExt API keeps and lists it: its "@id" is its hash, and its hint its beginning. */
const theKey = keptAs('AbCdEfGh0123456789abcdefghijklmnopqrstuv');

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
        const sent  = body as AccountAPIKey;
        const added = { ...sent, '@id': keptAs(sent['@id']), hint: sent['@id'].slice(0, 6) };
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

async function opened(Path = '/account', Keys?: AccountAPIKey[]): Promise<HTMLElement> {

    account = anAccount();
    apiKeys = Keys ?? [ { '@id': theKey, hint: 'AbCdEf', userId: 'alice', description: { en: 'billing export' }, accessRights: 'readOnly', created: '2026-10-02T10:00:00Z' } ];
    sshKeys = [ { fingerprint: 'SHA256:abc+def/ghi', line: 'from="192.0.2.0/24" ssh-ed25519 AAAAC3key alice@laptop', label: 'laptop', created: '2026-10-03T10:00:00Z' } ];

    return open(accountPage, Path, [], node, root => root.querySelector('#account-form') !== null || root.querySelector('.error-box') !== null);

}

const submit = (root: HTMLElement, form: string) => root.querySelector<HTMLFormElement>(form)!.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));
const field  = <T extends HTMLElement = HTMLInputElement>(root: HTMLElement, form: string, name: string) => root.querySelector<T>(`${form} [name="${name}"]`)!;
const sent   = (method: string, path: string) => asked.filter(one => one.method === method && one.path === path);


describe('what the account page reads', () => {

    it('takes an API key of letters, digits and . _ ~ -, of 20 characters or more', () => {
        assert.equal(apiKeyProblem(theKey), null);
        assert.equal(apiKeyProblem('my-own.key_for~debugging'), null);
        assert.equal(apiKeyProblem('a'.repeat(20)), null);
        assert.match(apiKeyProblem('a'.repeat(19)) ?? '', /at least 20 characters; this one has 19/);
        assert.match(apiKeyProblem('with a space in it, long enough') ?? '', /letters, digits and \. _ ~ - only/);
        assert.match(apiKeyProblem('slash/in/it/long/enough/yes') ?? '', /letters, digits/);
        assert.match(apiKeyProblem('Schlüssel-mit-Umlaut-lang-genug') ?? '', /letters, digits/);
    });

    it('reads the addresses a key is bound to, separated by commas or spaces, each once', () => {
        assert.deepEqual(boundAddresses(''), []);
        assert.deepEqual(boundAddresses('  '), []);
        assert.deepEqual(boundAddresses('192.0.2.7, 2001:db8::7  192.0.2.7,,'), [ '192.0.2.7', '2001:db8::7' ]);
    });

    it('takes addresses one by one, and says what is no address, a network or one with a zone', () => {
        assert.equal(boundAddressesProblem([]), null);
        assert.equal(boundAddressesProblem([ '192.0.2.7', '2001:db8::7', '::ffff:192.0.2.7', '::1', '0.0.0.0' ]), null);
        assert.equal(boundAddressesProblem([ '192.0.2.0/24' ]), "'192.0.2.0/24' is a network; an API key is bound to addresses, one by one.");
        assert.equal(boundAddressesProblem([ 'fe80::1%eth0' ]), "'fe80::1%eth0' names a zone; an API key is bound to the address without it.");
        for (const wrong of [ '192.7', '300.1.1.1', '1.2.3.4.5', 'proxy.example', '2001:db8::7::1', '12345::1', '1.2.3.' ])
            assert.equal(boundAddressesProblem([ '192.0.2.7', wrong ]), `'${wrong}' is no IP address.`, wrong);
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

    it('are named by their hint and the beginning of their hash, the key itself kept nowhere', async () => {

        const root = await opened();
        const row  = root.querySelector(`#account-api-keys [data-api-key="${theKey}"]`);

        assert.ok(row !== null, 'the key is not listed');
        assert.equal(row.querySelector('code.api-key')?.textContent, `AbCdEf... #${theKey.slice(0, 8)}`, 'the key is not named by its hint and hash');
        assert.equal(row.querySelector('[data-copy]'), null, 'a button copies what is not the key');
        assert.equal(root.querySelector('#api-key-made'), null, 'a key is shown that was not made here');
        assert.match(row.textContent!, /billing export/);

    });

    it('say which addresses they open the door from, as people write them, and anywhere for the others', async () => {

        const bound = 'Bound0to0two0addresses0abcdefgh';
        const root  = await opened('/account', [
                          { '@id': theKey, userId: 'alice', accessRights: 'readOnly', created: '2026-10-02T10:00:00Z' },
                          { '@id': bound,  userId: 'alice', accessRights: 'readOnly', created: '2026-10-02T11:00:00Z', validRemoteIPAddresses: [ '192.0.2.7', '2001:0db8:0000:0000:0000:0000:0000:0007', '[::1]' ] }
                      ]);

        assert.equal(root.querySelector(`[data-api-key="${bound}"]  .api-key-from`)?.textContent?.trim(), '192.0.2.7, 2001:db8::7, ::1', 'not as people write them');
        assert.equal(root.querySelector(`[data-api-key="${theKey}"] .api-key-from`)?.textContent?.trim(), 'anywhere');

    });

    it('binds a new one to the addresses typed in, each once, and to none where none are', async () => {

        const root = await opened();

        field(root, '#api-key-form', 'from').value = ' 192.0.2.7, 2001:db8::7  192.0.2.7 ';
        submit(root, '#api-key-form');

        await until(() => sent('ADD', '/ext/users/alice/APIKeys').length === 1, 'nothing is sent');

        assert.deepEqual((sent('ADD', '/ext/users/alice/APIKeys')[0]!.body as Record<string, unknown>)['validRemoteIPAddresses'], [ '192.0.2.7', '2001:db8::7' ]);

        await until(() => root.querySelectorAll('#account-api-keys [data-api-key]').length === 2, 'the new key is not listed');

        assert.equal(field(root, '#api-key-form', 'from').value, '', 'the form still has the addresses');

        submit(root, '#api-key-form');

        await until(() => sent('ADD', '/ext/users/alice/APIKeys').length === 2, 'the second is not sent');

        assert.ok(!('validRemoteIPAddresses' in (sent('ADD', '/ext/users/alice/APIKeys')[1]!.body as Record<string, unknown>)), 'a key bound to nothing was sent with addresses');

    });

    it('refuses to bind one to a network, and sends nothing', async () => {

        const root  = await opened();
        const error = () => root.querySelector('#api-key-error')?.textContent ?? '';

        field(root, '#api-key-form', 'from').value = '192.0.2.7 10.0.0.0/8';
        submit(root, '#api-key-form');

        await until(() => error().length > 0, 'nothing is said of the network');

        assert.equal(error(), "'10.0.0.0/8' is a network; an API key is bound to addresses, one by one.");
        assert.deepEqual(sent('ADD', '/ext/users/alice/APIKeys'), []);

    });

    it('makes a new one here when no key is typed in, and sends it as the HTTPExt API takes one', async () => {

        const root = await opened();

        field(root, '#api-key-form', 'description').value = 'monitoring';
        field<HTMLSelectElement>(root, '#api-key-form', 'accessRights').value = 'readWrite';
        field(root, '#api-key-form', 'notAfter').value = '2099-12-31';

        submit(root, '#api-key-form');

        await until(() => root.querySelectorAll('#account-api-keys [data-api-key]').length === 2, 'the new key is not listed');

        const add  = sent('ADD', '/ext/users/alice/APIKeys');

        assert.equal(add.length, 1);

        const body = add[0]!.body as Record<string, unknown>;
        const made = body['@id'] as string;

        assert.match(made, /^[A-Za-z0-9]{40}$/);
        assert.equal(body['@context'],     'https://opendata.social/contexts/UsersAPI/APIKey');
        assert.equal(body['userId'],       'alice');
        assert.deepEqual(body['description'], { en: 'monitoring' });
        assert.equal(body['accessRights'], 'readWrite');
        assert.ok(typeof body['created'] === 'string' && !Number.isNaN(Date.parse(body['created'] as string)), 'no time it was made');
        assert.equal(new Date(body['notAfter'] as string).getFullYear(), 2099);

        assert.equal(root.querySelector(`#account-api-keys [data-api-key="${keptAs(made)}"] code.api-key`)?.textContent, `${made.slice(0, 6)}... #${keptAs(made).slice(0, 8)}`, 'the new key is not listed by its hint and hash');
        assert.equal(root.querySelector('#api-key-made code.api-key')?.textContent, made, 'the new key is not shown once, whole');
        assert.ok(root.querySelector('#api-key-made [data-copy]') !== null, 'no button copies it');

    });

    it('takes the key typed in as it is', async () => {

        const root = await opened();
        const own  = 'my-own.key_for~debugging-1';

        field(root, '#api-key-form', 'key').value = `  ${own} `;
        field(root, '#api-key-form', 'description').value = 'debugging';

        submit(root, '#api-key-form');

        await until(() => sent('ADD', '/ext/users/alice/APIKeys').length === 1, 'nothing is sent');

        assert.equal((sent('ADD', '/ext/users/alice/APIKeys')[0]!.body as Record<string, unknown>)['@id'], own);

        await until(() => root.querySelector(`#account-api-keys [data-api-key="${keptAs(own)}"]`) !== null, 'the key typed in is not listed');

        assert.equal(field(root, '#api-key-form', 'key').value, '', 'the form still has the key');

    });

    it('refuses a key typed in with other characters, or too short, and sends nothing', async () => {

        const root  = await opened();
        const error = () => root.querySelector('#api-key-error')?.textContent ?? '';

        field(root, '#api-key-form', 'key').value = 'a key with spaces, long enough';
        submit(root, '#api-key-form');

        await until(() => error().length > 0, 'nothing is said of the spaces');
        assert.match(error(), /letters, digits and \. _ ~ - only/);

        field(root, '#api-key-form', 'key').value = 'short-key';
        submit(root, '#api-key-form');

        await until(() => /at least 20 characters/.test(error()), 'nothing is said of the length');

        assert.deepEqual(sent('ADD', '/ext/users/alice/APIKeys'), []);

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
        const row  = () => root.querySelector(`#account-api-keys [data-api-key="${theKey}"]`)!;

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

        root.querySelector<HTMLButtonElement>(`#account-api-keys [data-api-key="${theKey}"] [data-remove]`)!.click();

        await until(() => root.querySelector('#no-api-keys') !== null, 'it is still listed');

        assert.equal(sent('DELETE', `/ext/users/alice/APIKeys/${theKey}`).length, 1);
        assert.ok(said.join('\n').includes(`Remove the API key ${apiKeyName({ '@id': theKey, hint: 'AbCdEf', userId: 'alice', accessRights: 'readOnly', created: '' })}?`), 'nobody was asked, or not of the key by its name');

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
