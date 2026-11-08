/**
 * The SSH server's page drawn, in a document of happy-dom, against a node that
 * is a stand-in for fetch: what it shows of the server, its host key, who is
 * connected and with which keys every account signs in; what a save sends and
 * what it says back; that a change that ends the sessions is asked about
 * first; and that a switch on the command line that wins is said.
 */

import { asked, open, refused, said, until, type Asked } from '../../test/node.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import type { SSHConfiguration, SSHUpdate } from '../api/client.ts';

const { movesTheServer, ruleLine, sftpSessionsEnding, sshPage, typedRules, when } = await import('./ssh.ts');


/** What the stand-in node has, how it answers a save, and what it was told. */
let held:     SSHConfiguration;
let answer:   ((update: SSHUpdate) => Response | SSHConfiguration) | null = null;

function aServer(Changes: Partial<SSHConfiguration> = {}): SSHConfiguration {
    return {
        enabled:        true,
        port:           22347,
        passwords:      false,
        sftp:           false,
        sftpByDefault:  false,
        listenAddress:  '127.0.0.1',
        url:            'ssh://127.0.0.1:22347',
        defaultPort:    22347,
        file:           'configuration.json',
        configured:     { enabled: true, port: 22347 },
        accessRules:    [],
        commandLine:    {},
        limits:         { loginGraceTime: 30, maxAuthTries: 6, maxSessions: 4, maxConnections: 130,
                          maxUnauthenticated: 10, maxUnauthenticatedPerAddress: 3, clientAliveInterval: 60, clientAliveCountMax: 3,
                          byKind: { account: { maxConnections: 20, connections: 1 }, station: { maxConnections: 100, connections: 0 } } },
        hostKeys:       [ { algorithm: 'ssh-ed25519', fingerprint: 'SHA256:hostkeyhostkey', publicKey: 'ssh-ed25519 AAAAC3host lc@machine',
                            file: 'ssh/ssh_host_ed25519_key', knownHosts: '[127.0.0.1]:22347 ssh-ed25519 AAAAC3host' } ],
        algorithms:     { keyExchange: [ 'mlkem768x25519-sha256', 'curve25519-sha256' ], hostKey: [ 'ssh-ed25519' ],
                          cipher: [ 'chacha20-poly1305@openssh.com' ], mac: [ 'hmac-sha2-256-etm@openssh.com' ], compression: [ 'none' ] },
        sftpAreas:      [ { path: '/logs', read: null, write: null }, { path: '/logs/metrological', read: null, write: null } ],
        connections:    1,
        sessions:       [ { id: 'c1', kind: 'cli', account: 'root', from: '192.0.2.7:51234', key: 'SHA256:rootskey', since: '2026-10-09T08:15:00Z' } ],
        accounts:       [ { account: 'root',    keys: [ { fingerprint: 'SHA256:rootskey', algorithm: 'ssh-ed25519', comment: 'root@laptop',
                                                          label: 'made up at the first start', created: '2026-10-01T10:00:00Z', createdBy: 'the first start', isDisabled: false } ] },
                          { account: 'viewer1', keys: [] } ],
        ...Changes
    };
}

/** How the stand-in node answers. */
function node({ method, path, body }: Asked): unknown {

    if (path === '/configuration/ssh' && method === 'PUT') {
        const update = body as SSHUpdate;
        if (answer !== null)
            return answer(update);
        // Rules sent as lines are the node's to read: a test that sends them says what the node made of them.
        const { accessRules: _rules, ...settings } = update;
        held = { ...held, enabled: update.enabled ?? held.enabled, port: update.port ?? held.port, passwords: update.passwords ?? held.passwords,
                          sftp: update.sftp ?? held.sftp, configured: { ...held.configured, ...settings } };
        return held;
    }

    if (path === '/configuration/ssh')
        return held;

    return undefined;

}

async function opened(Server: Partial<SSHConfiguration> = {}, Permissions = [ 'ssh:read', 'ssh:edit' ]): Promise<HTMLElement> {

    held   = aServer(Server);
    answer = null;

    return open(sshPage, '/configuration/ssh', Permissions, node, root => root.querySelector('#ssh-form') !== null || root.querySelector('.error-box') !== null);

}

const rulesBox    = (root: HTMLElement) => root.querySelector<HTMLTextAreaElement>('#access-rules-form [name="rules"]');
const submitRules = (root: HTMLElement) => root.querySelector<HTMLFormElement>('#access-rules-form')!.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));

const field  = (root: HTMLElement, name: string) => root.querySelector<HTMLInputElement>(`#ssh-form [name="${name}"]`)!;
const submit = (root: HTMLElement) => root.querySelector<HTMLFormElement>('#ssh-form')!.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));
const puts   = () => asked.filter(one => one.method === 'PUT' && one.path === '/configuration/ssh');
const wait   = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));


describe('whether a change moves the SSH server', () => {

    it('is so for another port, switched off or on, and passwords told otherwise - and not for what it has, or a port the command line keeps', () => {

        const now = aServer();

        assert.equal(movesTheServer(now, { enabled: true, passwords: false, port: 22347 }), false, 'what it has');
        assert.equal(movesTheServer(now, { enabled: true, passwords: false, port: 22400 }), true,  'another port');
        assert.equal(movesTheServer(now, { enabled: false, passwords: false }),             true,  'switched off');
        assert.equal(movesTheServer(now, { enabled: true, passwords: true }),               true,  'passwords');
        assert.equal(movesTheServer(aServer({ commandLine: { port: 22347 } }), { enabled: true, passwords: false, port: 22400 }), false,
                     'a port the command line keeps is not moved to');
        assert.equal(movesTheServer(aServer({ enabled: false, url: null, port: 22347 }), { enabled: false, passwords: true }), false,
                     'passwords of a server that is off');
        assert.equal(movesTheServer(now, { enabled: true, passwords: false, sftp: true }),  false, 'SFTP switched on');
        assert.equal(movesTheServer(aServer({ sftp: true }), { enabled: true, passwords: false, sftp: false }), false, 'SFTP switched off');

    });

});


describe('how many sessions of SFTP a change ends', () => {

    it('are those of SFTP where it is switched off, none where it stays on or the server moves, which ends every session', () => {

        const now = aServer({ sftp: true, sessions: [ { id: 'c1',        kind: 'cli',  account: 'root',    from: '192.0.2.7:51234', key: 'SHA256:rootskey', since: '2026-10-09T08:15:00Z' },
                                                      { id: 'c1/sftp-1', kind: 'sftp', account: 'root',    from: '192.0.2.7:51234', key: 'SHA256:rootskey', since: '2026-10-09T08:16:00Z' },
                                                      { id: 'c2/sftp-2', kind: 'sftp', account: 'viewer1', from: '192.0.2.9:40000', key: 'SHA256:viewkey', since: '2026-10-09T08:17:00Z' } ] });

        assert.equal(sftpSessionsEnding(now, { enabled: true, passwords: false, sftp: false }),               2, 'switched off');
        assert.equal(sftpSessionsEnding(now, { enabled: true, passwords: false, sftp: true }),                0, 'left on');
        assert.equal(sftpSessionsEnding(now, { enabled: true, passwords: false }),                            0, 'not said');
        assert.equal(sftpSessionsEnding(now, { enabled: true, passwords: false, sftp: false, port: 22400 }),  0, 'the server moves, and that is asked about instead');
        assert.equal(sftpSessionsEnding(aServer(), { enabled: true, passwords: false, sftp: false }),         0, 'off already');

    });

});


describe('when a session began', () => {

    it('is said in the time zone of the browser, as every other page says a moment - not in UTC, unsaid', () => {

        const zone = process.env['TZ'];

        try
        {
            process.env['TZ'] = 'Europe/Berlin';

            const said = when('2026-10-09T01:38:00Z');

            // The hour as the browser's language writes it: "03:38" in German,
            // "3:38 AM" in English.
            assert.match(said, /(^|\D)0?3:38/, 'a session begun at 03:38 in Berlin');
            assert.doesNotMatch(said, /(^|\D)0?1:38/, 'said in UTC');
            assert.equal(when('no moment'), 'no moment', 'what is no moment is said as it came');
        }
        finally
        {
            if (zone === undefined) delete process.env['TZ']; else process.env['TZ'] = zone;
        }

    });

});


describe('the SSH server page', () => {

    it('shows the server, its host key, who is connected, the keys of the accounts and what it offers', async () => {

        const root = await opened();

        assert.equal(root.querySelector('#ssh-url')?.textContent, 'ssh://127.0.0.1:22347');
        assert.match(root.querySelector('#ssh-connections')!.textContent!, /1 connection/);
        assert.equal(root.querySelector('#ssh-host-keys .fingerprint')?.textContent, 'SHA256:hostkeyhostkey');
        assert.equal(root.querySelector('#ssh-host-keys .known-hosts')?.textContent, '[127.0.0.1]:22347 ssh-ed25519 AAAAC3host');
        assert.match(root.querySelector('#ssh-sessions [data-session="c1"]')!.textContent!, /root.*192\.0\.2\.7:51234.*SHA256:rootskey/s);
        assert.ok(root.querySelector('#ssh-sessions [data-session="c1"]')!.textContent!.includes(when('2026-10-09T08:15:00Z')), 'when the session began');
        assert.match(root.querySelector('#ssh-keys [data-key="SHA256:rootskey"]')!.textContent!, /root.*ssh-ed25519.*made up at the first start.*root@laptop.*by the first start/s);
        assert.match(root.querySelector('#accounts-without-keys')!.textContent!, /viewer1/);
        assert.deepEqual([ ...root.querySelectorAll('[data-algorithms="Key exchange"] .chip') ].map(chip => chip.textContent),
                         [ 'mlkem768x25519-sha256', 'curve25519-sha256' ], 'in the order the server prefers them');
        assert.match(root.querySelector('#ssh-limits')!.textContent!, /within 30 s, at most 6 tries/);
        assert.match(root.querySelector('#ssh-limits')!.textContent!, /at most 130, 10 of them not signed in yet/);
        assert.equal(root.querySelector('#ssh-limits-by-kind')!.textContent!.replace(/\s+/g, ' ').trim(),
                     'account 1 of 20, station 0 of 100 open - ssh.maxConnections', 'each kind, apart');
        assert.equal(field(root, 'port').value, '22347');
        assert.equal(field(root, 'enabled').checked, true);
        assert.equal(field(root, 'passwords').checked, false);
        assert.equal(field(root, 'sftp').checked, false);
        assert.ok(root.querySelector('#sftp-served') === null, 'SFTP is said to be served where it is off');
        assert.ok(root.querySelector('#command-line-wins') === null, 'a switch is said to win where none said anything');
        assert.ok(root.querySelector('#ssh-keys [data-key="SHA256:rootskey"] .chip') === null, 'a key that is on is said to be off');

    });

    it('shows whether SFTP is served, the folders it shows and what each needs, and who is at it', async () => {

        const off  = await opened();

        assert.match(off.querySelector('#ssh-sftp')!.textContent!, /Not served now/);

        const root = await opened({ sftp: true, configured: { enabled: true, port: 22347, sftp: true },
                                    sftpAreas: [ { path: '/logs',  read: null,             write: null },
                                                 { path: '/logos', read: 'providers:read', write: 'providers:edit' } ],
                                    sessions:  [ { id: 'c3/sftp-1', kind: 'sftp', account: 'cpo1', from: '192.0.2.7:51300', key: 'SHA256:cpokey', since: '2026-10-09T08:20:00Z' } ] });

        assert.equal(root.querySelector('#sftp-served')?.textContent, 'and SFTP');
        assert.equal(field(root, 'sftp').checked, true);
        assert.match(root.querySelector('#ssh-sftp')!.textContent!, /^\s*Files over SFTP\s*Served/);
        assert.match(root.querySelector('#ssh-sftp [data-sftp-area="/logs"]')!.textContent!,  /\/logs\s*anybody signed in\s*nobody/);
        assert.match(root.querySelector('#ssh-sftp [data-sftp-area="/logos"]')!.textContent!, /\/logos\s*whoever may providers:read\s*whoever may providers:edit/);
        assert.match(root.querySelector('#ssh-sessions [data-session="c3/sftp-1"]')!.textContent!, /cpo1\s*SFTP\s*192\.0\.2\.7:51300/);

    });

    it('ticks SFTP where the file says nothing and the kind serves it by default - with the server off too, so that switching it on keeps it', async () => {

        const off = await opened({ enabled: false, url: null, sftp: false, sftpByDefault: true, configured: {} });

        assert.equal(field(off, 'sftp').checked, true, 'the default is not shown');
        assert.ok(off.querySelector('#sftp-served') === null, 'SFTP is said to be served while the server is off');

        const said = await opened({ sftp: false, sftpByDefault: true, configured: { enabled: true, port: 22347, sftp: false } });

        assert.equal(field(said, 'sftp').checked, false, 'what the file says does not win over the default');

    });

    it('says which key of an account is switched off', async () => {

        const root = await opened({ accounts: [ { account: 'root', keys: [ { fingerprint: 'SHA256:rootskey', algorithm: 'ssh-ed25519', comment: 'root@laptop', label: null,
                                                                             created: '2026-10-01T10:00:00Z', createdBy: null, isDisabled: true } ] } ] });

        assert.equal(root.querySelector('#ssh-keys [data-key="SHA256:rootskey"] .chip')?.textContent, 'off');

    });

    it('says who is at the command line with a password, and that nobody is where nobody is', async () => {

        const withPassword = await opened({ sessions: [ { id: 'c2', kind: 'cli', account: 'root', from: '192.0.2.8:4000', key: null, since: '2026-10-09T09:00:00Z' } ] });

        assert.match(withPassword.querySelector('#ssh-sessions [data-session="c2"]')!.textContent!, /the command line.*a password/s);

        const nobody = await opened({ sessions: [], connections: 0 });

        assert.match(nobody.querySelector('#ssh-sessions')!.textContent!, /Nobody is connected over SSH/);

    });

    it('says which subsystem a session is of, and what a login a kind lets in besides is', async () => {

        const root = await opened({ sessions: [ { id: 'c4/ocpp@open.charging.cloud-1', kind: 'subsystem', account: 'cs001', principal: 'station',
                                                  subsystem: 'ocpp@open.charging.cloud', label: 'OCPP', from: '10.10.0.5:40000', key: 'SHA256:cskey', since: '2026-10-09T09:00:00Z' },
                                                { id: 'c5', kind: 'cli', account: 'root', principal: 'account',
                                                  subsystem: null, label: null, from: '192.0.2.7:51234', key: 'SHA256:rootskey', since: '2026-10-09T09:01:00Z' } ] });

        const station = root.querySelector('#ssh-sessions [data-session="c4/ocpp@open.charging.cloud-1"]')!.textContent!;
        const account = root.querySelector('#ssh-sessions [data-session="c5"]')!.textContent!;

        assert.match(station, /cs001\s*\(station\)\s*OCPP\s*\(ocpp@open\.charging\.cloud\)\s*10\.10\.0\.5:40000/);
        assert.match(account, /root\s*the command line/);
        assert.doesNotMatch(account, /\(account\)/, 'an account is not said to be one');

    });

    it('saves what is typed, and says what the node said of it', async () => {

        const root = await opened({ sessions: [] });

        field(root, 'port').value = '22400';
        field(root, 'passwords').checked = true;

        answer = update => ({ ...aServer({ sessions: [] }), port: update.port ?? null, passwords: true, url: 'ssh://127.0.0.1:22400',
                              configured: { enabled: true, port: update.port, passwords: true },
                              notice: 'Saved for the next start without that switch.' });

        submit(root);
        await until(() => /^Saved/.test(root.querySelector('#form-note')?.textContent ?? ''), 'the save did not go through');

        assert.deepEqual(puts().map(one => one.body), [ { enabled: true, passwords: true, sftp: false, port: 22400 } ]);
        assert.equal(root.querySelector('#form-note')!.textContent, 'Saved for the next start without that switch.', 'what the node said is not said');
        assert.equal(root.querySelector('#ssh-url')?.textContent, 'ssh://127.0.0.1:22400', 'the page shows what it sent, not what the node took');
        assert.equal(said.length, 0, 'nobody connected, and it asked all the same');

    });

    it('asks before a change that ends the sessions over SSH, and sends nothing when told no', async () => {

        const root     = await opened();
        const yes      = window.confirm;

        field(root, 'port').value = '22400';

        window.confirm = (text?: string) => { said.push(String(text)); return false; };

        try
        {
            submit(root);
            await wait(10);
        }
        finally
        {
            window.confirm = yes;
        }

        assert.match(said.at(-1) ?? '', /1 session\(s\) over SSH end/);
        assert.equal(puts().length, 0, 'told no, it went to the node all the same');

        submit(root);
        await until(() => puts().length === 1, 'told yes, it did not go to the node');

    });

    it('does not ask where nothing moves, and leaves an emptied port to the file', async () => {

        const root = await opened();

        field(root, 'port').value = '';

        submit(root);
        await until(() => puts().length === 1, 'the save did not go to the node');

        assert.deepEqual(puts()[0]!.body, { enabled: true, passwords: false, sftp: false }, 'an emptied port was sent as something');
        assert.equal(said.length, 0, 'it asked although nothing moves');

    });

    it('asks before switching SFTP off ends its sessions, sends nothing when told no, and does not ask where none is open', async () => {

        const root     = await opened({ sftp: true, configured: { enabled: true, port: 22347, sftp: true },
                                        sessions: [ { id: 'c1/sftp-1', kind: 'sftp', account: 'root', from: '192.0.2.7:51234', key: 'SHA256:rootskey', since: '2026-10-09T08:16:00Z' } ] });
        const yes      = window.confirm;

        field(root, 'sftp').checked = false;

        window.confirm = (text?: string) => { said.push(String(text)); return false; };

        try
        {
            submit(root);
            await wait(10);
        }
        finally
        {
            window.confirm = yes;
        }

        assert.match(said.at(-1) ?? '', /SFTP is switched off for this, and 1 session\(s\) of it end/);
        assert.equal(puts().length, 0, 'told no, it went to the node all the same');

        submit(root);
        await until(() => puts().length === 1, 'told yes, it did not go to the node');

        assert.deepEqual(puts()[0]!.body, { enabled: true, passwords: false, sftp: false, port: 22347 });

        // Opened anew, with what was said and asked so far forgotten.
        const nobody   = await opened({ sftp: true, configured: { enabled: true, port: 22347, sftp: true }, sessions: [] });

        field(nobody, 'sftp').checked = false;

        submit(nobody);
        await until(() => puts().length === 1, 'switched off with nobody at it, it did not go to the node');

        assert.equal(said.length, 0, 'it asked although no session of SFTP was open');

    });

    it('refuses a port that is no port before it asks the node, and says a port that is taken where the form is', async () => {

        const root = await opened({ sessions: [] });

        field(root, 'port').value = '70000';
        submit(root);

        assert.match(root.querySelector('#form-error')!.textContent!, /from 1 to 65535/);
        assert.equal(puts().length, 0);

        answer = () => refused(409, 'Port 22400 is taken on this machine. The SSH server goes on on port 22347, and nothing was saved.');

        field(root, 'port').value = '22400';
        submit(root);
        await until(() => /is taken/.test(root.querySelector('#form-error')?.textContent ?? ''), 'the refusal is not said');

        assert.equal(field(root, 'port').value, '22400', 'what was typed is gone after a refusal');

    });

    it('says a switch on the command line that wins over what is saved', async () => {

        const root = await opened({ commandLine: { port: 22999 }, port: 22999, url: 'ssh://127.0.0.1:22999' });

        assert.match(root.querySelector('#command-line-wins')!.textContent!, /--ssh-port 22999.*keeps it on that port/s);

        const off = await opened({ commandLine: { enabled: false }, enabled: false, url: null });

        assert.match(off.querySelector('#command-line-wins')!.textContent!, /--no-ssh.*keeps it off/s);
        assert.match(off.querySelector('#ssh-settings')!.textContent!, /not served over SSH/);

    });

    it('lets somebody who may only look see it, and change nothing', async () => {

        const root = await opened({}, [ 'ssh:read' ]);

        assert.equal(field(root, 'port').disabled,      true);
        assert.equal(field(root, 'enabled').disabled,   true);
        assert.equal(field(root, 'passwords').disabled, true);
        assert.ok(root.querySelector<HTMLButtonElement>('#ssh-form button[type="submit"]')!.disabled, 'the save is offered');
        assert.match(root.querySelector('.notice')!.textContent!, /look at the SSH server/);

    });

    it('copies the known_hosts line, and says so on its button', async () => {

        const root     = await opened();
        const copied: string[] = [];
        const before   = Object.getOwnPropertyDescriptor(navigator, 'clipboard');

        Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (text: string) => { copied.push(text); } }, configurable: true });

        try
        {
            const button = root.querySelector<HTMLButtonElement>('[data-copy="known-hosts"]')!;
            button.click();
            await until(() => button.textContent === 'Copied', 'the button does not say it copied');
            assert.deepEqual(copied, [ '[127.0.0.1]:22347 ssh-ed25519 AAAAC3host' ]);
        }
        finally
        {
            if (before)
                Object.defineProperty(navigator, 'clipboard', before);
        }

    });

});


describe('an SSH access rule, as a line', () => {

    it('is written as the command line writes it, every condition left out where the rule has none', () => {

        assert.equal(ruleLine({ action: 'deny' }), 'deny');
        assert.equal(ruleLine({ action: 'deny', principal: 'account:*', service: 'shell', source: [ '10.0.0.0/8', '192.168.1.0/24' ],
                                localAddress: [ '10.10.0.1' ], authMethod: [ 'password' ], comment: 'the device network' }),
                     'deny principal=account:* service=shell source=10.0.0.0/8,192.168.1.0/24 local=10.10.0.1 auth=password # the device network');

    });

    it('is typed one a line, empty lines and the spaces around a line left out', () => {

        assert.deepEqual(typedRules('  deny principal=account:*  \r\n\r\nallow service=sftp\n   \n'), [ 'deny principal=account:*', 'allow service=sftp' ]);
        assert.deepEqual(typedRules(''), []);

    });

});


describe('the SSH access rules on the SSH server page', () => {

    const rules = [ { action: 'allow' as const, principal: 'station:*', service: 'subsystem:ocpp@open.charging.cloud' },
                    { action: 'deny'  as const, principal: 'account:*', localAddress: [ '10.10.0.1' ], comment: 'the device network' } ];

    it('says where there are none, and offers the form', async () => {

        const root = await opened();

        assert.match(root.querySelector('#no-access-rules')!.textContent!, /No rules/);
        assert.equal(rulesBox(root)!.value, '');

    });

    it('shows the rules numbered, in order, with what each leaves out as everybody, everything, anywhere', async () => {

        const root = await opened({ accessRules: rules });
        const rows = [ ...root.querySelectorAll<HTMLTableRowElement>('#access-rules tbody tr') ];

        assert.deepEqual(rows.map(row => row.dataset['rule']), [ '1', '2' ]);
        assert.deepEqual([ ...rows[0]!.cells ].map(cell => cell.textContent!.trim()),
                         [ '1', 'allow', 'station:*', 'subsystem:ocpp@open.charging.cloud', 'anywhere', 'any address', 'any way', '' ]);
        assert.deepEqual([ ...rows[1]!.cells ].map(cell => cell.textContent!.trim()),
                         [ '2', 'deny', 'account:*', 'everything', 'anywhere', '10.10.0.1', 'any way', 'the device network' ]);
        assert.equal(rulesBox(root)!.value,
                     'allow principal=station:* service=subsystem:ocpp@open.charging.cloud\n' +
                     'deny principal=account:* local=10.10.0.1 # the device network');

    });

    it('sends the rules typed, one a line, and shows what the node made of them', async () => {

        const root = await opened({ sessions: [] });

        rulesBox(root)!.value = 'deny principal=account:* local=10.10.0.1 # the device network\n\n';

        answer = () => ({ ...aServer({ sessions: [] }), accessRules: [ rules[1]! ] });

        submitRules(root);
        await until(() => /^Saved/.test(root.querySelector('#rules-note')?.textContent ?? ''), 'the rules were not saved');

        assert.deepEqual(puts().map(one => one.body), [ { accessRules: [ 'deny principal=account:* local=10.10.0.1 # the device network' ] } ]);
        assert.deepEqual([ ...root.querySelectorAll<HTMLTableRowElement>('#access-rules tbody tr') ].map(row => row.dataset['rule']), [ '1' ]);
        assert.equal(said.length, 0, 'nobody connected, and it asked all the same');

    });

    it('sends no rule at all where every line is emptied - which takes them out', async () => {

        const root = await opened({ sessions: [], accessRules: rules });

        rulesBox(root)!.value = '   \n';

        answer = () => ({ ...aServer({ sessions: [] }) });

        submitRules(root);
        await until(() => puts().length === 1, 'the rules were not sent');

        assert.deepEqual(puts()[0]!.body, { accessRules: [] });

    });

    it('asks before rules that are asked of the sessions open now, and sends nothing when told no', async () => {

        const root = await opened({ accessRules: rules });
        const yes  = window.confirm;

        window.confirm = (text?: string) => { said.push(String(text)); return false; };

        try
        {
            submitRules(root);
            await wait(10);
        }
        finally
        {
            window.confirm = yes;
        }

        assert.match(said.at(-1) ?? '', /1 session\(s\) over SSH open now/);
        assert.equal(puts().length, 0, 'told no, it went to the node all the same');

    });

    it('says what the node refused where the form is, and keeps what was typed', async () => {

        const root = await opened({ sessions: [] });

        answer = () => refused(400, "'ssh.accessRules[0].service' must be \"shell\", \"sftp\" or \"subsystem:<name>\", not 'telnet'.");

        rulesBox(root)!.value = 'deny service=telnet';

        submitRules(root);
        await until(() => /telnet/.test(root.querySelector('#rules-error')?.textContent ?? ''), 'the refusal is not said');

        assert.equal(rulesBox(root)!.value, 'deny service=telnet', 'what was typed is gone after a refusal');

    });

    it('lets somebody who may only look see the rules, and offers no form', async () => {

        const root = await opened({ accessRules: rules }, [ 'ssh:read' ]);

        assert.equal(root.querySelectorAll('#access-rules tbody tr').length, 2);
        assert.equal(rulesBox(root), null, 'the form is offered to somebody who may not change the rules');

    });

});
