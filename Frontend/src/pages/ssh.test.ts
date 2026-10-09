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

const { movesTheServer, sshPage } = await import('./ssh.ts');


/** What the stand-in node has, how it answers a save, and what it was told. */
let held:     SSHConfiguration;
let answer:   ((update: SSHUpdate) => Response | SSHConfiguration) | null = null;

function aServer(Changes: Partial<SSHConfiguration> = {}): SSHConfiguration {
    return {
        enabled:        true,
        port:           22347,
        passwords:      false,
        listenAddress:  '127.0.0.1',
        url:            'ssh://127.0.0.1:22347',
        defaultPort:    22347,
        file:           'configuration.json',
        configured:     { enabled: true, port: 22347 },
        commandLine:    {},
        limits:         { loginGraceTime: 30, maxAuthTries: 6, maxSessions: 4, maxConnections: 100,
                          maxUnauthenticated: 10, maxUnauthenticatedPerAddress: 3, clientAliveInterval: 60, clientAliveCountMax: 3 },
        hostKeys:       [ { algorithm: 'ssh-ed25519', fingerprint: 'SHA256:hostkeyhostkey', publicKey: 'ssh-ed25519 AAAAC3host lc@machine',
                            file: 'ssh/ssh_host_ed25519_key', knownHosts: '[127.0.0.1]:22347 ssh-ed25519 AAAAC3host' } ],
        algorithms:     { keyExchange: [ 'mlkem768x25519-sha256', 'curve25519-sha256' ], hostKey: [ 'ssh-ed25519' ],
                          cipher: [ 'chacha20-poly1305@openssh.com' ], mac: [ 'hmac-sha2-256-etm@openssh.com' ], compression: [ 'none' ] },
        connections:    1,
        sessions:       [ { id: 'c1', account: 'root', from: '192.0.2.7:51234', key: 'SHA256:rootskey', since: '2026-10-09T08:15:00Z' } ],
        accounts:       [ { account: 'root',    keys: [ { fingerprint: 'SHA256:rootskey', algorithm: 'ssh-ed25519', comment: 'root@laptop',
                                                          label: 'made up at the first start', created: '2026-10-01T10:00:00Z', createdBy: 'the first start' } ] },
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
        held = { ...held, enabled: update.enabled ?? held.enabled, port: update.port ?? held.port, passwords: update.passwords ?? held.passwords,
                          configured: { ...held.configured, ...update } };
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

    });

});


describe('the SSH server page', () => {

    it('shows the server, its host key, who is connected, the keys of the accounts and what it offers', async () => {

        const root = await opened();

        assert.equal(root.querySelector('#ssh-url')?.textContent, 'ssh://127.0.0.1:22347');
        assert.match(root.querySelector('#ssh-connections')!.textContent!, /1 connection/);
        assert.equal(root.querySelector('#ssh-host-keys .fingerprint')?.textContent, 'SHA256:hostkeyhostkey');
        assert.equal(root.querySelector('#ssh-host-keys .known-hosts')?.textContent, '[127.0.0.1]:22347 ssh-ed25519 AAAAC3host');
        assert.match(root.querySelector('#ssh-sessions [data-session="c1"]')!.textContent!, /root.*192\.0\.2\.7:51234.*2026-10-09 08:15.*SHA256:rootskey/s);
        assert.match(root.querySelector('#ssh-keys [data-key="SHA256:rootskey"]')!.textContent!, /root.*ssh-ed25519.*made up at the first start.*root@laptop.*by the first start/s);
        assert.match(root.querySelector('#accounts-without-keys')!.textContent!, /viewer1/);
        assert.deepEqual([ ...root.querySelectorAll('[data-algorithms="Key exchange"] .chip') ].map(chip => chip.textContent),
                         [ 'mlkem768x25519-sha256', 'curve25519-sha256' ], 'in the order the server prefers them');
        assert.match(root.querySelector('#ssh-limits')!.textContent!, /within 30 s, at most 6 tries/);
        assert.equal(field(root, 'port').value, '22347');
        assert.equal(field(root, 'enabled').checked, true);
        assert.equal(field(root, 'passwords').checked, false);
        assert.ok(root.querySelector('#command-line-wins') === null, 'a switch is said to win where none said anything');

    });

    it('says who is at the command line with a password, and that nobody is where nobody is', async () => {

        const withPassword = await opened({ sessions: [ { id: 'c2', account: 'root', from: '192.0.2.8:4000', key: null, since: '2026-10-09T09:00:00Z' } ] });

        assert.match(withPassword.querySelector('#ssh-sessions [data-session="c2"]')!.textContent!, /a password/);

        const nobody = await opened({ sessions: [], connections: 0 });

        assert.match(nobody.querySelector('#ssh-sessions')!.textContent!, /Nobody is at the command line over SSH/);

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

        assert.deepEqual(puts().map(one => one.body), [ { enabled: true, passwords: true, port: 22400 } ]);
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

        assert.deepEqual(puts()[0]!.body, { enabled: true, passwords: false }, 'an emptied port was sent as something');
        assert.equal(said.length, 0, 'it asked although nothing moves');

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
