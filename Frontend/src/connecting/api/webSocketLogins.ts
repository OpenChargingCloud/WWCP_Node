import { request }  from '../../api/client';
import type { I18NString } from './i18n';
import { loginServer } from '../settings';


// Who may sign in at a WebSocket server of a node - and over SSH - and how it
// is asked: the logins and their groups, and the chains a client certificate
// may lead to. Every node with such a server serves them by the same routes -
// NodeHTTPAPI.WebSocketLogins of WWCP_Node -, below a root of its own: a
// node that serves charging stations at "/configuration/ocpp-server", a PKI
// for its registration authorities at "/configuration/ra-server" - see
// loginServer() in ../settings.ts.
//
// One of its names is the name of something else elsewhere, and stays so here:
// a WebSocketLogin is somebody who may sign in to this node - not the
// credentials a connection of ./connections signs in with. A module that
// exports both modules' names names one of them under another name.


/**
 * How a client may authenticate at a WebSocket server: by HTTP authentication
 * without TLS or over it, or by its TLS client certificate - OCPP's security
 * profiles 1, 2 and 3.
 */
export type ClientAuthentication = 'httpAuthWithoutTLS' | 'httpAuthOverTLS' | 'tlsClientCertificate';

/** One chain a client's certificate may lead to. */
export interface TrustedChain {
    id:             string;
    name:           string;
    addedAt:        string;
    enabled:        boolean;
    subject:        string;
    issuer:         string;
    serialNumber:   string;
    thumbprint:     string;
    notBefore:      string;
    notAfter:       string;
    /** Whether it can vouch for others at all, or only for itself. */
    isCA:           boolean;
    intermediates:  number;
    warnings:       string[];
    state:          'pending' | 'valid' | 'expired';
    daysRemaining:  number;
}

/** Which chains a client.s own certificate may lead to. */
export interface ClientTrust {
    directory:   string;
    now:         string;
    enabled:     number;
    maxEntries:  number;
    entries:     TrustedChain[];
}

/** A way a login can prove who it is. */
export type AuthMethod = 'basic' | 'totp' | 'certificate' | 'sshkey' | 'keypin';

/**
 * The key pin of a TLS client key a login is let in by: SHA-256
 * over its SubjectPublicKeyInfo. Nothing about it is secret.
 */
export interface StationKeyPin {
    /** 64 lower-case hexadecimal digits. */
    pin:       string;
    label?:    string;
    added:     string;
    addedBy?:  string;
}

/** An SSH public key a login signs in with over SSH. Nothing about it is secret. */
export interface StationSSHKey {
    /** "SHA256:...", as OpenSSH writes it: what the key is known by. */
    fingerprint:  string;
    /** The authorized_keys line it was given as, its options in front. */
    line:         string;
    label?:       string;
    created:      string;
    createdBy?:   string;
    isDisabled?:  boolean;
}

/**
 * What a login needs in order to be let in with a one-time token.
 *
 * The shared secret is never in here: it is the one credential the controller
 * has to keep readable, so it is handed out once when it is set and never put
 * into the list this page reads.
 */
export interface TOTPSettings {
    validitySeconds:  number;
    length:           number;
    alphabet:         string;
    hashAlgorithm:    'SHA256' | 'SHA384' | 'SHA512';
    /** There, and true, where the token has to be bound to the TLS session of its connection. */
    tlsChannelBinding?: boolean;
}

export { inEnglish, textOf, type I18NString } from './i18n';

/** Somebody who may sign in. */
export interface WebSocketLogin {
    login:        string;
    group:        string;
    enabled:      boolean;
    addedAt:      string;
    hasPassword:  boolean;
    hasTOTP:      boolean;
    totp?:        TOTPSettings;
    hasSSHKey?:   boolean;
    sshKeys?:     StationSSHKey[];
    hasKeyPin?:   boolean;
    keyPins?:     StationKeyPin[];
    description?: I18NString;
}

/** A group of logins, and what its members are allowed to do. */
export interface LoginGroup {
    id:                string;
    name:              string;
    enabled:           boolean;
    builtIn:           boolean;
    addedAt:           string;
    authMethods:       AuthMethod[];
    /** How its members may authenticate - OCPP's security profiles 1, 2 and 3. */
    clientAuthentication:  ClientAuthentication[];
    /** What its stations have over their SSH connection besides OCPP: the names of SSH subsystems. */
    sshChannels?:      string[];
    members:           number;
    description?:      I18NString;
}

/** Who may sign in, and with what. */
export interface WebSocketLogins {
    file:               string;
    enabled:            number;
    maxLogins:        number;
    maxGroups:          number;
    minPasswordLength:  number;
    minSecretLength:    number;
    defaultGroup:       string;
    groups:             LoginGroup[];
    logins:             WebSocketLogin[];
}

/** What a group may be changed to. */
export interface LoginGroupUpdate {
    id?:               string;
    name:              string;
    enabled:           boolean;
    authMethods:       AuthMethod[];
    /** How its members may authenticate - OCPP's security profiles 1, 2 and 3. */
    clientAuthentication:  ClientAuthentication[];
    /** Replaced like everything else about a group: left out, its stations have OCPP alone. */
    sshChannels?:      string[];
    description?:      I18NString;
}

/** What a one-time token may be set to. */
export interface TOTPUpdate {
    sharedSecret?:     string;
    validitySeconds?:  number;
    length?:           number;
    alphabet?:         string;
    hashAlgorithm?:    string;
    group?:            string;
    description?:      I18NString;
}


/**
 * An SSH key's fingerprint as it goes into a URL: without "SHA256:", and in
 * the URL-safe Base64 alphabet, where '/' would be read as a path - as the
 * controller reads it back.
 */
export function fingerprintInURL(fingerprint: string): string {
    return fingerprint.replace(/^SHA256:/, '').replace(/\+/g, '-').replace(/\//g, '_');
}


/** The path of one login, or of something of it, below the root. */
function loginPath(login: string, rest: string = ''): string {
    return `${loginServer().root}/logins/${encodeURIComponent(login)}${rest}`;
}


/**
 * How the logins of a WebSocket server of a node are asked, at the root the
 * kind of node said - see loginServer().
 */
export const webSocketLoginsAPI = {

    trust: {

        get:      ()  => request<ClientTrust>('GET', `${loginServer().root}/trust`),

        add:      (pem: string, name: string) =>
                      request<{ id: string; warnings: string[] }>('POST', `${loginServer().root}/trust`, { pem, name }),

        update:   (id: string, change: { enabled?: boolean; name?: string }) =>
                      request<ClientTrust>('PUT', `${loginServer().root}/trust/${encodeURIComponent(id)}`, change),

        remove:   (id: string) =>
                      request<ClientTrust>('DELETE', `${loginServer().root}/trust/${encodeURIComponent(id)}`)

    },

    logins: {

        get:      ()  => request<WebSocketLogins>('GET', `${loginServer().root}/logins`),

        /**
         * Add a login or give one a new password. An empty password means
         * "make one up", and the made-up one comes back here and nowhere
         * else: it is kept only as a hash.
         */
        save:     (login: string, password: string, group: string, description?: I18NString) =>
                      request<{ login: string; password?: string; logins: WebSocketLogins }>(
                          'POST', `${loginServer().root}/logins`, { login, password, group, description }),

        enable:   (login: string, enabled: boolean) =>
                      request<WebSocketLogins>('PUT', loginPath(login), { enabled }),

        move:     (login: string, group: string) =>
                      request<WebSocketLogins>('PUT', loginPath(login), { group }),

        remove:   (login: string) =>
                      request<WebSocketLogins>('DELETE', loginPath(login)),

        /**
         * Give a login what it needs to be let in with a one-time token. An
         * empty shared secret means "make one up", and it comes back here -
         * the only place it is ever handed out.
         */
        saveTOTP: (login: string, update: TOTPUpdate) =>
                      request<{ login: string; sharedSecret?: string; logins: WebSocketLogins }>(
                          'PUT', loginPath(login, '/totp'), update),

        /**
         * Whether a login's token has to be bound to the TLS session of its
         * connection. Its secret stays as it is.
         */
        bindTOTP:       (login: string, bound: boolean) =>
                      request<WebSocketLogins>('PUT', loginPath(login, '/totp/binding'), { tlsChannelBinding: bound }),

        removeTOTP:     (login: string) =>
                      request<WebSocketLogins>('DELETE', loginPath(login, '/totp')),

        removePassword: (login: string) =>
                      request<WebSocketLogins>('DELETE', loginPath(login, '/password')),

        /**
         * Give a login an SSH key - one line of an authorized_keys file -,
         * adding the login where it is not listed yet. A public key: nothing
         * secret goes either way.
         */
        addSSHKey: (login: string, line: string, label: string, group: string, description?: I18NString) =>
                      request<{ login: string; fingerprint: string; logins: WebSocketLogins }>(
                          'POST', loginPath(login, '/sshKeys'), { line, label, group, description }),

        /** Take a key away; a session it opened ends. */
        removeSSHKey: (login: string, fingerprint: string) =>
                      request<WebSocketLogins>('DELETE', loginPath(login, `/sshKeys/${fingerprintInURL(fingerprint)}`)),

        /**
         * Let a login in by the key pin of its TLS client key - 64 hexadecimal
         * digits, with or without colons, or "sha256//" and base64 - adding
         * the login where it is not listed yet.
         */
        addKeyPin: (login: string, pin: string, label: string, group: string, description?: I18NString) =>
                      request<{ login: string; keyPin: string; logins: WebSocketLogins }>(
                          'POST', loginPath(login, '/keyPins'), { pin, label, group, description }),

        /** Stop letting a login in by a key pin; the pin as the list has it, 64 hexadecimal digits. */
        removeKeyPin: (login: string, pin: string) =>
                      request<WebSocketLogins>('DELETE', loginPath(login, `/keyPins/${encodeURIComponent(pin)}`))

    },

    groups: {

        /** Everything about the group is replaced, not merged. */
        save:     (update: LoginGroupUpdate) =>
                      update.id === undefined
                          ? request<WebSocketLogins>('POST', `${loginServer().root}/groups`, update)
                          : request<WebSocketLogins>('PUT',  `${loginServer().root}/groups/${encodeURIComponent(update.id)}`, update),

        remove:   (id: string) =>
                      request<WebSocketLogins>('DELETE', `${loginServer().root}/groups/${encodeURIComponent(id)}`)

    },

    /**
     * How a client may authenticate at the server itself, as its own route
     * says - which a group can only narrow.
     */
    allowed: async () => loginServer().allowedOf(await request<unknown>('GET', loginServer().root))

};
