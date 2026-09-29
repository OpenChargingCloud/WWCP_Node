import { config } from '../config';


// What the JSON API every node has answers: the routes WWCP_Node's NodeHTTPAPI
// serves below /api/v1, whatever the kind of node. Everything but the sign-in
// needs the session cookie, which the browser sends by itself because every
// request here is same-origin.
//
// A kind of node builds its own client on this: its own resources, status,
// configuration and kinds of certificate, named in nodeAPI() at the end, and
// its own routes on top, which go through the same request().


// ---------------------------------------------------------------------------
// The log
// ---------------------------------------------------------------------------

/** How loudly a log entry asks to be read. */
export type LogLevel = 'debug' | 'info' | 'notice' | 'warning' | 'error' | 'critical';

/** The levels in the order the node defines them, quietest first. */
export const logLevels: LogLevel[] = ['debug', 'info', 'notice', 'warning', 'error', 'critical'];

/** One thing that happened inside the node. */
export interface LogEntry {
    /** A number that only ever grows, so the page can tell what it has seen. */
    id:             number;
    timestamp:      string;
    level:          LogLevel;
    /** What it is about: "http", "dns", "nts", ... - without the level. */
    tags:           string[];
    message:        string;
    /** Whatever else belongs to it, when there is more than one line to say. */
    data?:          unknown;
    /** Bears on the time or the trust, and was signed into the metrological log as well. */
    metrological?:  true;
}

/** What a page of the log brings back. */
export interface LogPage {
    /** The newest id of the whole log, whatever this page was filtered by. */
    lastId:    number;
    capacity:  number;
    tags:      string[];
    entries:   LogEntry[];
}


// ---------------------------------------------------------------------------
// Who may do what
// ---------------------------------------------------------------------------

/** What a role may be allowed to touch on every node. A kind of node adds its own. */
export type NodeResource = 'configuration' | 'dns' | 'nts' | 'certificates';

/** How a resource may be touched. */
export type Operation = 'read' | 'edit' | 'run';

/**
 * What somebody signed in may do: an operation on a resource, written
 * "dns:edit".
 *
 * A copy of what the node enforces, not the enforcement: it is here so a page
 * can grey out what this person may not do instead of offering it and letting
 * them find out by being refused. Every request is checked again on arrival,
 * so editing this list in a browser buys a button that answers 403. Spelt out
 * resource by resource by the node, so "*" never arrives here.
 */
export type Permission<R extends string = NodeResource> = `${R}:${Operation}`;

/** Who is signed in to the web interface, as every node says it. A kind of node may say more. */
export interface NodeMe<R extends string = NodeResource> {
    username:       string;
    roles:          string[];
    permissions:    Permission<R>[];
    /**
     * Whether the log is for them: what the log itself would answer. A kind
     * of node decides what it takes - a sign-in, or a permission its drivers
     * do not have - and the pages follow the log, and offer its page, as this
     * says rather than working the rule out for themselves.
     */
    mayReadTheLog:  boolean;
}


// ---------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------

/** How the node is doing right now, as every node says it. A kind of node may say more. */
export interface NodeStatus {
    service:    string;
    version:    string;
    hermod:     string | null;
    timestamp:  string;
    startedAt:  string;
    uptime:     string;
    sessions:   number;
    log:        { entries: number; capacity: number; lastId: number; tags: string[] };
}

/**
 * What the node is made of. Only the shape a page relies on is named; the
 * rest is rendered from whatever the node sends, so that a new section on the
 * server needs no change here. A kind of node adds its own sections.
 */
export interface NodeConfiguration {
    http:  Record<string, unknown>;
    web:   Record<string, unknown>;
    log:   Record<string, unknown>;
    time:  Record<string, unknown>;
}


// ---------------------------------------------------------------------------
// What a server is held to
// ---------------------------------------------------------------------------

/** What a certificate other than the one a server is held to comes to. */
export type PinMismatch = 'refuse' | 'record' | 'accept';

/** What a server is held to from the first time it is believed. */
export type TrustOnFirstUse = 'root' | 'certificate';

/**
 * What one server is held to beyond what every server is held to, as the
 * node reads it back: the certificates it may show and the roots its chain
 * may end at - any one of them - what a mismatch comes to, and what it learns
 * the first time it is believed. Every fingerprint is a SHA-256 one, in the
 * 64 lower-case digits the node keeps.
 */
export interface ServerPins {
    /** The first certificate and root once more, as they were read when there could be only one of each. */
    certificate:      string | null;
    root:             string | null;
    certificates:     string[];
    roots:            string[];
    onMismatch:       PinMismatch;
    trustOnFirstUse:  TrustOnFirstUse | null;
}

/**
 * What a server is held to, in the keys its entry is written with: one of a
 * kind under the singular key, several under the plural - the way the
 * configuration file says it, and the way the node takes it back.
 */
export interface PinKeys {
    certificateFingerprint?:   string;
    certificateFingerprints?:  string[];
    rootFingerprint?:          string;
    rootFingerprints?:         string[];
    onMismatch?:               PinMismatch;
    trustOnFirstUse?:          TrustOnFirstUse;
}

/** What a server was last believed with - pinned or not, another one is noticed. */
export interface KnownServer {
    certificate:  string;
    root:         string | null;
    since:        string;
}

/** What the node made of a server's certificate, in one word. */
export type JudgementOutcome = 'accepted' | 'recorded' | 'tolerated'
                             | 'pinMismatch' | 'untrusted' | 'wrongName' | 'noCertificate';

/** What the node made of the certificate a server showed, the last time it showed one. */
export interface ServerJudgement {
    server:       string;
    service:      string;
    at:           string;
    /** Whether the server was used: "recorded" and "tolerated" are, although a fingerprint did not match. */
    accepted:     boolean;
    outcome:      JudgementOutcome;
    certificate:  string | null;
    root:         string | null;
    /** The node's own root it was validated by, where this machine knows none. */
    anchoredBy:   string | null;
    heldTo:       Pick<ServerPins, 'certificate' | 'root' | 'certificates' | 'roots'> | null;
    /** What it was held to from this connection on, trusted on first use. */
    learned:      TrustOnFirstUse | null;
    /** What it had been believed with before, where this was another certificate. */
    previously:   KnownServer | null;
    /** Only in the answer to a test: what was found, one step after another. */
    steps?:       { level: 'info' | 'notice' | 'warning' | 'error'; text: string }[];
}


// ---------------------------------------------------------------------------
// Name resolution
// ---------------------------------------------------------------------------

/**
 * One name server as the node is told it: what its configuration keeps, with
 * what it is held to where it is asked over TLS or HTTPS.
 */
export interface DNSServerEntry extends PinKeys {
    /** An IP address or a host name. */
    address:              string;
    port:                 number;
    transport:            string;
    queryTimeoutSeconds:  number | null;
    /**
     * What the page showed the server held to, in the keys above: the node
     * changes only what was changed on the page, and keeps what the server
     * learned while the page was open. Only on a server the page loaded, and
     * never read back.
     */
    pinsAsShown?:         PinKeys;
}

/**
 * One name server the node asks, and what the node says about it: what it is
 * held to once more, the way the NTS answer has it, what was made of its
 * certificate last, and what it was last believed with. Those three are read
 * and never sent back.
 */
export interface DNSServer extends DNSServerEntry {
    heldTo?:     ServerPins | null;
    judgement?:  ServerJudgement | null;
    known?:      KnownServer | null;
}

/** What may be changed about the name resolution while the node runs. */
export interface DNSSettings {
    queryTimeoutSeconds:  number;
    /** null leaves it to the server's own default. */
    recursionDesired:     boolean | null;
    useCache:             boolean;
    dnssecOK:             boolean;
    followCNAMEs:         boolean;
    maxCNAMEFollows:      number;
    maxRetries:           number;
}

/** How the node resolves names. */
export interface DNSConfiguration {
    enabled:    boolean;
    servers:    DNSServer[];
    settings:   DNSSettings;
    /** What was decided when the client was made, and is not on offer. */
    fixed:      Record<string, unknown>;
    limits: {
        maxServers:       number;
        maxQueryTimeout:  number;
        transports:       string[];
        recordTypes:      string[];
    };
    file:       string;
}

/** What a PUT to the DNS configuration may carry; everything is optional. */
export interface DNSUpdate {
    enabled?:              boolean;
    servers?:              DNSServerEntry[];
    queryTimeoutSeconds?:  number;
    recursionDesired?:     boolean | null;
    useCache?:             boolean;
    dnssecOK?:             boolean;
    followCNAMEs?:         boolean;
    maxCNAMEFollows?:      number;
    maxRetries?:           number;
}

/** One resource record a test query brought back. */
export interface DNSRecord {
    name:        string;
    type:        string;
    timeToLive:  number;
    value:       string;
}

/** What a test query brought back. */
export interface DNSQueryResult {
    name:           string;
    /** Which single name server was asked, or null when all of them were. */
    asked?:         string | null;
    /** Set when an address was typed and a reverse name was asked for instead. */
    turnedAround?:  string | null;
    recordTypes:    string[];
    ok:             boolean;
    error?:         string;
    responseCode?:  string;
    server?:        string;
    runtime_ms?:    number;
    authoritative?: boolean;
    truncated?:     boolean;
    dnssec?:        string | null;
    timedOut?:      boolean;
    answers:        DNSRecord[];
    more?:          number;
    /** What was made of the certificate of every server this asked over TLS or HTTPS, step by step. */
    certificates?:  ServerJudgement[];
}


// ---------------------------------------------------------------------------
// The certificate store
// ---------------------------------------------------------------------------

/**
 * One certificate in the store, of one of the kinds K the node keeps.
 * Everything but label, active and usages is read out of the file.
 */
export interface Certificate<K extends string = string> {
    /** The handle it is addressed by: the first 16 digits of its fingerprint. */
    id:             string;
    kind:           K;
    fileName:       string;
    label:          string;
    subject:        string;
    issuer:         string;
    serialNumber:   string;
    /** Its SHA-256 fingerprint in full, for comparing against what a CA said. */
    thumbprint:     string;
    notBefore:      string;
    notAfter:       string;
    keyAlgorithm:   string;
    hasPrivateKey:  boolean;
    /** How many further certificates travel with it, e.g. its sub-CAs. */
    chainLength:    number;
    /** Whether the node is using it. Somebody switches this; time does not. */
    active:         boolean;
    importedAt:     string;
    expired:        boolean;
    notYetValid:    boolean;
    /** Active, and inside its own validity. */
    usable:         boolean;
    description:    string;
    /**
     * What it may be used for - "dns", "nts" - where its kind is kept for
     * some uses and not others, and null there for every use. Left out for
     * every other kind, which is for what its kind says.
     */
    usages?:        string[] | null;
}

/** What the store says about one kind it keeps. */
export interface CertificateKindInfo {
    description:      string;
    trustAnchor:      boolean;
    needsPrivateKey:  boolean;
    /** Whether one of this kind is told what it is for, in this store. */
    hasUsages:        boolean;
    /** What one of this kind may be told it is for - the store's word, not the kind's. */
    usages:           string[];
}

/** The whole store, grouped the way it is shown. */
export interface CertificateStore<K extends string = string> {
    directory:     string;
    /** The kinds that are trust anchors, in the order they are shown. */
    trustAnchors:  K[];
    /** The kinds that are presented, in the order they are shown. */
    credentials:   K[];
    /** The kinds that are neither: kept to recognise a server by its fingerprint. */
    recognised:    K[];
    kinds:         Record<K, CertificateKindInfo>;
    /** What a TLS root or a server certificate may be told it is for, as it was said before every kind said its own. */
    usages:        string[];
    certificates:  Record<K, Certificate<K>[]>;
    /** Whether anything in the store carries a private key, which is kept unencrypted. */
    keysAreUnencrypted: boolean;
}

/** What an import sends: the file, base64-encoded, and what to make of it. */
export interface CertificateImport<K extends string = string> {
    kind:       K;
    /** The file's bytes, base64-encoded. PEM, DER or PKCS#12. */
    content:    string;
    /** What opens it, where it is a protected PKCS#12. Used once and not kept. */
    password?:  string;
    /** What to call it; its common name where this is left out. */
    label?:     string;
    /** What it is for, where its kind has usages; left out for every use. */
    usages?:    string[];
}

/** What a change to a stored certificate may say. Everything else is read from the file. */
export interface CertificateUpdate {
    active?:  boolean;
    label?:   string | null;
    /** What it is for; null for every use again, and left out to leave it alone. */
    usages?:  string[] | null;
}


// ---------------------------------------------------------------------------
// The time
// ---------------------------------------------------------------------------

/** One line of what happened while a time server was being asked. */
export interface TimeServerTestStep {
    at_ms:  number;
    level:  'info' | 'notice' | 'warning' | 'error';
    text:   string;
}

/** What came of asking one time server everything. */
export interface TimeServerTest {
    host:        string;
    ok:          boolean;
    runtime_ms:  number;
    steps:       TimeServerTestStep[];
}

/**
 * What may be changed about the time servers while the node runs. What is
 * left out stays as it is; the list of servers is one value and replaces the
 * node's whole.
 */
export interface NTSUpdate {
    enabled?:                    boolean;
    servers?:                    NTSServerEntry[];
    minServers?:                 number;
    maxDeviationSeconds?:        number;
    checkEverySeconds?:          number;
    timeoutSeconds?:             number;
    /** Who the operator says stands behind the time; null takes the claim back. */
    legalTimeAuthority?:         string | null;
    legalTimeToleranceSeconds?:  number;
    legalTimeMaxAgeSeconds?:     number;
}

/**
 * One time server as the configuration names it. Whatever is left out is the
 * usual: priority 0, the usual ports, switched on, held to no fingerprint.
 */
export interface NTSServerEntry extends PinKeys {
    hostname:       string;
    priority?:      number;
    ntsKEPort?:     number;
    ntpPort?:       number;
    enabled?:       boolean;
    /**
     * What the page showed the server held to, in the keys above: the node
     * changes only what was changed on the page, and keeps what the server
     * learned while the page was open. Only on a server the page loaded.
     */
    pinsAsShown?:   PinKeys;
}

/** How one synchronisation of the group went. */
export interface NTSSyncResult {
    ok:           boolean;
    server:       string;
    at:           string;
    error?:       string;
    runtime_ms?:  number;
    offset_ms?:   number | null;

    /** What the group concluded: the median, how many answered, how far apart. */
    group?:       {
        name:               string;
        answered:           number;
        required:           number;
        offset_ms:          number | null;
        spread_ms:          number | null;
        deviationExceeded:  boolean;
    };

    /** One entry per server asked, answered or not. */
    servers?:     NTSServerResult[];
}

/** What one time server of a group said. */
export interface NTSServerResult {
    hostname:       string;
    ok:             boolean;
    offset_ms?:     number | null;
    roundTrip_ms?:  number | null;
    authenticated?: boolean | null;
    keyExchange?:   string;
    error?:         string | null;
}

/** One server of the node's group, and what its key exchange is doing. */
export interface NTSTimeSource {
    hostname:       string;
    priority:       number;
    ntsKEPort:      number;
    ntpPort:        number;
    enabled:        boolean;
    cookies?:       number | null;
    lastExchange?:  string | null;
    aeadAlgorithm?: string | null;

    /**
     * The root CA the certificate chain of the last key exchange ended at -
     * the chain the node built, so the root it judged the certificate by - or
     * null before the first exchange.
     */
    rootCA?:        NTSRootCA | null;

    /** The SHA-256 fingerprint of the certificate the last key exchange showed, which a pin is written down from. */
    certificate?:   string | null;

    /**
     * What it is held to beyond what every server is held to, or null where
     * that is nothing: what the page has to send back with it, as the list it
     * sends replaces the node's whole.
     */
    heldTo?:        ServerPins | null;
    judgement?:     ServerJudgement | null;
    known?:         KnownServer | null;
}

/** A root CA, by a name to call it, its subject, and its SHA-256 fingerprint. */
export interface NTSRootCA {
    name:         string;
    subject:      string;
    fingerprint:  string;
}

/** Where the node gets the time from, and the rules for believing it. */
export interface NTSConfiguration {
    enabled:      boolean;

    /**
     * Every server the node has, switched on or not, in the order they were
     * configured - the list a page edits and sends back whole - and the rules
     * for believing them. Both are always there.
     */
    timeSources:  NTSTimeSource[];
    group:        { name: string; minServers: number; maxDeviationSeconds: number };

    /**
     * What may be changed about the group, the test and what legal time rests
     * on. The quorum is the one wanted; the group's own can be lower while it
     * has fewer servers on.
     */
    settings:     {
        timeoutSeconds:             number | null;
        checkEverySeconds:          number;
        minServers:                 number;
        maxDeviationSeconds:        number;
        legalTimeAuthority:         string | null;
        legalTimeToleranceSeconds:  number;
        legalTimeMaxAgeSeconds:     number;
    };
    /** What any new client starts with. */
    policy:       Record<string, unknown>;
    lastSync:     NTSSyncResult | null;
    limits:       {
        maxTimeout:          number;
        minCheckEvery:       number;
        maxCheckEvery:       number;
        minDeviation:        number;
        maxDeviation:        number;
        minTolerance:        number;
        maxTolerance:        number;
        minMaxAge:           number;
        maxMaxAge:           number;
        maxAuthorityLength:  number;
        defaultNTSKEPort:    number;
        defaultNTPPort:      number;
    };
    file:         string;
    /** Only on the answer to a synchronisation, which carries both. */
    result?:      NTSSyncResult;
}

/**
 * What time it is here, and what that is worth.
 *
 * Two different questions the node keeps apart: `now` is its own system
 * clock, and everything under `nts` is what happened when it last asked the
 * servers that know. The clock is not set from that answer - see the C# side
 * - so `offset_ms` is the whole of the result.
 *
 * `legal` is decided by the node and never by a page: whether a time may be
 * called legal depends on a claim the operator made, on the check being
 * recent and on the difference being small, and `why` names whichever of
 * those is missing.
 */
export interface Clock {
    now:        string;
    /** Always "system": said out loud, because the check below did not set it. */
    source:     string;
    nts: {
        enabled:       boolean;
        /** The group the clock is checked against, its servers and its quorum; null while switched off. */
        group:         string | null;
        /** The one server by name when the group has only one. */
        server:        string | null;
        servers:       string[] | null;
        minServers:    number | null;
        lastServer:    string | null;
        /** How many servers the last check asked, and how many of them answered: numbers, for a screen to say in its own words. */
        asked:         number | null;
        answered:      number | null;
        checkedAt:     string | null;
        ageSeconds:    number | null;
        offset_ms:     number | null;
        everySeconds:  number;
    };
    legal:            boolean;
    authority:        string | null;
    /** null while legal; otherwise "notClaimed", "ntsOff", "neverChecked", "stale", "offBy" or "unknown". */
    why:              string | null;
    toleranceSeconds: number;
    maxAgeSeconds:    number;
}


// ---------------------------------------------------------------------------
// Asking the node
// ---------------------------------------------------------------------------

export class ApiError extends Error {

    readonly status:  number;
    readonly body?:   unknown;

    constructor(status:   number,
                message:  string,
                body?:    unknown) {

        super(message);

        this.name    = 'ApiError';
        this.status  = status;
        this.body    = body;

    }

    /** The session is gone: somebody has to sign in again. */
    get isUnauthorized(): boolean {
        return this.status === 401;
    }

    /** Signed in, and not allowed: signing in again changes nothing. */
    get isForbidden(): boolean {
        return this.status === 403;
    }

}


/**
 * Nothing came back at all.
 *
 * Not an ApiError, because the two are different things to be told: an
 * ApiError is the node answering and saying no, with a sentence of its own
 * about why. This is the node saying nothing - and a page that can tell the
 * two apart can say so, instead of repeating a status that was never sent.
 */
export class NoAnswer extends Error {

    readonly reason:  'ran out of time' | 'could not be reached';

    constructor(reason:   'ran out of time' | 'could not be reached',
                message:  string) {

        super(message);

        this.name    = 'NoAnswer';
        this.reason  = reason;

    }

}


/**
 * How long the web interface waits for the node to answer about itself.
 *
 * Measured on the vehicle's web interface, against a vehicle that had gone
 * quiet rather than away - the case a refused connection does not cover, and
 * the one a car park's network actually produces: 98 seconds after Save, the
 * request was still open, both buttons of the form were still greyed out, and
 * the page said nothing at all. Seven pages clicked through in that state left
 * nine requests hanging, more than the browser will even keep connections open
 * for.
 *
 * Fifteen seconds is more than two orders of magnitude more than a node
 * needs: every read and write of the local controller's own configuration
 * measured between 1 and 30 milliseconds, and the slowest thing it does outside
 * a key - a station's login, made up and stored - under 100. That is the
 * point. The deadline is here to notice silence and not slowness, so it can
 * be generous enough that a slow link never trips it.
 */
export const answerWithin = 15_000;

/**
 * And how long for the node to do something and then answer.
 *
 * Longer, because a write is a file and sometimes more than one, and because
 * giving up on a write is the worse mistake of the two to make: the node may
 * have carried it out and only been slow to say so.
 */
export const actWithin = 30_000;

/**
 * How long a question the node has to put to somebody else may take: the
 * timeouts of the steps it takes one after another, added up, and the usual
 * allowance on top - so that what the page gives up on is silence from the
 * node rather than patience it was told to have.
 */
export function afterAsking(Timeouts: number[]): number {
    return Timeouts.reduce((total, seconds) => total + seconds * 1000, 0) + answerWithin;
}


let unauthorizedHandler: (() => void) | null = null;

/** Called whenever the API answers 401, i.e. the session is gone. */
export function onUnauthorized(handler: () => void): void {
    unauthorizedHandler = handler;
}


/** Where a route of the node's API is, for what is not asked with request(): a download, a stream. */
export function apiURL(Path: string): string {
    return config.apiBase + Path;
}


/**
 * The sentence a refusal came with, in the first of the keys that carries
 * one - and the status line where none does.
 *
 * The node says no with "error". A kind's routes that report on somebody
 * else - an OCPI partner that did not register - say it with "message", and
 * Hermod's own with "description": all three are shown to somebody who asked
 * for something and was refused, so all three are read, in the order given.
 */
function refusalOf(Json:      unknown,
                   Response:  Response,
                   Keys:      string[]): string {

    if (typeof Json === 'object' && Json !== null)
        for (const key of Keys) {
            const said = (Json as Record<string, unknown>)[key];
            if (typeof said === 'string')
                return said;
        }

    return `${Response.status} ${Response.statusText}`;

}


/**
 * Sign in at the HTTPExt API and answer with who is now signed in.
 *
 * Two requests rather than one, and that is not a detour. The HTTPExt API is
 * the only place that can check a password - the store it reads is private to
 * it - but it answers in its own shape and knows nothing of the node's roles.
 * So it sets the session cookie, and "me" is asked afterwards for the roles
 * and permissions the pages actually work from.
 *
 * Form-urlencoded because that is what its sign-in route accepts, and the
 * field is called "login" rather than "username".
 */
export async function signIn<M = NodeMe>(username: string, password: string): Promise<M> {

    const giveUp = new AbortController();
    const timer  = setTimeout(() => giveUp.abort(), actWithin);

    let response: Response;

    try
    {
        response = await fetch(config.extBase + '/login', {
                             method:       'POST',
                             headers:      {
                                               'Content-Type':  'application/x-www-form-urlencoded',
                                               'Accept':        'application/json'
                                           },
                             credentials:  'same-origin',
                             signal:       giveUp.signal,
                             body:         new URLSearchParams({ login: username, password }).toString()
                         });
    }
    catch (problem)
    {
        throw nothingCameBack(problem, 'POST', actWithin, giveUp.signal.aborted);
    }
    finally
    {
        clearTimeout(timer);
    }

    if (!response.ok) {

        // Its refusals carry a "description"; the node's carry an "error".
        // Both are shown to somebody who just typed a password, so both are
        // read - its own first, since this is its answer.
        let json: unknown = null;

        try {
            json = JSON.parse(await response.text());
        }
        catch { /* the status line says enough */ }

        throw new ApiError(response.status, refusalOf(json, response, ['description', 'error', 'message']), null);

    }

    // Read to its end, so that the browser finishes this request cleanly
    // before the next one goes out. What it said is not needed, and a body
    // that cannot be read is no reason to stop.
    try {
        await response.arrayBuffer();
    }
    catch { /* nothing to finish */ }

    return request<M>('GET', '/auth/me');

}


/**
 * One request to the node, with a deadline.
 *
 * The deadline covers reading the body as well as opening the connection: a
 * node that sends its headers and then stops mid-answer hangs exactly as
 * thoroughly as one that never starts.
 *
 * What a kind of node asks beyond what every node has goes through here too.
 */
export async function request<T>(method:  string,
                                 path:    string,
                                 body?:   unknown,
                                 within:  number = method === 'GET' ? answerWithin : actWithin): Promise<T> {

    const headers: Record<string, string> = { 'Accept': 'application/json' };

    if (body !== undefined)
        headers['Content-Type'] = 'application/json';

    const giveUp = new AbortController();
    const timer  = setTimeout(() => giveUp.abort(), within);

    let response:  Response;
    let text:      string;

    try
    {

        // Same origin, so the session cookie travels with every request.
        response = await fetch(config.apiBase + path, {
                             method,
                             headers,
                             credentials: 'same-origin',
                             signal:      giveUp.signal,
                             body:        body !== undefined ? JSON.stringify(body) : undefined
                         });

        if (response.status === 401)
            unauthorizedHandler?.();

        if (response.status === 204) {
            // Nothing to read, but reading it lets the browser finish the
            // request cleanly instead of aborting an unconsumed body.
            await response.arrayBuffer();
            return undefined as T;
        }

        text = await response.text();

    }
    catch (problem)
    {
        throw nothingCameBack(problem, method, within, giveUp.signal.aborted);
    }
    finally
    {
        clearTimeout(timer);
    }

    let json: unknown = null;

    try {
        json = text.length > 0 ? JSON.parse(text) : null;
    }
    catch {
        if (response.ok)
            throw new ApiError(response.status, `Invalid JSON in the response of ${method} ${path}`, text);
    }

    if (!response.ok)
        throw new ApiError(response.status, refusalOf(json, response, ['error', 'message', 'description']), json);

    return json as T;

}


/**
 * What to say when nothing came back, in words somebody can act on.
 *
 * A read that runs out of time changed nothing, and can be told so. A write
 * that runs out of time is the honest awkward case: the page stopped waiting,
 * but the node may well have done the thing and been slow to say so, and
 * telling somebody that it did not work would invite them to do it twice. So
 * it says what is actually known - that the waiting stopped - and where to
 * look for the rest.
 */
function nothingCameBack(Problem:  unknown,
                         Method:   string,
                         Within:   number,
                         GaveUp:   boolean): unknown {

    const seconds  = Math.round(Within / 1000);
    const node     = `The ${config.nodeName}`;

    if (GaveUp)
        return new NoAnswer(
                   'ran out of time',
                   Method === 'GET'
                       ? `${node} did not answer within ${seconds} seconds. ` +
                         'It may be busy, restarting, or no longer reachable from here.'
                       : `${node} did not answer within ${seconds} seconds, so this page ` +
                         'stopped waiting. It may still have carried this out - reload to see ' +
                         'what it now says.'
               );

    // The browser's own word for this is "Failed to fetch", which on a page
    // about a node names neither the node nor what to do next.
    if (Problem instanceof TypeError)
        return new NoAnswer(
                   'could not be reached',
                   `${node} could not be reached. It may be switched off, restarting, ` +
                   'or on the other side of a network that is down.'
               );

    return Problem;

}


// ---------------------------------------------------------------------------
// The routes every node has
// ---------------------------------------------------------------------------

/** What a kind of node says its own of these are. */
export interface NodeTypes {
    me:             NodeMe<string>;
    status:         NodeStatus;
    configuration:  NodeConfiguration;
    /** The kinds of certificate its store keeps. */
    kind:           string;
    store:          CertificateStore<string>;
}

/**
 * The routes every node has, typed with what a kind of node says its own of
 * them are. A kind builds its `api` from this and its own routes:
 *
 *     export const api = { ...nodeAPI<{ me: Me; ... }>(), csms: { ... } };
 */
export function nodeAPI<T extends NodeTypes = NodeTypes>() {

    return {

        /** The Server-Sent Events stream; the browser sends the session cookie along. */
        eventsURL: apiURL('/events'),

        auth: {
            me:      ()                                    => request<T['me']>('GET',  '/auth/me'),
            login:   (username: string, password: string)  => signIn<T['me']>(username, password),
            logout:  ()                                    => request<void>   ('POST', '/auth/logout')
        },

        status:         () => request<T['status']>       ('GET', '/status'),
        configuration:  () => request<T['configuration']>('GET', '/configuration'),

        /** What time it is here and what that is worth; cheap, and safe to poll. */
        clock:          () => request<Clock>             ('GET', '/clock'),

        dns: {
            get:   ()                    => request<DNSConfiguration>('GET', '/configuration/dns'),
            /** Only the fields given are changed; the answer is the whole configuration as it now stands. */
            save:  (update: DNSUpdate)   => request<DNSConfiguration>('PUT', '/configuration/dns', update),
            /**
             * Make the node look a name up. A POST because it sends traffic.
             *
             * @param seconds  how long the name servers asked may take.
             * @param server   which configured name server to ask, by its
             *                 place in the list - or undefined to resolve the
             *                 way the node resolves anything else, asking all
             *                 of them at once.
             */
            query: (name: string, recordTypes: string[], seconds: number, server?: number) =>
                       request<DNSQueryResult>('POST', '/configuration/dns/query', { name, recordTypes, server },
                                               afterAsking([ seconds ]))
        },

        nts: {
            get:   ()                    => request<NTSConfiguration>('GET', '/configuration/nts'),
            save:  (update: NTSUpdate)   => request<NTSConfiguration>('PUT', '/configuration/nts', update),
            /**
             * Ask one time server everything: the name, the key exchange, the
             * authenticated NTP request, each one written down as it happens.
             *
             * @param timeoutSeconds  what the node allows each of the two steps.
             * @param host            which server, on the ports it is
             *                        configured with, or undefined for the
             *                        configured one.
             */
            test:  (timeoutSeconds: number, host?: string) => request<TimeServerTest>(
                                                   'POST', '/configuration/nts/test', { host },
                                                   afterAsking([timeoutSeconds, timeoutSeconds])),
            /**
             * Ask every server of the group, with every step in the log - two
             * steps over the network per server, so two of the node's own
             * timeouts before the page stops believing in it. The answer is the
             * whole NTS configuration, with the synchronisation's under
             * `result`: the exchange moves the cookies and the key material the
             * page is showing.
             *
             * @param timeoutSeconds  what the node allows each of the two steps.
             */
            sync:  (timeoutSeconds: number) => request<NTSConfiguration>(
                                                   'POST', '/configuration/nts/sync', {},
                                                   afterAsking([timeoutSeconds, timeoutSeconds])
                                               )
        },

        certificates: {

            /** The whole store, grouped by kind. */
            get:     ()  => request<T['store']>('GET', '/certificates'),

            /**
             * Put a certificate into the store.
             *
             * Importing the same file twice is the same entry - the handle is
             * its fingerprint - so this is safe to repeat.
             */
            import:  (certificate: CertificateImport<T['kind']>) =>
                         request<Certificate<T['kind']>>('POST', '/certificates', certificate),

            /** Switch one on or off, rename it, or say what it is for. */
            update:  (id: string, update: CertificateUpdate) =>
                         request<Certificate<T['kind']>>('PATCH', `/certificates/${encodeURIComponent(id)}`, update),

            /** Take one out of the store and delete its file. */
            remove:  (id: string) =>
                         request<T['store']>('DELETE', `/certificates/${encodeURIComponent(id)}`),

            /**
             * Read the store directory again.
             *
             * For certificates somebody copied in rather than uploaded - which
             * is a perfectly good way to install one on a machine you already
             * have a shell on.
             */
            reload:  ()  => request<T['store']>('POST', '/certificates/reload', {})

        },

        /**
         * A page of the log, oldest of the returned entries first.
         *
         * @param limit  at most this many entries
         * @param after  only what is newer than this id
         * @param tag    only entries carrying this tag - a level counting as one
         */
        logs: (limit?: number, after?: number, tag?: string) => {

            const query = new URLSearchParams();

            if (limit !== undefined)  query.set('limit', String(limit));
            if (after !== undefined)  query.set('after', String(after));
            if (tag)                  query.set('tag',   tag);

            const suffix = query.size > 0 ? `?${query}` : '';

            return request<LogPage>('GET', `/logs${suffix}`);

        }

    };

}
