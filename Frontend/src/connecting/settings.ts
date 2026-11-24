/*
 * What the pages of the connections are told by the kind of node they are
 * drawn for: a charging station and a local controller keep the same
 * connections and credentials, and serve them by the same
 * routes, but each under a resource of its own, and each is something else.
 *
 * Said once, in a kind's main.ts, before the web interface starts - the pages
 * ask when they are drawn. Untold, they are a charging station's.
 *
 *   setConnectionsResource('csms');
 *   setNodeNoun('local controller');
 *   setNodeTraits({ oneNodePerOCPPVersion: false, isConnectedTo: true });
 *
 * A charging station, whose station port is the connections' as well:
 *
 *   setStationsResource('connections');
 *
 * A node that connects downwards - a CSMS, connecting to the charging stations and
 * local controllers that cannot connect to it - says that as well:
 *
 *   setNodeTraits({ oneNodePerOCPPVersion: false, isConnectedTo: true, connectsDown: true });
 */

/** What a kind of node is, where the pages say something that is not true of every kind. */
export interface NodeTraits {
    /** Whether it is one OCPP node for each version of OCPP it speaks, so that a connection says which of them connects. */
    oneNodePerOCPPVersion:  boolean;
    /** Whether it is connected to itself, as a server, beside connecting to its back ends. */
    isConnectedTo:              boolean;
    /**
     * Whether what it connects to is below it - charging stations, local
     * controllers - and not its back end: then the pages speak of the node at
     * the other end, and of no CSMS there.
     */
    connectsDown:              boolean;
    /**
     * What the form of a connection suggests, where the kind's connections are
     * neither a back end's nor those of the nodes below it - a PKI's, which are
     * its registration authorities': left out, what the traits above say.
     */
    examples?:                 { description: string; url: string };
}

let resource  = 'connections';
let stations  = 'stations';
let noun      = 'station';
let inFull    = 'charging station';
let traits: NodeTraits = { oneNodePerOCPPVersion: true, isConnectedTo: false, connectsDown: false };


/** Name the resource a right to the connections is a right to: "connections" on a charging station, "csms" on a local controller. */
export function setConnectionsResource(Name: string): void {
    resource = Name;
}

/** The resource a right to the connections is a right to. */
export function connectionsResource(): string {
    return resource;
}

/**
 * Name the resource a right to the station port and its WebSocket logins is a
 * right to: "stations" on a local controller, a gateway and a CSMS,
 * "connections" on a charging station - whoever may change where it connects to may
 * change who connects to it.
 */
export function setStationsResource(Name: string): void {
    stations = Name;
}

/** The resource a right to the station port and its WebSocket logins is a right to. */
export function stationsResource(): string {
    return stations;
}

/**
 * Say what the node is called where a page speaks of it: "this station",
 * "this local controller" - and in full, where it is first named: "this
 * charging station". In full it is the same, unless it is said.
 */
export function setNodeNoun(Noun: string, InFull: string = Noun): void {
    noun    = Noun;
    inFull  = InFull;
}

/** What the node is called: "station". */
export function nodeNoun(): string {
    return noun;
}

/** What the node is called in full: "charging station". */
export function nodeNounInFull(): string {
    return inFull;
}

/** Say what is true of this kind of node; what is left out stays as it is. */
export function setNodeTraits(Traits: Partial<NodeTraits>): void {
    traits = { ...traits, ...Traits };
}

/** What is true of this kind of node. */
export function nodeTraits(): NodeTraits {
    return traits;
}

/**
 * What is at the other end of a connection, in a word: the "back end" of a
 * node that connects upwards, the "node" a node that connects downwards reaches.
 */
export function farEnd(): string {
    return traits.connectsDown ? 'node' : 'back end';
}


/**
 * The WebSocket server whose logins the pages of the logins and of the
 * accepted chains speak of: where its routes are, what signs in there, and
 * how it says what it allows.
 *
 * A node that serves charging stations has it as it is untold. A PKI says, for
 * its registration authorities:
 *
 *   setLoginServer({ root: '/configuration/ra-server', page: '/configuration/ra-server',
 *                    login: 'registration authority', logins: 'registration authorities',
 *                    ... });
 *
 * and the resource its rights are asked of with setStationsResource().
 */
export interface LoginServer {
    /** Where its routes are: "/configuration/ocpp-server". */
    root:              string;
    /** Its own page, linked where a page says what the server allows. */
    page:              string;
    /** Where the page of its logins is, and the page of its accepted chains. */
    loginsPage:        string;
    trustPage:         string;
    /** What signs in there, one and many: "charging station", "charging stations". */
    login:             string;
    logins:            string;
    /** Who signs in there, said once in the subtitle of the logins: "a charging station, a local controller, a gateway". */
    who:               string;
    /** An identification, as the forms suggest one: "cs001". */
    example:           string;
    /** What it speaks over the connection, where a page says so: "OCPP". */
    protocol:          string;
    /** Whether the ways a client authenticates are OCPP's security profiles 1, 2 and 3, and said so. */
    securityProfiles:  boolean;
    /** Whether a login that signs in with an SSH key may have its time and its names over that connection. */
    sshChannels:       boolean;
    /** How a client may authenticate at the server, out of what its own route answers. */
    /** The icon of its logins: "fa-charging-station". */
    icon:              string;
    /** What a login is, as the forms suggest it: "Ladepunkt 1". */
    describedAs:       string;
    allowedOf:         (Server: unknown) => import('./api/webSocketLogins').ClientAuthentication[];
}

let server: LoginServer = {
    root:              '/configuration/ocpp-server',
    page:              '/configuration/ocpp-server',
    loginsPage:        '/configuration/ocpp-server/logins',
    trustPage:         '/configuration/ocpp-server/trust',
    login:             'charging station',
    logins:            'charging stations',
    who:               'a charging station, a local controller, a gateway',
    example:           'cs001',
    protocol:          'OCPP',
    securityProfiles:  true,
    sshChannels:       true,
    icon:              'fa-charging-station',
    describedAs:       'Ladepunkt 1',
    allowedOf:         Server => (Server as { clientAuthentication?: import('./api/webSocketLogins').ClientAuthentication[] }).clientAuthentication ?? []
};

/** Say which WebSocket server the pages of the logins are about; what is left out stays as it is. */
export function setLoginServer(Server: Partial<LoginServer>): void {
    server = { ...server, ...Server };
}

/** The WebSocket server the pages of the logins are about. */
export function loginServer(): LoginServer {
    return server;
}
