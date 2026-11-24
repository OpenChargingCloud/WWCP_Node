/*
 * What the tests of the pages of a WebSocket server's logins share: every
 * kind's stand-in for fetch and document of happy-dom - test/node.ts - and the
 * charging station server as a node that has just been set up has it, at
 * "/configuration/ocpp-server", where the pages are as long as a kind says
 * nothing else. The pages speak of a local controller here, as they did while
 * they were its.
 *
 * Imported first, before a page: lit-html looks for the document as it is
 * loaded, and the pages load it.
 *
 *   import { aWebSocketServer, open, ... } from '../../../test/loginServer.ts';
 *   const { clientTrustPage } = await import('./clientTrust.ts');
 */

import { setNodeNoun } from '../src/connecting/settings.ts';

import type { ClientAuthentication } from '../src/connecting/api/webSocketLogins.ts';

export * from './node.ts';

setNodeNoun('local controller');


/** The charging station server, as a node that has just been set up has it: what the pages of the logins read of it. */
export function aWebSocketServer(): { clientAuthentication: ClientAuthentication[]; [field: string]: unknown } {
    return {
        enabled:               false,
        port:                  8443,
        clientAuthentication:  [ 'httpAuthWithoutTLS', 'httpAuthOverTLS', 'tlsClientCertificate' ],
        state:                 { running: false, tls: false, url: 'wss://lc001.example.org:8443' }
    };
}
