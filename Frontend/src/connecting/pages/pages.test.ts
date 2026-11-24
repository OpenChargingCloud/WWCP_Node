/**
 * What the pages of the connections and of the WebSocket logins are held to:
 * what every page of every kind of node is, by the rules of test/pages.ts.
 *
 * Run with `npm test`.
 */

import { everyPageIn } from '../../../test/pages.ts';


everyPageIn(new URL('./', import.meta.url), {
    withForms: [ 'authentication.ts', 'clientTrust.ts', 'connections.ts', 'webSocketLogins.ts' ]
});
