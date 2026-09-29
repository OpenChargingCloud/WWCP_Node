// Runtime configuration, read from <meta> tags in index.html so that no
// inline script is needed (keeps the Content-Security-Policy strict). The
// {{placeholders}} in those tags are filled in by the node as it serves the
// page.

function meta(name: string): string | undefined {
    // In a test Node runs there is no page to read, and every value is its
    // default.
    return globalThis.document?.querySelector<HTMLMetaElement>(`meta[name="${name}"]`)?.content;
}

export const config = {

    // Where this web interface is mounted: "" on a port of its own, "/EV" or
    // the like when several of these programs share one HTTP server and are
    // told apart by the first path segment. See basePath.ts.
    base:             meta('base')             ?? '',

    apiBase:          meta('api-base')         ?? '/api/v1',

    // Signing in happens at Hermod's HTTPExt API, not at the node's own API:
    // it is the only place that can check a password. Everything after the
    // sign-in goes to apiBase with the cookie it set.
    extBase:          meta('ext-base')         ?? '/ext',
    frontendVersion:  meta('frontend-version') ?? '?',
    serverVersion:    meta('server-version')   ?? '?',

    // What the node calls itself in everything it says - "local controller",
    // "charging station" - for the pages every kind shares to say it the same
    // way.
    nodeName:         meta('node-name')        ?? 'node'
};
