import { ApiError, nodeAPI, onUnauthorized, type NodeMe, type NodeResource, type Operation } from './api/client';
import { fromURL } from './basePath';

/** The routes it asks: every node's. */
const api = nodeAPI();

/**
 * Who is signed in to the web interface. The truth lives in the session cookie
 * and on the node; this is a cache of /auth/me so that the router's guard and
 * the pages can react without asking every time.
 *
 * One of it for the whole page - the router's guard, the shell and every page
 * read the same - typed by a kind of node with what its "me" says and the
 * resources it has: its own auth.ts hands this one on as
 * AuthState<Me, Resource>.
 */
export class AuthState<M extends NodeMe<string> = NodeMe, R extends string = NodeResource> {

    user: M | null = null;

    private readonly listeners = new Set<(user: M | null) => void>();

    /** Ask the node who we are; null when nobody is signed in. */
    async refresh(): Promise<M | null> {

        try
        {
            this.set(await api.auth.me() as M);
        }
        catch (error)
        {

            if (!(error instanceof ApiError && error.isUnauthorized))
                console.warn('Could not load the session:', error);

            this.set(null);

        }

        return this.user;

    }

    /**
     * Sign in, and be whoever the node then says is signed in. A refusal is
     * thrown on to the page, which says it, and leaves nobody signed in.
     */
    async signIn(login: string, password: string): Promise<M> {

        const user = await api.auth.login(login, password) as M;

        this.set(user);

        return user;

    }

    set(user: M | null): void {
        this.user = user;
        for (const listener of this.listeners)
            listener(user);
    }

    onChange(listener: (user: M | null) => void): () => void {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    async signOut(): Promise<void> {
        try {
            await api.auth.logout();
        }
        finally {
            this.set(null);
        }
    }

    /**
     * Whether the person signed in may do this.
     *
     * Used to grey a control out, never to decide anything: the node checks
     * every request again when it arrives, so a page that got this wrong shows
     * a button that answers 403 rather than one that works.
     */
    can(resource: R, operation: Operation): boolean {
        return (this.user?.permissions as string[] | undefined)?.includes(`${resource}:${operation}`) ?? false;
    }

    /** Router guard: the sign-in page with a way back, or null when signed in. */
    readonly requireSignIn = (url: URL): string | null =>
        this.user
            ? null
            // The route and not the address bar's path: what comes back here
            // goes through the router, which puts the base back on. Carrying
            // "/EV/logs" through a sign-in would come back as "/EV/EV/logs".
            : `/login?next=${encodeURIComponent(fromURL(url.pathname) + url.search)}`;

    /** The session is gone: forget who was signed in, and the guards do the rest. */
    readonly lost = (): void => {
        if (this.user !== null)
            this.set(null);
    };

}

export const auth = new AuthState();

// A 401 from any request means the session is gone (expired, signed out
// elsewhere, the node restarted): forget the user, the guards do the rest.
onUnauthorized(auth.lost);
