import { auth } from '../auth';
import { config } from '../config';
import { must, type HTMLFragment } from '../html';
import { html, nothing, render } from '../view';
import type { Page } from '../router';
import { brand, versions } from '../shell';
import { errorMessage, field, safeNext } from '../ui';

/** What a kind of node says on its sign-in beyond what every node says. */
export interface SignInWords {
    /** The sentence under the heading. */
    line?:   string;
    /** Where the first password comes from. */
    hint?:   string;
    /** Anything else under the form: an e-mobility provider's "Sign up". */
    below?:  () => HTMLFragment;
}

/** The sentence under the heading, unless a kind of node says its own. */
export function signInLine(Words: SignInWords = {}): string {
    return Words.line ?? `Sign in to configure this ${config.nodeName} and read its log.`;
}

/** Where the first password comes from, unless a kind of node says its own. */
export function signInHint(Words: SignInWords = {}): string {
    return Words.hint ?? `The ${config.nodeName} makes up one account at its first start and shows its password once, on the console.`;
}

/**
 * The sign-in, and the only page there is for somebody who is not signed in.
 * Where they were going comes along as "next", and they go on there - to one
 * of this node's own pages and nowhere else, see safeNext.
 */
export function loginPage(Words: SignInWords = {}): Page {

    return {

        title: 'Sign in',

        render({ root, url, navigate }) {

            const next = safeNext(url.searchParams.get('next')) ?? '/';

            if (auth.user) {
                navigate(next, true);
                return;
            }

            const { name, icon } = brand();

            render(root, html`
                <section class="login">

                    <h1><i class="fa-solid ${icon}"></i> ${name}</h1>
                    <p class="muted">${signInLine(Words)}</p>

                    <form id="login-form" class="form-stack" @submit=${signIn}>
                        <label>Username
                            <input name="username" required autocomplete="username" autofocus />
                        </label>
                        <label>Password
                            <input name="password" type="password" required autocomplete="current-password" />
                        </label>
                        <div class="form-actions">
                            <button type="submit" class="btn primary">Sign in</button>
                            <span id="form-error" class="form-error" role="alert"></span>
                        </div>
                    </form>

                    <p class="small muted login-hint">${signInHint(Words)}</p>

                    ${Words.below?.() ?? nothing}

                    <p class="small muted">${versions()}</p>

                </section>
            `);

            function signIn(event: SubmitEvent): void {

                event.preventDefault();

                const form    = event.currentTarget as HTMLFormElement;
                const error   = must<HTMLElement>(form, '#form-error');
                const button  = must<HTMLButtonElement>(form, 'button[type="submit"]');

                error.textContent = '';
                button.disabled   = true;

                void (async () => {
                    try
                    {
                        // The password is read untrimmed: a space at either end
                        // is part of it, and quietly dropping one would turn a
                        // right password into a wrong one.
                        await auth.signIn(field(form, 'username'), field(form, 'password', false));
                        navigate(next, true);
                    }
                    catch (problem)
                    {
                        error.textContent = errorMessage(problem);
                        button.disabled   = false;
                    }
                })();

            }

        }

    };

}
