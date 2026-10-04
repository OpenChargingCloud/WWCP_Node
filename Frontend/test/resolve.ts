/*
 * How Node finds what webpack finds.
 *
 * The pages are written for webpack: a relative import leaves the extension
 * out, and what every kind of node shares is imported as "@node/...", which
 * webpack's alias and the tsconfig's paths turn into WWCP_Node/Frontend/src.
 * The tests are run by Node, which knows neither - "imports" in a package.json
 * cannot say it either, since it may not point out of the package. Loaded
 * before the tests, with "node --import <this file> --test ...", this tells
 * Node both.
 *
 * A kind of node finds it where it finds the shared files, from its own
 * Frontend directory: ../../../WWCP_Node/Frontend/test/resolve.ts.
 *
 * A package - lit-html - is looked for in the node_modules of the directory
 * the tests run in first: a shared file imports it too, and from where that
 * file is Node would look in WWCP_Node/Frontend/node_modules, which a kind's
 * build never installs. webpack's resolve.modules says the same for the
 * bundle. A file of a package keeps its own imports as they are.
 */

import { registerHooks } from 'node:module';
import { pathToFileURL } from 'node:url';

const shared  = new URL('../src/', import.meta.url);
const runHere = pathToFileURL(`${process.cwd()}/package.json`).href;

registerHooks({
    resolve(specifier, context, next) {

        if (context.parentURL?.includes('/node_modules/'))
            return next(specifier, context);

        if (specifier.startsWith('@node/'))
            specifier = new URL(specifier.slice('@node/'.length), shared).href;

        else if (/^(@[a-z0-9-]+\/)?[a-z0-9-]/.test(specifier) && !specifier.startsWith('node:')) {
            try {
                return next(specifier, { ...context, parentURL: runHere });
            }
            catch {
                return next(specifier, context);
            }
        }

        else if (!specifier.startsWith('.') || /\.(m|c)?js$|\.json$/.test(specifier))
            return next(specifier, context);

        return next(specifier.endsWith('.ts') ? specifier : `${specifier}.ts`, context);

    }
});
