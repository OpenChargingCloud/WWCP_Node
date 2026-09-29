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
 */

import { registerHooks } from 'node:module';

const shared = new URL('../src/', import.meta.url);

registerHooks({
    resolve(specifier, context, next) {

        if (specifier.startsWith('@node/'))
            specifier = new URL(specifier.slice('@node/'.length), shared).href;

        else if (!specifier.startsWith('.'))
            return next(specifier, context);

        return next(specifier.endsWith('.ts') ? specifier : `${specifier}.ts`, context);

    }
});
