/**
 * What a shared file may import: another shared file, and nothing else.
 *
 * Every kind of node bundles these files as its own, from its own checkout of
 * WWCP_Node. A shared file that reached into a product - "../../../EV/..." - or
 * named a package only one product installs would build in that product and
 * fail in the other seven, or build everywhere against eight different things.
 * The tests import from Node itself, which only the tests may.
 */

import { strict as assert }                     from 'node:assert';
import { readdirSync, readFileSync, statSync }  from 'node:fs';
import { dirname, join, relative, resolve }     from 'node:path';
import { describe, it }                         from 'node:test';
import { fileURLToPath }                        from 'node:url';

const src = dirname(fileURLToPath(import.meta.url));

/** Every file below a directory with one of these endings. */
function filesBelow(Directory: string, ...Endings: string[]): string[] {
    return readdirSync(Directory).flatMap(name => {
        const path = join(Directory, name);
        return statSync(path).isDirectory()
                   ? filesBelow(path, ...Endings)
                   : Endings.some(ending => name.endsWith(ending)) ? [ path ] : [];
    });
}

/**
 * The lines of a source that are not comments, so that an example in one is
 * not taken for the real thing - the stylesheet shows in a comment how a
 * product uses it.
 */
function codeOf(Source: string): string {
    return Source.split('\n').
                  filter(line => !/^\s*(\/\/|\/\*|\*)/.test(line)).
                  join('\n');
}

/**
 * What a file imports: the specifier of every import and export statement,
 * which begin a line - one written over several lines ends in "from" and its
 * specifier on a later one.
 */
function importsOf(Path: string): string[] {

    const code = codeOf(readFileSync(Path, 'utf8'));

    return [ ...code.matchAll(/^(?:import|export)\b[^;]*?\bfrom\s+['"]([^'"]+)['"]/gm),
             ...code.matchAll(/^import\s+['"]([^'"]+)['"]/gm) ].
               map(match => match[1]!);

}


describe('a shared file', () => {

    const shared = filesBelow(src, '.ts').filter(path => !path.endsWith('.test.ts'));

    it('is there to be asked about, with what it imports', () => {

        assert.ok(shared.length >= 15, `only ${shared.length} shared files were found below ${src}`);

        // The reading below has to find what is there, or every file passes.
        assert.deepEqual(importsOf(join(src, 'start.ts')).sort(), [
            './api/client', './auth', './basePath', './html', './logs/store', './pages/dns',
            './pages/login', './pages/logs', './pages/notFound', './pages/nts', './router', './shell'
        ]);

    });

    for (const path of shared) {

        it(`imports only other shared files: ${relative(src, path).replaceAll('\\', '/')}`, () => {

            for (const specifier of importsOf(path)) {

                assert.ok(specifier.startsWith('./') || specifier.startsWith('../'),
                          `"${specifier}" is not a shared file - a package, or a product's alias`);

                assert.ok(!relative(src, resolve(dirname(path), specifier)).startsWith('..'),
                          `"${specifier}" reaches out of WWCP_Node/Frontend/src`);

            }

        });

    }

});


describe('the shared stylesheet', () => {

    it('uses only its own partials', () => {

        const partials = filesBelow(join(src, 'styles'), '.scss');

        assert.ok(partials.length > 1, 'no stylesheet was found to ask');

        for (const path of partials)
            for (const match of codeOf(readFileSync(path, 'utf8')).matchAll(/@(?:use|forward|import)\s+['"]([^'"]+)['"]/g))
                assert.ok(!match[1]!.includes('/') && !match[1]!.startsWith('@'),
                          `${relative(src, path)} uses "${match[1]}", which is not one of its own partials`);

    });

});
