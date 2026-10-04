/*
 * The rules of pages.ts, asked of pages written for them: what each one has to
 * find, and what it has to let pass. The ways a page holds its forms are the
 * ones the eight kinds of node were found using when their pages were first
 * asked - by name, all at once, and by a flag of the page's own.
 */

import { strict as assert }  from 'node:assert';
import { spawnSync }         from 'node:child_process';
import { describe, it }      from 'node:test';
import { fileURLToPath }     from 'node:url';

import { asksBeforeItsReload, attributesSaidAsText, drawsByComparing, expressionsInATextarea, patternsABrowserRefuses, stepsMissingTheirMin, formsNotHeld, formsOf, inlineStylesOf, linksPastTheBase, numbersReadAsZeroWhenEmptied, rolesNamedAsNeeded, saysWhetherItHolds, signedInSaidByHand, tablesOutsideAScroll } from './pages.ts';


const page = (source: string) => ({ name: 'page.ts', source });


describe('a page with a form', () => {

    it('says whether it is holding anything only by telling unsaved', () => {
        assert.equal(saysWhetherItHolds(page(`<form id="dns-form" class="form-stack"></form>`)), false);
        assert.equal(saysWhetherItHolds(page(`const release = unsaved.heldBy(() => dirty);`)), true);
    });

    it('is read for every form it has, with its id or without one', () => {
        assert.deepEqual(formsOf(page(`<form id="dns-form" class="form-stack">  <form class="form-stack upload-form" data-id="\${entry.id}">
                                       <form
                                           class="form-stack" id="add-form">`)),
                         [ 'dns-form', null, 'add-form' ]);
    });

});


describe('a page holding its forms', () => {

    it('by name holds the ones it names, and not the one it forgot', () => {

        const session = page(`<form id="link-form">  <form id="goals-form">  <form id="run-form">
                              unsaved.heldBy(() => typedSinceDrawn(content.querySelector('#link-form')) ||
                                                   typedSinceDrawn(content.querySelector('#goals-form')));`);

        assert.deepEqual(formsNotHeld(session), [ '#run-form' ]);

    });

    it('by name cannot hold a form without one', () => {
        assert.deepEqual(formsNotHeld(page(`<form class="form-stack" data-edit="\${entry.id}">
                                            unsaved.heldBy(() => typedSinceDrawn(content.querySelector('#add-form')));`)),
                         [ 'a form without an id' ]);
    });

    it('all at once holds every one, a form without an id as well', () => {
        assert.deepEqual(formsNotHeld(page(`<form id="socket-form">  <form class="form-stack upload-form">
                                            unsaved.heldBy(() => anyFormTypedSinceDrawn(content));`)),
                         []);
    });

    it('by a flag of its own alone holds none: what is typed and not yet added is in no flag', () => {
        assert.deepEqual(formsNotHeld(page(`<form id="add-form" class="form-stack">
                                            const release = unsaved.heldBy(() => dirty);`)),
                         [ '#add-form' ]);
    });

    it('by its flag and by its forms holds them all', () => {
        assert.deepEqual(formsNotHeld(page(`<form id="add-form" class="form-stack">
                                            const release = unsaved.heldBy(() => dirty || anyFormTypedSinceDrawn(content));`)),
                         []);
    });

    it('does not have to hold a dialog\'s form, which asks for itself', () => {

        const dns = page(`<form id="dns-form">  <form id="pins-form">
                          unsaved.heldBy(() => typedSinceDrawn(content.querySelector('#dns-form')));`);

        assert.deepEqual(formsNotHeld(dns),                 [ '#pins-form' ]);
        assert.deepEqual(formsNotHeld(dns, [ 'pins-form' ]), []);

    });

});


describe('a Reload', () => {

    it('that asks before it throws a draft away passes', () => {
        assert.equal(asksBeforeItsReload(page(`<button id="reload">  if (!unsaved.mayBeLost()) return;`)), true);
    });

    it('that does not is found', () => {
        assert.equal(asksBeforeItsReload(page(`<button id="reload">  void load();`)), false);
    });

    it('is not asked of a page that has none', () => {
        assert.equal(asksBeforeItsReload(page(`<form id="add-form">`)), true);
    });

});


describe('a number', () => {

    it('read with Number() is found, as an emptied field would be 0', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`timeout: Number(data.get('timeout')),  retries: Number(data.get('maxRetries'))`)),
                         [ 'timeout', 'maxRetries' ]);
    });

    it('read with numberField passes', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`timeout: numberField(form, 'timeout')`)), []);
    });

    it('may be read with Number() where it is a priority, since empty means 0 there', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`priority: Number(data.get('priority') ?? 0)`)), []);
    });

    it('read with Number() of field() is found as well', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`pingEvery: Number(field(form, 'pingEvery')),`)), [ 'pingEvery' ]);
    });

    it('read with Number() of an input\'s value is found as well, and of what is not typed is not', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`const index = Number(input.dataset.index);
                                                           servers[index].port = Number(input.value);`)),
                         [ 'input.value' ]);
    });

    it('may be read with Number() where the page says itself what empty means', () => {
        assert.deepEqual(numbersReadAsZeroWhenEmptied(page(`port: field(form, 'port') === '' ? 0 : Number(field(form, 'port')),`)), []);
    });

    it('is asked of a page with no form as well, whose inputs are emptied as easily - the charging station\'s power fields', () => {

        // The rules run as everyPageIn runs them for a kind, on the page in
        // fixtures/numbers/, and what failed there is what they found. In a
        // runner of their own: node:test's run() declines to run files from
        // within a test file, and the variable this runner gives its files
        // turned a nested one's failures into none.
        const env = { ...process.env };
        delete env.NODE_TEST_CONTEXT;

        const child  = spawnSync(process.execPath,
                                 [ '--test', '--test-reporter=tap', fileURLToPath(new URL('./fixtures/numbers.rules.ts', import.meta.url)) ],
                                 { env, encoding: 'utf-8' });

        const failed = child.stdout.split('\n').
                                    filter(line => /^\s*not ok \d+ - /.test(line)).
                                    map   (line => line.replace(/^\s*not ok \d+ - /, ''));

        assert.ok(failed.some(name => name.startsWith('power.ts reads its numbers with numberField')),
                  `power.ts, which has no form, was not asked how it reads its numbers - failed: ${failed.join(', ') || 'nothing'}`);

    });

});


describe('a style', () => {

    it('written into a page as an attribute is found, as the policy drops it', () => {
        assert.deepEqual(inlineStylesOf(page(`<button type="button" id="reveal" class="btn small" style="margin-left:auto">`)),
                         [ 'style="margin-left:auto"' ]);
    });

    it('in a style element, or set as an attribute by the script, is found as well', () => {
        assert.deepEqual(inlineStylesOf(page(`<style>.x { color: red }</style>  row.setAttribute('style', 'display:none');`)),
                         [ '<style', "setAttribute('style'" ]);
    });

    it('said by a class passes, and so does a style property the script sets, which the policy lets through', () => {
        assert.deepEqual(inlineStylesOf(page(`<input name="partyId" class="capitals" data-style="x" />  bar.style.width = \`\${percent}%\`;`)),
                         []);
    });

});


describe('a table', () => {

    it('drawn straight into its card is found, as on a phone it stands past the card', () => {
        assert.deepEqual(tablesOutsideAScroll(page(`<p class="hint">Who may sign in.</p>\n    <table class="table">\n<thead></thead></table>`)),
                         [ '<table class="table">' ]);
    });

    it('in a .table-scroll passes, with other classes beside it as well', () => {
        assert.deepEqual(tablesOutsideAScroll(page(`<div class="table-scroll">\n    <table class="records"></table>\n</div>  ` +
                                                   `<div class="wide table-scroll" data-id="x"><table></table></div>`)),
                         []);
    });

});


describe('a link', () => {

    it('written with a path of its own is found, as it leads past the base', () => {
        assert.deepEqual(linksPastTheBase(page(`Every reading is in the <a href="/logs">log</a>.`)), [ '/logs' ]);
    });

    it('through toURL passes, and so do one to elsewhere and one within the page', () => {
        assert.deepEqual(linksPastTheBase(page(`<a href="\${toURL('/logs')}">log</a>  <a href="https://www.ptb.de/">PTB</a>  <a href="#legal">legal time</a>`)),
                         []);
    });

});


describe('a page drawn', () => {

    it('with view.ts draws by comparing, by @node/view or by a path of the shared frontend\'s own', () => {
        assert.ok(drawsByComparing(page(`import { html, render } from '@node/view';`)));
        assert.ok(drawsByComparing(page(`import { html, nothing, render, repeat } from '../view';`)));
        assert.ok(drawsByComparing(page(`import { html, render } from './view';`)));
    });

    it('with html.ts does not, nor does one that only speaks of view.ts', () => {
        assert.ok(!drawsByComparing(page(`import { html, must, render } from '@node/html';`)));
        assert.ok(!drawsByComparing(page(`import { html, must, render } from '../html';
                                           // Drawn as '@node/view' would draw it, one day.`)));
    });

});


describe('who is signed in', () => {

    it('said by the page itself is found, whichever way it names them', () => {
        assert.deepEqual(signedInSaidByHand(page(`Signed in as \${auth.user?.roles.join(', ') ?? 'somebody'}, which may look at the name
                                                  resolution but not change it.  Signed in as \${auth.user?.roleTitle ?? 'somebody'}, which may`)),
                         [ `Signed in as \${auth.user?.roles.join(', ') ?? 'somebody'}`, `Signed in as \${auth.user?.roleTitle ?? 'somebody'}` ]);
    });

    it('said through mayButNot passes, and so does a table that shows the name alone', () => {
        assert.deepEqual(signedInSaidByHand(page(`<div class="notice">\${mayButNot('look at the store', 'change it')}</div>
                                                  <tr><td>Signed in as</td><td><code>\${me?.username ?? '-'}</code></td></tr>`)),
                         []);
    });

});


describe('a role', () => {

    it('named as the one that is needed is found, one or several, across a line\'s end', () => {
        assert.deepEqual(rolesNamedAsNeeded(page(`That needs the system administrator role.  That needs the CPO or the system administrator role.
                                                  That needs the driver, the service or the system
                                                  administrator role.  Switching one off needs the CPO role; the others need the installer role.
                                                  That needs the operator role or better.`)),
                         [ 'needs the system administrator role', 'needs the CPO or the system administrator role',
                           'needs the driver, the service or the system administrator role', 'needs the CPO role',
                           'need the installer role', 'needs the operator role' ]);
    });

    it('that is needed without a name passes, and so does what else a page says is needed', () => {
        assert.deepEqual(rolesNamedAsNeeded(page(`That needs a role that may change it.  Looking something up needs a role that may run queries.
                                                  That needs the role that changes how this station connects.
                                                  A partner needs the token it was given to call any of them.
                                                  Which roles there are, and what the role of an account may, is the configuration file's to say.`)),
                         []);
    });

});


describe('a page drawn by comparing', () => {

    it('saying an attribute as text in a tag is found, and one bound passes', () => {
        assert.deepEqual(attributesSaidAsText(page(`<input name="url" \${mayChange ? '' : html\`disabled\`} />
                                                    <input name="port" ?disabled=\${!mayChange} value="\${port}" />`)),
                         [ "${mayChange ? '' : html`disabled`}" ]);
    });

    it('putting an expression between the tags of a textarea is found, and a defaultValue bound passes', () => {
        assert.deepEqual(expressionsInATextarea(page(`<textarea name="reachableAs" rows="4"
                                                          \${mayChange ? '' : html\`disabled\`}>\${names.join('\\n')}</textarea>
                                                      <textarea name="pem" .defaultValue=\${pem} @input=\${(event) => typed(event)}
                                                                ?disabled=\${!may}></textarea>
                                                      <textarea name="note"></textarea>`)),
                         [ "<textarea name=\"reachableAs\" rows=\"4\" ${mayChange ? '' : html`disabled`}>${names.join('\\n')}</textarea>" ]);
    });

});


describe('a pattern', () => {

    it('that the v flag refuses is found, as Chrome then checks nothing', () => {
        assert.deepEqual(patternsABrowserRefuses(page(`<input name="id" pattern="[a-z0-9-]+" />  <input name="cc" pattern="[A-Za-z]{2}" />`)),
                         [ '[a-z0-9-]+' ]);
    });

    it('with its hyphen escaped passes, as the template hands it on, and one with an expression in it is not asked', () => {
        assert.deepEqual(patternsABrowserRefuses(page(`<input name="id" pattern="[a-z0-9\\\\-]+" />
                                                      <input name="user" pattern="[A-Za-z0-9]([A-Za-z0-9._\\\\-]*[A-Za-z0-9])?" />
                                                      <input name="code" pattern="\${codePattern}" />`)),
                         []);
    });

});


describe('a number field', () => {

    it('whose min is not on its steps is found, also where the step is the browser\'s own 1', () => {
        assert.deepEqual(stepsMissingTheirMin(page(`<input type="number" name="tolerance" min="0.001" step="0.1" />
                                                    <input type="number" name="half" min="0.5" />
                                                    <input name="power" step="0.5" min="0.25" type="range" />`)),
                         [ 'min="0.001" step="0.1"', 'min="0.5" step="1"', 'min="0.25" step="0.5"' ]);
    });

    it('whose min is on its steps passes, and so do step="any", an expression, and a field that is no number', () => {
        assert.deepEqual(stepsMissingTheirMin(page(`<input type="number" name="timeout" min="0.1" step="0.1" max="30" />
                                                    <input type="number" name="deviation" min="0.001" step="0.001" />
                                                    <input type="number" name="port" min="1" max="65535" />
                                                    <input type="number" name="checkEvery" min="0" step="0.25" />
                                                    <input type="number" name="offset" min="0.3" step="0.1" />
                                                    <input type="number" name="free" min="0.001" step="any" />
                                                    <input type="number" name="limit" min="\${limits.min}" step="0.1" @input=\${(event) => typed(event)} />
                                                    <input type="text" name="label" min="0.5" />`)),
                         []);
    });

});


describe('a page whose forms another page holds', () => {

    /** What failed where the rules of a fixture's rules file ran, in a runner of their own as for the numbers. */
    function failedIn(rules: string): string[] {

        const env = { ...process.env };
        delete env.NODE_TEST_CONTEXT;

        const child = spawnSync(process.execPath,
                                [ '--test', '--test-reporter=tap', fileURLToPath(new URL(`./fixtures/${rules}`, import.meta.url)) ],
                                { env, encoding: 'utf-8' });

        return child.stdout.split('\n').
                            filter(line => /^\s*not ok \d+ - /.test(line)).
                            map   (line => line.replace(/^\s*not ok \d+ - /, ''));

    }

    it('is asked that it hands them on as sections and does not hold them itself, instead of how it holds them', () => {

        const failed = failedIn('held.rules.ts');

        assert.ok(!failed.some(name => name.startsWith('certificates.ts hands its forms')),
                  `a page that hands its forms on as sections was found not to - failed: ${failed.join(', ')}`);
        assert.ok(failed.some(name => name.startsWith('nosections.ts hands its forms')),
                  `a page said to hand its forms on, with no sections, passed - failed: ${failed.join(', ') || 'nothing'}`);
        assert.ok(failed.some(name => name.startsWith('selfheld.ts hands its forms')),
                  `a page said to hand its forms on that holds them itself passed - failed: ${failed.join(', ') || 'nothing'}`);
        assert.ok(!failed.some(name => /holding anything|holds every form/.test(name)),
                  `a page said to hand its forms on was asked how it holds them - failed: ${failed.join(', ')}`);

    });

    it('is asked how it holds them where it is not said to hand them on', () => {

        const failed = failedIn('unlisted.rules.ts');

        assert.ok(failed.some(name => name === 'certificates.ts says whether it is holding anything'),
                  `a page with forms it neither holds nor is said to hand on passed - failed: ${failed.join(', ') || 'nothing'}`);

    });

});
