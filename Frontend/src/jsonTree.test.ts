/*
 * A JSON value as a tree to browse: folded at first, a level made only when it
 * is unfolded, unfolded and folded by a click and by the keyboard, every level
 * at once, and searched by names and values - and what a value says goes in
 * as text, never as markup.
 *
 * Run with `npm test`.
 */

import '../test/dom.ts';

import { strict as assert } from 'node:assert';
import { describe, it }      from 'node:test';

import { collapseAll, expandAll, filterTree, isExpanded, jsonTree } from './jsonTree.ts';


const aDocument = {
    'ocpp2.1': {
        SecurityCtrlr: {
            OrganizationName:   { value: 'GraphDefined', mutability: 'ReadWrite' },
            BasicAuthPassword:  { hidden: true,          mutability: 'WriteOnly' }
        },
        'DNSClientCtrlr[ptb1]': {
            Enabled:            { value: 'true',         mutability: 'ReadOnly' }
        }
    },
    'ocpp1.6': {
        HeartbeatInterval:      { value: '300', readonly: false },
        list:                   [ 1, null, false ]
    }
};

/** The row of the given path, as the tree made it. */
function nodeAt(Tree: HTMLElement, ...Path: string[]): HTMLElement | null {
    return Tree.querySelector<HTMLElement>(`.jt-node[data-path='${JSON.stringify(Path)}']`);
}

/** The names of the rows that are shown, in order. */
function shownKeys(Tree: HTMLElement): string[] {
    return [ ...Tree.querySelectorAll<HTMLElement>('.jt-node') ].
               filter (node => !node.hidden && node.closest('.jt-children[hidden]') === null && node.closest('.jt-node[hidden]') === null).
               map    (node => node.querySelector(':scope > .jt-row > .jt-key')?.textContent ?? '');
}


describe('A JSON tree', () => {

    it('shows the first level folded, and makes nothing under it yet', () => {

        const tree = jsonTree(aDocument);

        assert.deepEqual(shownKeys(tree), [ 'ocpp2.1', 'ocpp1.6' ]);
        assert.equal(nodeAt(tree, 'ocpp2.1')?.getAttribute('aria-expanded'), 'false');
        assert.ok(tree.querySelector('.jt-children') === null, 'A level was made before it was unfolded.');
        assert.equal(nodeAt(tree, 'ocpp2.1')?.querySelector('.jt-summary')?.textContent, '{ 2 entries }');

    });

    it('unfolds a level by a click and folds it again, one level at a time', () => {

        const tree = jsonTree(aDocument);

        nodeAt(tree, 'ocpp2.1')!.querySelector<HTMLElement>('.jt-row')!.click();

        assert.ok(isExpanded(nodeAt(tree, 'ocpp2.1')!));
        assert.deepEqual(shownKeys(tree), [ 'ocpp2.1', 'SecurityCtrlr', 'DNSClientCtrlr[ptb1]', 'ocpp1.6' ]);
        assert.equal(isExpanded(nodeAt(tree, 'ocpp2.1', 'SecurityCtrlr')!), false);

        nodeAt(tree, 'ocpp2.1')!.querySelector<HTMLElement>('.jt-row')!.click();

        assert.deepEqual(shownKeys(tree), [ 'ocpp2.1', 'ocpp1.6' ]);

    });

    it('is unfolded and folded at the keyboard', () => {

        const tree = jsonTree(aDocument);
        const row  = nodeAt(tree, 'ocpp1.6')!.querySelector<HTMLElement>('.jt-row')!;

        assert.equal(row.tabIndex, 0);

        row.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
        assert.ok(isExpanded(nodeAt(tree, 'ocpp1.6')!));

        row.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft', bubbles: true }));
        assert.equal(isExpanded(nodeAt(tree, 'ocpp1.6')!), false);

        row.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
        assert.ok(isExpanded(nodeAt(tree, 'ocpp1.6')!));

    });

    it('shows a value as JSON writes it, in the class of its type, and an array by index', () => {

        const tree = jsonTree(aDocument);

        expandAll(tree);

        const value = nodeAt(tree, 'ocpp2.1', 'SecurityCtrlr', 'OrganizationName', 'value')!.querySelector('.jt-value')!;

        assert.equal(value.textContent, '"GraphDefined"');
        assert.ok   (value.classList.contains('jt-string'));
        assert.equal(nodeAt(tree, 'ocpp1.6', 'list')?.querySelector('.jt-summary')?.textContent, '[ 3 items ]');
        assert.ok   (nodeAt(tree, 'ocpp1.6', 'list', '1')?.querySelector('.jt-value.jt-null'));
        assert.ok   (nodeAt(tree, 'ocpp1.6', 'list', '2')?.querySelector('.jt-value.jt-boolean'));
        assert.ok   (nodeAt(tree, 'ocpp1.6', 'list', '0')?.querySelector('.jt-value.jt-number'));

    });

    it('unfolds every level at once, and folds them all again', () => {

        const tree = jsonTree(aDocument);

        expandAll(tree);

        assert.ok(shownKeys(tree).includes('BasicAuthPassword'));
        assert.ok([ ...tree.querySelectorAll<HTMLElement>('.jt-branch') ].every(isExpanded));

        collapseAll(tree);

        assert.deepEqual(shownKeys(tree), [ 'ocpp2.1', 'ocpp1.6' ]);

    });

    it('says of a folded branch what it is asked to say', () => {

        const tree = jsonTree(aDocument, {
                         summary: value => 'value' in value ? `= ${JSON.stringify((value as { value: unknown }).value)}` : null
                     });

        expandAll(tree);

        assert.equal(nodeAt(tree, 'ocpp2.1', 'DNSClientCtrlr[ptb1]', 'Enabled')?.querySelector(':scope > .jt-row > .jt-summary')?.textContent, '= "true"');
        assert.equal(nodeAt(tree, 'ocpp2.1', 'SecurityCtrlr')?.querySelector(':scope > .jt-row > .jt-summary')?.textContent,                    '{ 2 entries }');

    });

    it('finds a name or a value, unfolds the way to it, hides the rest - and shows all again', () => {

        const tree = jsonTree(aDocument);

        assert.ok(filterTree(tree, 'graphdefined') > 0);
        assert.deepEqual(shownKeys(tree), [ 'ocpp2.1', 'SecurityCtrlr', 'OrganizationName', 'value' ]);

        // A branch whose own name matches shows all of itself.
        filterTree(tree, 'dnsclientctrlr');
        assert.deepEqual(shownKeys(tree), [ 'ocpp2.1', 'DNSClientCtrlr[ptb1]' ]);
        nodeAt(tree, 'ocpp2.1', 'DNSClientCtrlr[ptb1]')!.querySelector<HTMLElement>('.jt-row')!.click();
        assert.deepEqual(shownKeys(tree), [ 'ocpp2.1', 'DNSClientCtrlr[ptb1]', 'Enabled' ]);

        assert.equal(filterTree(tree, 'nothing like it'), 0);
        assert.deepEqual(shownKeys(tree), []);

        filterTree(tree, '');
        assert.deepEqual(shownKeys(tree), [ 'ocpp2.1', 'ocpp1.6' ]);

    });

    it('writes what a value says as text, never as markup', () => {

        const tree = jsonTree({ '<b>name</b>': '<img src=x onerror=alert(1)>' });

        assert.ok(tree.querySelector('img') === null, 'A value was written as markup.');
        assert.ok(tree.querySelector('b')   === null, 'A name was written as markup.');
        assert.equal(tree.querySelector('.jt-key')?.textContent, '<b>name</b>');

    });

});
