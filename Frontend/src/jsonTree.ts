/*
 * A JSON value as a tree to browse: every object and array folded at first,
 * unfolded one level at a time by a click or the keyboard, and searched by
 * the names and the values in it - what a page shows of a document too big to
 * read laid out at once, an OCPP Device Model say.
 *
 * Made as elements, not drawn by view.ts: what is shown goes in as text, which
 * needs no escaping - a node at the other end writes much of what a tree like
 * this shows -, and a level is made only when it is first unfolded, so that a
 * tree of thousands of values costs one row until somebody looks inside.
 *
 *   const tree = jsonTree(value, { summary: ... });
 *   page.append(tree);
 *   expandAll(tree);  collapseAll(tree);  filterTree(tree, 'needle');
 */


/** What a tree is asked for. */
export interface JSONTreeOptions {

    /**
     * What a folded object or array says of itself after its name, in place of
     * how many entries it has - "= true" for a variable, say -, or null for
     * the count.
     */
    summary?:  (Value: object, Path: readonly string[]) => string | null;

}

/** What a row of the tree stands for. */
interface Entry {
    value:    unknown;
    path:     string[];
    options:  JSONTreeOptions;
}

const entries = new WeakMap<HTMLElement, Entry>();


/** An element of the given kind and class, with the given text - as text. */
function element<K extends keyof HTMLElementTagNameMap>(Tag: K, Class = '', Text?: string): HTMLElementTagNameMap[K] {
    const made = document.createElement(Tag);
    if (Class !== '')
        made.className = Class;
    if (Text !== undefined)
        made.textContent = Text;
    return made;
}

/** Whether the value has entries of its own: an object or an array. */
function isBranch(Value: unknown): Value is object {
    return typeof Value === 'object' && Value !== null;
}

/** The entries of an object or an array, by name or by index. */
function childrenOf(Value: object): [string, unknown][] {
    return Array.isArray(Value)
               ? Value.map((item, index) => [String(index), item] as [string, unknown])
               : Object.entries(Value);
}

/** A value that has no entries, as JSON writes it - and the class its type is shown in. */
function leafText(Value: unknown): { text: string; type: string } {
    switch (typeof Value) {
        case 'string':   return { text: JSON.stringify(Value), type: 'string'  };
        case 'number':   return { text: String(Value),         type: 'number'  };
        case 'boolean':  return { text: String(Value),         type: 'boolean' };
        default:         return { text: Value === null ? 'null' : String(Value), type: 'null' };
    }
}

/** What a folded branch says of itself. */
function summaryOf(Value: object, Path: readonly string[], Options: JSONTreeOptions): string {

    const said = Options.summary?.(Value, Path) ?? null;

    if (said !== null)
        return said;

    const count = Array.isArray(Value) ? Value.length : Object.keys(Value).length;

    return Array.isArray(Value)
               ? `[ ${count} ${count === 1 ? 'item' : 'items'} ]`
               : `{ ${count} ${count === 1 ? 'entry' : 'entries'} }`;

}

/** One row: a branch, folded, or a leaf. */
function nodeElement(Name: string | null, Value: unknown, Path: string[], Options: JSONTreeOptions): HTMLElement {

    const node = element('div', 'jt-node');
    node.setAttribute('role', 'treeitem');
    node.dataset.path = JSON.stringify(Path);

    const row  = element('div', 'jt-row');

    if (isBranch(Value)) {

        node.classList.add('jt-branch');
        node.setAttribute('aria-expanded', 'false');

        row.tabIndex = 0;
        row.append(element('i', 'jt-caret fa-solid fa-caret-right'));

        if (Name !== null)
            row.append(element('span', 'jt-key', Name));

        row.append(element('span', 'jt-summary', summaryOf(Value, Path, Options)));

        entries.set(node, { value: Value, path: Path, options: Options });

    }

    else {

        node.classList.add('jt-leaf');

        const leaf = leafText(Value);

        if (Name !== null) {
            row.append(element('span', 'jt-key', Name));
            row.append(element('span', 'jt-colon', ':'));
        }

        row.append(element('span', `jt-value jt-${leaf.type}`, leaf.text));

    }

    node.append(row);

    return node;

}

/** The level under a branch, made the first time it is unfolded. */
function childrenElement(Node: HTMLElement): HTMLElement {

    const made = Node.querySelector<HTMLElement>(':scope > .jt-children');

    if (made !== null)
        return made;

    const entry     = entries.get(Node);
    const children  = element('div', 'jt-children');
    children.setAttribute('role', 'group');

    if (entry !== undefined && isBranch(entry.value)) {

        const all = childrenOf(entry.value);

        if (all.length === 0)
            children.append(element('div', 'jt-empty', Array.isArray(entry.value) ? 'no items' : 'no entries'));

        for (const [name, value] of all)
            children.append(nodeElement(name, value, [ ...entry.path, name ], entry.options));

    }

    Node.append(children);

    return children;

}

/** Unfold a branch, or fold it again. */
export function setExpanded(Node: HTMLElement, Expanded: boolean): void {

    if (!Node.classList.contains('jt-branch'))
        return;

    if (Expanded)
        childrenElement(Node).hidden = false;
    else {
        const children = Node.querySelector<HTMLElement>(':scope > .jt-children');
        if (children !== null)
            children.hidden = true;
    }

    Node.setAttribute('aria-expanded', String(Expanded));
    Node.querySelector(':scope > .jt-row > .jt-caret')?.classList.replace(Expanded ? 'fa-caret-right' : 'fa-caret-down',
                                                                           Expanded ? 'fa-caret-down'  : 'fa-caret-right');

}

/** Whether a branch is unfolded. */
export function isExpanded(Node: HTMLElement): boolean {
    return Node.getAttribute('aria-expanded') === 'true';
}


/**
 * The tree of the given value: its own entries shown, each of them folded -
 * or the value itself, where it is no object and no array.
 */
export function jsonTree(Value: unknown, Options: JSONTreeOptions = {}): HTMLElement {

    const tree = element('div', 'json-tree');
    tree.setAttribute('role', 'tree');

    if (isBranch(Value)) {

        const all = childrenOf(Value);

        if (all.length === 0)
            tree.append(element('div', 'jt-empty', Array.isArray(Value) ? 'no items' : 'no entries'));

        for (const [name, value] of all)
            tree.append(nodeElement(name, value, [ name ], Options));

    }
    else
        tree.append(nodeElement(null, Value, [], Options));

    tree.addEventListener('click', event => {

        const row  = (event.target as Element | null)?.closest<HTMLElement>('.jt-row');
        const node = row?.parentElement;

        // A value is selected to be copied, not folded.
        if (!node?.classList.contains('jt-branch'))
            return;

        setExpanded(node, !isExpanded(node));

    });

    tree.addEventListener('keydown', event => {

        const row  = (event.target as Element | null)?.closest<HTMLElement>('.jt-row');
        const node = row?.parentElement;

        if (!node?.classList.contains('jt-branch'))
            return;

        switch (event.key) {

            case 'Enter':
            case ' ':
                event.preventDefault();
                setExpanded(node, !isExpanded(node));
                break;

            case 'ArrowRight':
                event.preventDefault();
                setExpanded(node, true);
                break;

            case 'ArrowLeft':
                event.preventDefault();
                setExpanded(node, false);
                break;

        }

    });

    return tree;

}

/** Every branch of the tree, the levels not yet made included. */
function everyBranch(Tree: HTMLElement): HTMLElement[] {

    const found: HTMLElement[] = [];
    const todo = [ ...Tree.querySelectorAll<HTMLElement>(':scope > .jt-branch') ];

    while (todo.length > 0) {
        const node = todo.shift()!;
        found.push(node);
        todo.push(...childrenElement(node).querySelectorAll<HTMLElement>(':scope > .jt-branch'));
    }

    return found;

}

/** Every level unfolded. */
export function expandAll(Tree: HTMLElement): void {
    for (const node of everyBranch(Tree))
        setExpanded(node, true);
}

/** Every level folded, as the tree was made. */
export function collapseAll(Tree: HTMLElement): void {
    for (const node of Tree.querySelectorAll<HTMLElement>('.jt-branch'))
        setExpanded(node, false);
}

/**
 * Only what the given text is found in - a name, or a value, whatever its
 * case -, with every branch on the way to it unfolded and every other row
 * hidden; a branch whose own name matches shows all of itself. Everything,
 * folded as it was made, where the text is empty. Answers how many rows
 * matched.
 */
export function filterTree(Tree: HTMLElement, Text: string): number {

    const needle = Text.trim().toLowerCase();

    if (needle === '') {
        for (const node of Tree.querySelectorAll<HTMLElement>('.jt-node'))
            node.hidden = false;
        collapseAll(Tree);
        return 0;
    }

    let matched = 0;

    /** Whether the node, or anything under it, matches - showing what does. */
    function walk(Node: HTMLElement, Inside: boolean): boolean {

        const own = (Node.querySelector(':scope > .jt-row')?.textContent ?? '').toLowerCase().includes(needle);

        if (own)
            matched++;

        if (!Node.classList.contains('jt-branch')) {
            Node.hidden = !(own || Inside);
            return own;
        }

        let below = false;

        for (const child of childrenElement(Node).querySelectorAll<HTMLElement>(':scope > .jt-node'))
            below = walk(child, Inside || own) || below;

        Node.hidden = !(own || below || Inside);

        setExpanded(Node, below);

        return own || below;

    }

    for (const node of Tree.querySelectorAll<HTMLElement>(':scope > .jt-node'))
        walk(node, false);

    return matched;

}
