// What is left of the tagged template every page of every kind of node was
// written in, html`...`, which built a string and drew it with innerHTML: it
// was the one file all eight kinds had alike. Every page and the frame draw
// with view.ts now, and what was html.ts's is gone but this.

/** querySelector that throws instead of returning null. */
export function must<T extends Element>(root: ParentNode, selector: string): T {

    const element = root.querySelector<T>(selector);

    if (element === null)
        throw new Error(`Element '${selector}' not found!`);

    return element;

}
