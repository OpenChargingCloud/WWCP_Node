/* A page said to hand its forms on that holds them itself as well: the listing is wrong. */

declare const unsaved: { heldBy(check: () => boolean): () => void };

export const options = {
    sections: () => [ { below: 'presents', draw: () => '<form id="request-form"><input name="subject" /></form>' } ]
};

export const release = unsaved.heldBy(() => false);
