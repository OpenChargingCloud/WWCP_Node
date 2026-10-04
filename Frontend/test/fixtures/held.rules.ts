/*
 * The rules of pages.ts asked of the pages in ./held/, all three said to hand
 * their forms on: run by pages.test.ts, which says what failed. Meant to fail
 * for two of them, and so not named like a test.
 */

import { everyPageIn } from '../pages.ts';

everyPageIn(new URL('./held/', import.meta.url), {
    withForms:      [ 'certificates.ts', 'nosections.ts', 'selfheld.ts' ],
    heldElsewhere:  { 'certificates.ts':  'sections of the node\'s certificates page',
                      'nosections.ts':    'said so, and wrongly',
                      'selfheld.ts':      'said so, and wrongly' }
});
