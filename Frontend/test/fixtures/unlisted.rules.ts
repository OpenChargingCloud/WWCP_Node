/*
 * The rules of pages.ts asked of the pages in ./held/ with none of them said
 * to hand its forms on: run by pages.test.ts, which says what failed.
 */

import { everyPageIn } from '../pages.ts';

everyPageIn(new URL('./held/', import.meta.url), { withForms: [ 'certificates.ts', 'nosections.ts', 'selfheld.ts' ] });
