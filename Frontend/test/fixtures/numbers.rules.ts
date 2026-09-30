/*
 * Every rule of pages.ts asked of the pages in ./numbers/, which have no form:
 * run by pages.test.ts through node:test's run(), which says what failed. Not
 * a test of its own - it is meant to fail - and so not named like one.
 */

import { everyPageIn } from '../pages.ts';

everyPageIn(new URL('./numbers/', import.meta.url), { withForms: [] });
