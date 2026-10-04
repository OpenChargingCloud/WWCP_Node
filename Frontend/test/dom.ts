/*
 * A browser's document for a test that draws: lit-html draws into a real DOM,
 * and Node has none. happy-dom stands in, as the window and document of this
 * test file's process - Node's runner gives every test file a process of its
 * own, so nothing else sees it.
 *
 * Imported first, before anything that imports lit-html: lit-html looks for
 * the document as it is loaded.
 *
 *   import '../test/dom.ts';
 */

import { GlobalRegistrator } from '@happy-dom/global-registrator';

GlobalRegistrator.register({ url: 'http://127.0.0.1/' });
