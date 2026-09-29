/*
 * What the node writes into the page, read back: every <meta> tag config.ts
 * asks for, as the node fills them in as it serves the stub - among them the
 * name the node goes by, which the pages every kind shares say too.
 *
 * config.ts reads the page once, when it is loaded, so the page is there
 * before it is imported. Where there is none - in every other test Node
 * runs - it gives its defaults: unsaved.test.ts asks one of them.
 */

import { strict as assert } from 'node:assert';
import { describe, it }      from 'node:test';

const page: Record<string, string> = {
    'base':              '/LocalController',
    'api-base':          '/LocalController/api/v1',
    'ext-base':          '/LocalController/ext',
    'frontend-version':  '0.1.0',
    'server-version':    'v1.2.3',
    'node-name':         'local controller'
};

(globalThis as unknown as { document: unknown }).document = {
    querySelector: (selector: string) => {
        const name = /meta\[name="([^"]+)"\]/.exec(selector)?.[1];
        return name !== undefined && name in page ? { content: page[name] } : null;
    }
};

const { config } = await import('./config.ts');


describe('config', () => {

    it('reads what the node wrote into the page', () => {

        assert.deepEqual(config, {
            base:             '/LocalController',
            apiBase:          '/LocalController/api/v1',
            extBase:          '/LocalController/ext',
            frontendVersion:  '0.1.0',
            serverVersion:    'v1.2.3',
            nodeName:         'local controller'
        });

    });

});
