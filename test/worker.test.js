import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { shouldLogEvent } from '../cloudflare/logging.js';

test('an eligible honeypot request is logged once', () => {
    assert.equal(shouldLogEvent('/wp-login.php', false, false), true);
});

test('tests, verified bots, and ignored paths are not logged', () => {
    assert.equal(shouldLogEvent('/wp-login.php', true, false), false);
    assert.equal(shouldLogEvent('/wp-login.php', false, true), false);
    assert.equal(shouldLogEvent('/favicon.ico', false, false), false);
});

test('worker has one logging scheduling site and no undefined monitoring map', async () => {
    const worker = await readFile(new URL('../cloudflare/worker.js', import.meta.url), 'utf8');
    assert.equal((worker.match(/ctx\.waitUntil\(logEvent\(/g) ?? []).length, 1);
    assert.equal(worker.includes('MONITORING_PATHS.get('), false);
});
