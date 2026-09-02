// ============================================================
//  logger.js — event delivery to the PostgreSQL API
// ============================================================
//
// D1 IS GONE. This used to write the event to D1 and then run campaign
// detection against it; both now happen inside the API, in one transaction --
// see api/src/campaign.rs, which also fixed two features that could never fire
// in the D1 version.
//
// What is left is one call, and it stays wrapped in `waitUntil` by the caller
// so the visitor is never made to wait for it.

import { sendEvent } from './ingest.js';

export async function logEvent(meta, env) {
    // `sendEvent` never throws and never rejects: it reports its outcome as a
    // status string and logs its own failures. There is deliberately nothing to
    // catch here, and nothing left to fall back to -- the dual-write period is
    // over, and a lost event is now a lost event.
    //
    // The failure rate that decided this cutover was measured by comparing
    // D1's row count with PostgreSQL's over the same window.
    await sendEvent(meta, env);
}
