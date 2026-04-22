// ============================================================
//  helpers.js — Response helper functions
// ============================================================

export function html(body, status = 200, extra = {}) {
    return new Response(body, { status, headers: { 'Content-Type': 'text/html;charset=UTF-8', ...extra } });
}

export function json(data, status = 200, extra = {}) {
    return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...extra } });
}

export function plain(body, status = 200, extra = {}) {
    return new Response(body, { status, headers: { 'Content-Type': 'text/plain', ...extra } });
}

export function phpHeaders() {
    return { 'X-Powered-By': 'PHP/8.1.2', Server: 'Apache/2.4.52 (Ubuntu)' };
}

export function notFound() {
    return new Response('Not found', { status: 404 });
}
