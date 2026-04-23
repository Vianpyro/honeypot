const API = 'https://api.thevhome.com/stats/api';

const COUNTRY_NAMES = new Intl.DisplayNames(['en'], { type: 'region' });

function countryLabel(code) {
    if (!code || code === 'XX') return 'Unknown';
    try {
        const flag = String.fromCodePoint(
            ...[...code.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0))
        );
        return flag + '\u00A0' + (COUNTRY_NAMES.of(code) ?? code);
    } catch {
        return code;
    }
}

function fmtNum(n) {
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 1_000) return (n / 1_000).toFixed(1) + 'k';
    return String(n);
}

function el(id) { return document.getElementById(id); }

function escHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function renderRankList(listId, items, labelFn, max) {
    const ul = el(listId);
    if (!items?.length) {
        ul.innerHTML = '<li class="loading">no data</li>';
        return;
    }
    ul.innerHTML = items.map((item, i) => `
        <li class="rank-item">
            <span class="rank-n">${i + 1}</span>
            <div class="rank-bar-wrap">
                <div class="rank-bar-bg"></div>
                <div class="rank-bar-fill" style="width:${Math.round((item.c / max) * 100)}%"></div>
                <span class="rank-label">${escHtml(labelFn(item))}</span>
            </div>
            <span class="rank-count">${fmtNum(item.c)}</span>
        </li>
    `).join('');
}

function renderChart(volume) {
    const container = el('chart-bars');
    if (!volume?.length) {
        container.innerHTML = '<div class="loading">no data</div>';
        return;
    }
    const max = Math.max(...volume.map(v => v.c), 1);
    container.innerHTML = volume.map(v => `
        <div class="bar-wrap">
            <div class="bar-tooltip">${escHtml(v.d)}: ${v.c}</div>
            <div class="bar" style="height:${Math.max(2, Math.round((v.c / max) * 100))}%"></div>
        </div>
    `).join('');
}

function setLoading() {
    ['list-countries', 'list-services', 'list-paths', 'list-asns', 'list-tls', 'list-protocols', 'list-usernames-a', 'list-usernames-b']
        .forEach(id => { const e = el(id); if (e) e.innerHTML = '<li class="loading">loading...</li>'; });
    el('chart-bars').innerHTML = '<div class="loading">loading data...</div>';
}

async function load(days) {
    el('badge-days').textContent = days + 'd';
    setLoading();
    try {
        const res = await fetch(`${API}?days=${days}`);
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const d = await res.json();

        el('hdr-total').textContent = fmtNum(d.meta.total);
        el('hdr-ts').textContent = new Date(d.meta.generated_at).toLocaleTimeString();
        el('hdr-status').textContent = 'honeypot active';
        el('status-dot').style.background = '';
        el('status-dot').style.boxShadow = '';
        el('kpi-total').textContent = d.meta.total < 10_000 ? d.meta.total : fmtNum(d.meta.total);
        el('kpi-countries').textContent = d.meta.total_countries ?? '—';
        el('kpi-services').textContent = d.meta.total_services ?? '—';
        el('kpi-creds').textContent = fmtNum(d.meta.total_usernames ?? 0);

        renderChart(d.volume);

        const maxC = arr => arr?.length ? Math.max(...arr.map(x => x.c)) : 1;

        renderRankList('list-countries', d.top_countries,
            item => countryLabel(item.country), maxC(d.top_countries));

        renderRankList('list-services', d.top_services,
            item => item.service ?? 'unknown', maxC(d.top_services));

        renderRankList('list-paths', d.top_paths,
            item => item.path ?? '/', maxC(d.top_paths));

        renderRankList('list-asns', d.top_asns,
            item => item.as_organization ? `AS${item.asn} - ${item.as_organization}` : `AS${item.asn}`,
            maxC(d.top_asns));

        renderRankList('list-tls', d.top_tls,
            item => item.tls_version ?? 'unknown', maxC(d.top_tls));

        renderRankList('list-protocols', d.top_protocols,
            item => item.http_protocol ?? 'unknown', maxC(d.top_protocols));


        // Split usernames across two columns
        const usernames = d.top_usernames ?? [];
        const half = Math.ceil(usernames.length / 2);
        const maxU = maxC(usernames);
        renderRankList('list-usernames-a', usernames.slice(0, half),
            item => item.username, maxU);
        renderRankList('list-usernames-b', usernames.slice(half),
            item => item.username, maxU);

    } catch (e) {
        el('hdr-status').textContent = 'honeypot unreachable';
        el('status-dot').style.background = 'var(--red)';
        el('status-dot').style.boxShadow = '0 0 8px var(--red)';
        const errHtml = `<li class="error-msg">error: ${escHtml(e.message)}</li>`;
        ['list-countries', 'list-services', 'list-paths', 'list-asns', 'list-tls', 'list-protocols', 'list-usernames-a', 'list-usernames-b']
            .forEach(id => { const elem = el(id); if (elem) elem.innerHTML = errHtml; });
        el('chart-bars').innerHTML = `<div class="error-msg">error: ${escHtml(e.message)}</div>`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const daysSelect = el('days-select');
    el('btn-refresh').addEventListener('click', () => load(parseInt(daysSelect.value)));
    daysSelect.addEventListener('change', () => load(parseInt(daysSelect.value)));
    load(90);
});
