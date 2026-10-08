// ==UserScript==
// @name         IPAddrInfo
// @namespace    net.kister.ipaddrinfo
// @description  Highlight an IPv4/IPv6 address to see its IP assignment / Whois information in a toast popup
// @downloadURL  https://raw.githubusercontent.com/jkister/tampermonkey/main/src/IPAddrInfo.user.js
// @updateURL    https://raw.githubusercontent.com/jkister/tampermonkey/main/src/IPAddrInfo.user.js
// @homepage     https://github.com/jkister/tampermonkey
// @icon         https://www.google.com/s2/favicons?sz=64&domain=arin.net
// @version      20261008.01
// @author       jkister
// @match        *://*/*
// @connect      whois.arin.net
// @connect      rdap.org
// @connect      rdap.arin.net
// @grant        GM_xmlhttpRequest
// ==/UserScript==

(function () {
    'use strict';

    // ------------------------------------------------------------------
    // Data sources
    //   Primary: ARIN Whois-RWS  https://whois.arin.net/rest/ip/<addr>
    //            Gives orgRef (@handle/@name), parentNetRef (@handle/@name),
    //            and per-netBlock description (nettype), plus the org record
    //            for the postal address.  Covers ARIN (North America) space.
    //   Fallback: RDAP via rdap.org bootstrap  https://rdap.org/ip/<addr>
    //            Routes to the correct RIR (RIPE/APNIC/LACNIC/AFRINIC) and
    //            returns a uniform shape.  Some fields (parent handle naming,
    //            exact nettype wording) differ from ARIN; we degrade
    //            gracefully for those.
    // ------------------------------------------------------------------

    // ---------- IP address recognition ----------

    // IPv4 octet 0-255
    const V4_OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])';
    const V4 = `${V4_OCTET}(?:\\.${V4_OCTET}){3}`;

    // IPv6, including :: abbreviation and embedded IPv4 tail.
    // Deliberately permissive; validated more strictly below.
    const V6_SEG = '[0-9A-Fa-f]{1,4}';
    const V6 = '(?:' +
        `(?:${V6_SEG}:){7}${V6_SEG}` + '|' +                               // full
        `(?:${V6_SEG}:){1,7}:` + '|' +                                     // trailing ::
        `:(?::${V6_SEG}){1,7}` + '|' +                                     // leading ::
        `(?:${V6_SEG}:){1,6}:${V6_SEG}` + '|' +
        `(?:${V6_SEG}:){1,5}(?::${V6_SEG}){1,2}` + '|' +
        `(?:${V6_SEG}:){1,4}(?::${V6_SEG}){1,3}` + '|' +
        `(?:${V6_SEG}:){1,3}(?::${V6_SEG}){1,4}` + '|' +
        `(?:${V6_SEG}:){1,2}(?::${V6_SEG}){1,5}` + '|' +
        `${V6_SEG}:(?::${V6_SEG}){1,6}` + '|' +
        '::' + '|' +                                                       // bare ::
        `(?:${V6_SEG}:){1,6}${V4}` + '|' +                                 // v4-mapped tail
        `::(?:${V6_SEG}:){0,5}${V4}` +
        ')';

    // Whole-selection match: optional surrounding brackets, optional /prefix.
    const v4Re = new RegExp(`^\\[?(${V4})\\]?(?:/(\\d{1,2}))?$`);
    const v6Re = new RegExp(`^\\[?(${V6})\\]?(?:/(\\d{1,3}))?$`, 'i');

    function parseSelection(text) {
        const s = text.trim();

        let m = v4Re.exec(s);
        if (m) {
            const addr = m[1];
            const prefix = m[2] !== undefined ? parseInt(m[2], 10) : null;
            if (prefix !== null && prefix > 32) return null;
            return { addr, prefix, version: 4 };
        }

        m = v6Re.exec(s);
        if (m) {
            // Reject lone "::" or things that are clearly not an address.
            const addr = m[1];
            if (!/[0-9A-Fa-f]/.test(addr) && addr !== '::') return null;
            // Must contain a colon to be v6 (guards against the v6 regex
            // accidentally matching a stray token).
            if (addr.indexOf(':') === -1) return null;
            const prefix = m[2] !== undefined ? parseInt(m[2], 10) : null;
            if (prefix !== null && prefix > 128) return null;
            return { addr, prefix, version: 6 };
        }

        return null;
    }

    // ---------- HTTP helper (CORS-free via GM_xmlhttpRequest) ----------

    function httpGetJson(url) {
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: 'GET',
                url,
                headers: { 'Accept': 'application/json, application/rdap+json' },
                timeout: 12000,
                onload: (resp) => {
                    if (resp.status >= 200 && resp.status < 300) {
                        try {
                            resolve(JSON.parse(resp.responseText));
                        } catch (e) {
                            reject(new Error('bad JSON from ' + url));
                        }
                    } else {
                        reject(new Error('HTTP ' + resp.status + ' from ' + url));
                    }
                },
                onerror: () => reject(new Error('network error for ' + url)),
                ontimeout: () => reject(new Error('timeout for ' + url)),
            });
        });
    }

    // Unwrap ARIN Whois-RWS "{"$":"value"}" nodes.
    function v(node) {
        if (node == null) return null;
        if (typeof node === 'object' && '$' in node) return node['$'];
        return node;
    }

    function esc(str) {
        return String(str).replace(/[&<>"']/g, (c) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[c]));
    }

    // ---------- ARIN Whois-RWS lookup ----------

    async function lookupArin(addr) {
        const net = await httpGetJson(`https://whois.arin.net/rest/ip/${encodeURIComponent(addr)}`);
        if (!net || !net.net) throw new Error('no ARIN net record');
        const n = net.net;

        // netBlocks.netBlock may be a single object or an array.
        let blocks = n.netBlocks && n.netBlock ? n.netBlock : (n.netBlocks ? n.netBlocks.netBlock : null);
        if (blocks && !Array.isArray(blocks)) blocks = [blocks];

        // Choose the block that actually contains addr if possible; otherwise
        // the one with the shortest prefix (the "main" allocation), matching
        // the examples (151.196.0.0/14 is the shortest-prefix block).
        let chosen = null;
        if (blocks && blocks.length) {
            const matching = blocks.filter((b) => blockContains(b, addr));
            const pool = matching.length ? matching : blocks;
            chosen = pool.reduce((best, b) => {
                const bl = parseInt(v(b.cidrLength), 10);
                if (!best) return b;
                return bl < parseInt(v(best.cidrLength), 10) ? b : best;
            }, null);
        }

        const start = chosen ? v(chosen.startAddress) : v(n.startAddress);
        const len = chosen ? v(chosen.cidrLength) : null;
        const cidr = len !== null ? `${start}/${len}` : v(n.startAddress);
        const nettype = chosen ? v(chosen.description) : null;

        const orgRef = n.orgRef || n.customerRef || null;
        const orgName = orgRef ? orgRef['@name'] : null;
        const orgId = orgRef ? orgRef['@handle'] : null;
        const parent = n.parentNetRef ? n.parentNetRef['@handle'] : null;

        // ARIN returns HTTP 200 with a *referral stub* for space managed by
        // another RIR (e.g. "name":"RIPE-CBLK", org handle "RIPE"/"APNIC"/
        // "LACNIC"/"AFRINIC", nettype "Allocated to RIPE NCC"). That stub has
        // no real registrant data, so reject it and let the caller fall
        // through to RDAP, which routes to the authoritative RIR.
        const OTHER_RIRS = ['RIPE', 'APNIC', 'LACNIC', 'AFRINIC'];
        const isReferralStub =
            (orgId && OTHER_RIRS.indexOf(orgId.toUpperCase()) !== -1) ||
            (nettype && /^allocated to\b/i.test(nettype));
        if (isReferralStub) {
            throw new Error('ARIN referral to ' + (orgId || 'another RIR'));
        }

        const result = {
            source: 'ARIN',
            cidr,
            orgName,
            orgId,
            parent,
            nettype,
            netName: v(n.name),
            netHandle: v(n.handle),
            address: null, city: null, state: null, postal: null, country: null,
        };

        // Fetch the org record for the postal address, best-effort.
        if (orgId) {
            try {
                const orgResp = await httpGetJson(`https://whois.arin.net/rest/org/${encodeURIComponent(orgId)}`);
                const o = orgResp && (orgResp.org || orgResp.customer);
                if (o) {
                    result.city = v(o.city);
                    result.state = v(o['iso3166-2']);
                    result.postal = v(o.postalCode);
                    result.country = o['iso3166-1'] ? v(o['iso3166-1'].name) : null;
                    if (o.streetAddress && o.streetAddress.line) {
                        let lines = o.streetAddress.line;
                        if (!Array.isArray(lines)) lines = [lines];
                        result.address = lines.map((l) => v(l)).filter(Boolean).join(', ');
                    }
                }
            } catch (e) {
                // Address is optional; ignore failures.
            }
        }

        return result;
    }

    // Does an ARIN netBlock contain addr? Only attempted for IPv4 (cheap).
    function blockContains(block, addr) {
        if (addr.indexOf(':') !== -1) return false; // skip v6 math
        const start = v(block.startAddress);
        const end = v(block.endAddress);
        if (!start || !end || start.indexOf(':') !== -1) return false;
        const toInt = (ip) => ip.split('.').reduce((a, o) => (a << 8 >>> 0) + parseInt(o, 10), 0) >>> 0;
        try {
            const a = toInt(addr), s = toInt(start), e = toInt(end);
            return a >= s && a <= e;
        } catch (_) {
            return false;
        }
    }

    // ---------- RDAP fallback (rdap.org bootstrap) ----------

    function vcardField(entity, field) {
        if (!entity || !entity.vcardArray || !Array.isArray(entity.vcardArray)) return null;
        const props = entity.vcardArray[1];
        if (!Array.isArray(props)) return null;
        for (const p of props) {
            if (Array.isArray(p) && p[0] === field) {
                if (field === 'adr' && p[1] && p[1].label) return p[1].label;
                return p[3];
            }
        }
        return null;
    }

    function findRegistrant(entities) {
        if (!Array.isArray(entities)) return null;
        for (const e of entities) {
            if (Array.isArray(e.roles) && e.roles.indexOf('registrant') !== -1) return e;
        }
        // fall back to first entity with an org/fn name
        for (const e of entities) {
            if (vcardField(e, 'fn') || vcardField(e, 'org')) return e;
        }
        return entities[0] || null;
    }

    async function lookupRdap(addr) {
        const data = await httpGetJson(`https://rdap.org/ip/${encodeURIComponent(addr)}`);
        if (!data) throw new Error('no RDAP record');

        let cidr = null;
        if (Array.isArray(data.cidr0_cidrs) && data.cidr0_cidrs.length) {
            // shortest prefix = main allocation
            const c = data.cidr0_cidrs.reduce((best, x) =>
                (!best || x.length < best.length) ? x : best, null);
            const pfx = c.v4prefix || c.v6prefix;
            cidr = `${pfx}/${c.length}`;
        } else if (data.startAddress) {
            cidr = data.handle || data.startAddress;
        }

        const reg = findRegistrant(data.entities);
        const orgName = reg ? (vcardField(reg, 'fn') || vcardField(reg, 'org')) : null;
        const orgId = reg ? reg.handle : null;

        const result = {
            source: 'RDAP',
            cidr,
            orgName,
            orgId,
            parent: data.parentHandle || null,
            nettype: data.type || null,
            netName: data.name || null,
            netHandle: data.handle || null,
            address: null, city: null, state: null, postal: null,
            country: data.country || null,
        };

        if (reg) {
            const label = vcardField(reg, 'adr');
            if (label) {
                const parts = String(label).split('\n').map((s) => s.trim()).filter(Boolean);
                result.address = parts.join(', ');
            }
        }

        return result;
    }

    // ---------- Orchestration ----------

    async function lookup(addr) {
        // Try ARIN first; on any failure (incl. non-ARIN space), use RDAP.
        try {
            return await lookupArin(addr);
        } catch (e) {
            return await lookupRdap(addr);
        }
    }

    function titleCaseNettype(s) {
        if (!s) return s;
        // ARIN gives "Direct Allocation"/"Reallocated"; RDAP gives
        // "DIRECT ALLOCATION"/"ALLOCATION". Normalize ALLCAPS to Title Case.
        if (s === s.toUpperCase()) {
            return s.toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
        }
        return s;
    }

    function render(input, r) {
        const lines = [];
        const label = input.prefix !== null
            ? `${input.addr}/${input.prefix}`
            : input.addr;
        lines.push(`<b>${esc(label)}</b>`);

        if (r.cidr)    lines.push(`CIDR: ${esc(r.cidr)}`);
        if (r.orgName) lines.push(`orgname: ${esc(r.orgName)}`);
        if (r.orgId)   lines.push(`orgid: ${esc(r.orgId)}`);
        if (r.parent)  lines.push(`parent: ${esc(r.parent)}`);
        if (r.nettype) lines.push(`nettype: ${esc(titleCaseNettype(r.nettype))}`);

        const loc = [];
        if (r.address) loc.push(esc(r.address));
        if (r.city)    loc.push(esc(r.city));
        if (r.state)   loc.push(esc(r.state));
        if (r.postal)  loc.push(esc(r.postal));
        if (r.country) loc.push(esc(r.country));
        if (loc.length) lines.push(loc.join(', '));

        lines.push(`<span style="opacity:0.6;font-size:11px">source: ${esc(r.source)}</span>`);
        return lines.join('<br>');
    }

    // ---------- Toast UI (adapted from AWS Region Translator) ----------

    const tooltip = document.createElement('div');
    tooltip.style.position = 'fixed';
    tooltip.style.background = 'rgba(0,0,0,0.85)';
    tooltip.style.color = '#fff';
    tooltip.style.padding = '8px 12px';
    tooltip.style.borderRadius = '6px';
    tooltip.style.fontSize = '14px';
    tooltip.style.lineHeight = '1.4';
    tooltip.style.zIndex = 2147483647;
    tooltip.style.pointerEvents = 'auto';
    tooltip.style.transition = 'opacity 0.2s';
    tooltip.style.opacity = 0;
    tooltip.style.display = 'inline-block';
    tooltip.style.maxWidth = '90vw';
    tooltip.style.fontFamily = 'system-ui, sans-serif';

    const closeBtn = document.createElement('span');
    closeBtn.innerHTML = '&times;';
    closeBtn.style.float = 'right';
    closeBtn.style.cursor = 'pointer';
    closeBtn.style.marginLeft = '12px';
    closeBtn.style.fontWeight = 'bold';
    tooltip.appendChild(closeBtn);

    const contentDiv = document.createElement('div');
    tooltip.appendChild(contentDiv);
    document.body.appendChild(tooltip);

    closeBtn.addEventListener('click', hideTooltip);

    let onClickOutside = null;

    function hideTooltip() {
        tooltip.style.opacity = 0;
        if (onClickOutside) {
            document.removeEventListener('click', onClickOutside);
            onClickOutside = null;
        }
    }

    function showTooltip(content, x, y) {
        contentDiv.innerHTML = content;
        tooltip.style.opacity = 1;
        tooltip.style.left = '0px';
        tooltip.style.top = '0px';
        // Position after it renders so we can measure and keep it on-screen.
        requestAnimationFrame(() => {
            const rect = tooltip.getBoundingClientRect();
            let left = x + 12;
            let top = y + 12;
            if (left + rect.width > window.innerWidth - 8) {
                left = Math.max(8, window.innerWidth - rect.width - 8);
            }
            if (top + rect.height > window.innerHeight - 8) {
                top = Math.max(8, y - rect.height - 12);
            }
            tooltip.style.left = `${left}px`;
            tooltip.style.top = `${top}px`;
        });

        if (onClickOutside) document.removeEventListener('click', onClickOutside);
        onClickOutside = (event) => {
            if (!tooltip.contains(event.target)) hideTooltip();
        };
        setTimeout(() => document.addEventListener('click', onClickOutside), 0);
    }

    document.addEventListener('keydown', function (e) {
        if ((e.key === 'Escape' || e.key === 'Esc') && tooltip.style.opacity === '1') {
            hideTooltip();
        }
    });

    document.addEventListener('mouseup', function (event) {
        if (tooltip.contains(event.target)) return;
        if (event.button !== 0) return;

        const selectedText = window.getSelection().toString().trim();
        if (!selectedText) return;

        const parsed = parseSelection(selectedText);
        if (!parsed) return;

        const x = event.clientX;
        const y = event.clientY;

        showTooltip('Looking up <b>' + esc(selectedText) + '</b> &hellip;', x, y);

        lookup(parsed.addr)
            .then((r) => {
                showTooltip(render(parsed, r), x, y);
            })
            .catch((err) => {
                showTooltip(
                    'No assignment info found for <b>' + esc(parsed.addr) + '</b>' +
                    '<br><span style="opacity:0.6;font-size:11px">' + esc(err.message) + '</span>',
                    x, y
                );
                console.log('IPAddrInfo: lookup failed for ' + parsed.addr + ': ' + err.message);
            });
    });
})();
