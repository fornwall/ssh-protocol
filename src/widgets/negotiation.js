// Algorithm negotiation playground: edit the client's and server's KEXINIT
// name-lists and see what RFC 4253 section 7.1 selects in each category, why
// earlier client entries were passed over, and which features the marker
// pseudo-algorithms in kex_algorithms switch on.
(() => {
    'use strict';

    const { h, field, liveRegion } = SSHWidgets;

    // Ciphers with their own integrity tag: OpenSSH ignores the MAC lists for
    // a direction that selects one (OpenSSH PROTOCOL, AES-GCM draft).
    const AEAD = new Set([
        'chacha20-poly1305@openssh.com', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com',
    ]);

    // Marker pseudo-algorithms (RFC 8308 section 2.1, strict-KEX draft 3.1).
    const MARKERS = {
        'ext-info-c': 'c', 'ext-info-s': 's',
        'kex-strict-c': 'c', 'kex-strict-s': 's',
        'kex-strict-c-v00@openssh.com': 'c', 'kex-strict-s-v00@openssh.com': 's',
    };

    // RFC 4253 section 7.1: a KEX method is usable only with a host-key
    // algorithm that has the capability it needs. Every method here needs a
    // signature except GSS-API key exchange (RFC 4462, RFC 8732), and every
    // host-key algorithm can sign except "null" (RFC 4462 section 5).
    const needsSignature = (kex) => !kex.startsWith('gss-');
    const canSign = (hostKey) => hostKey !== 'null';

    const CATEGORIES = [
        { key: 'kex', title: 'Key exchange method', what: 'key exchange method', markers: true },
        { key: 'hostkey', title: 'Server host-key algorithm', what: 'host key type' },
        { key: 'enc', title: 'Encryption', what: 'cipher', directional: true },
        { key: 'mac', title: 'MAC', what: 'MAC', directional: true },
        { key: 'comp', title: 'Compression', what: 'compression method', directional: true },
    ];
    const DIRS = { cs: 'client → server', sc: 'server → client' };
    const cap = (text) => text[0].toUpperCase() + text.slice(1);

    // Each list pair is [client, server]; directional categories give one pair
    // for both directions or { cs, sc } for separate lists.
    const MODERN_KEX = 'mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,' +
        'curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,' +
        'ext-info-c,kex-strict-c-v00@openssh.com';
    const MODERN_HOSTKEY = 'ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256';
    const MODERN_ENC = 'chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr';
    const MODERN_MAC = 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512';
    const GSS = 'gss-curve25519-sha256-toWM5Slw5Ew8Mqkay+al2g==';

    const PRESETS = [
        {
            name: 'Chapter example',
            note: 'The worked example above. cipher-a and cipher-b are placeholder names.',
            kex: ['curve25519-sha256,ecdh-sha2-nistp256', 'ecdh-sha2-nistp256,curve25519-sha256'],
            hostkey: ['ssh-ed25519,rsa-sha2-256', 'rsa-sha2-256'],
            enc: { cs: ['aes128-gcm@openssh.com,cipher-a', 'cipher-a,aes128-gcm@openssh.com'],
                sc: ['cipher-b,cipher-a', 'cipher-a,cipher-b'] },
            mac: { cs: ['hmac-sha2-256', 'hmac-sha2-512'], sc: ['hmac-sha2-256', 'hmac-sha2-512,hmac-sha2-256'] },
            comp: ['none', 'none,zlib'],
        },
        {
            name: 'Modern client and server',
            note: 'Abridged OpenSSH-style lists, including the ext-info and strict-KEX markers that OpenSSH appends.',
            kex: [MODERN_KEX, 'mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,' +
                'curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ext-info-s,kex-strict-s-v00@openssh.com'],
            hostkey: [MODERN_HOSTKEY, 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256'],
            enc: [MODERN_ENC, MODERN_ENC],
            mac: [MODERN_MAC, MODERN_MAC],
            comp: ['none,zlib@openssh.com', 'none,zlib@openssh.com'],
        },
        {
            name: 'Server without markers or AEAD',
            note: 'An older server: no ext-info or strict-KEX markers, and only CTR-mode ciphers, so a MAC must match.',
            kex: [MODERN_KEX, 'curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256'],
            hostkey: [MODERN_HOSTKEY, 'rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256'],
            enc: [MODERN_ENC, 'aes256-ctr,aes192-ctr,aes128-ctr'],
            mac: [MODERN_MAC, 'hmac-sha2-512,hmac-sha2-256'],
            comp: ['none,zlib@openssh.com', 'none'],
        },
        {
            name: 'Legacy server with only ssh-rsa',
            note: 'The server’s only host key is RSA, offered as ssh-rsa (SHA-1 signatures), which current OpenSSH clients no longer accept by default.',
            kex: [MODERN_KEX, 'curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1'],
            hostkey: [MODERN_HOSTKEY, 'ssh-rsa'],
            enc: [MODERN_ENC, 'aes128-ctr,aes256-ctr,aes128-cbc,3des-cbc'],
            mac: [MODERN_MAC, 'hmac-sha1,hmac-sha2-256'],
            comp: ['none,zlib@openssh.com', 'none,zlib@openssh.com'],
        },
        {
            name: 'No common cipher',
            note: 'A device that offers only CBC-mode ciphers, which current OpenSSH clients do not offer by default.',
            kex: [MODERN_KEX, 'ecdh-sha2-nistp256,diffie-hellman-group14-sha256'],
            hostkey: [MODERN_HOSTKEY, 'rsa-sha2-256'],
            enc: [MODERN_ENC, 'aes128-cbc,aes256-cbc,3des-cbc'],
            mac: [MODERN_MAC, 'hmac-sha2-256,hmac-sha1'],
            comp: ['none,zlib@openssh.com', 'none'],
        },
        {
            name: 'Strict-KEX names differ',
            note: 'The client offers only the standard strict-KEX name, the server only the pre-standard one.',
            kex: ['curve25519-sha256,ext-info-c,kex-strict-c', 'curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com'],
            hostkey: [MODERN_HOSTKEY, 'ssh-ed25519'],
            enc: [MODERN_ENC, MODERN_ENC],
            mac: [MODERN_MAC, MODERN_MAC],
            comp: ['none', 'none'],
        },
        {
            name: 'GSS-API KEX, no host key',
            note: 'Kerberos-authenticated key exchange (RFC 4462, RFC 8732) with a server that has no host key and so offers only the “null” host-key algorithm, which cannot sign.',
            kex: [`curve25519-sha256,${GSS},ext-info-c`, `curve25519-sha256,${GSS}`],
            hostkey: ['ssh-ed25519,rsa-sha2-256,null', 'null'],
            enc: [MODERN_ENC, MODERN_ENC],
            mac: [MODERN_MAC, MODERN_MAC],
            comp: ['none', 'none'],
        },
    ];

    const parse = (text) => text.split(',').map((name) => name.trim()).filter(Boolean);
    const code = (text) => h('code', null, text);

    // RFC 4253 7.1: the first client name that the server also lists and that
    // `reject` (a compatibility check) does not rule out.
    function scan({ c, s }, { reject, markers } = {}) {
        let chosen = null;
        const steps = c.map((name) => {
            if (chosen) return { name, status: 'unreached' };
            if (!s.includes(name)) {
                return markers && MARKERS[name] ? { name, status: 'marker', why: 'marker, never selected' }
                    : { name, status: 'absent', why: 'the server does not list it' };
            }
            const rule = reject ? reject(name) : null;
            if (rule) return { name, status: 'incompatible', rule, why: `both list it, but ${rule}` };
            chosen = name;
            return { name, status: 'chosen' };
        });
        return { steps, chosen, empty: !c.length ? 'client' : !s.length ? 'server' : null };
    }

    const usable = (res) => res.skipped || (res.chosen && !res.error);

    function negotiate(p) {
        const hk = p.hostkey.cs;
        const signers = hk.c.filter((name) => hk.s.includes(name) && canSign(name));
        const kex = scan(p.kex.cs, {
            markers: true,
            reject: (name) => (!MARKERS[name] && needsSignature(name) && !signers.length
                ? 'it needs a signature-capable host-key algorithm that both sides list, and there is none'
                : null),
        });
        if (kex.chosen && MARKERS[kex.chosen]) {
            kex.error = `both lists contain the marker ${kex.chosen}, so it would be selected; it is not a key exchange method, so both sides must disconnect`;
        }
        const method = kex.error ? null : kex.chosen;
        const r = { kex: { cs: kex }, enc: {}, mac: {}, comp: {} };
        r.hostkey = {
            cs: scan(hk, {
                reject: (name) => (method && needsSignature(method) && !canSign(name)
                    ? `it cannot sign and ${method} needs a host-key signature` : null),
            }),
        };
        for (const d of ['cs', 'sc']) {
            r.enc[d] = scan(p.enc[d]);
            r.mac[d] = scan(p.mac[d]);
            if (AEAD.has(r.enc[d].chosen)) r.mac[d].skipped = r.enc[d].chosen;
            r.comp[d] = scan(p.comp[d]);
        }
        return r;
    }

    // What an OpenSSH client prints: it checks KEX and host key by name only,
    // then each direction (server → client first) and stops at the first miss.
    function opensshError(p, r) {
        const order = [['kex', 'cs'], ['hostkey', 'cs']];
        for (const d of ['sc', 'cs']) order.push(['enc', d], ['mac', d], ['comp', d]);
        for (const [key, d] of order) {
            const lists = p[key][d];
            if (key === 'mac' && r.mac[d].skipped) continue;
            const match = lists.c.find((name) => lists.s.includes(name));
            if (key === 'kex' && MARKERS[match]) return null;
            if (!match) {
                const what = CATEGORIES.find((cat) => cat.key === key).what;
                return `Unable to negotiate with 203.0.113.5 port 22: no matching ${what} found. Their offer: ${lists.s.join(',')}`;
            }
        }
        return null;
    }

    function features(p) {
        const kc = p.kex.cs.c;
        const ks = p.kex.cs.s;
        const items = [];
        const item = (cls, label, ...text) => items.push(h('li', { class: `w-neg-feature ${cls}` }, h('strong', null, label), ' ', ...text));

        item(kc.includes('ext-info-c') ? 'w-neg-on' : 'w-neg-off', 'Server → client EXT_INFO:',
            kc.includes('ext-info-c')
                ? ['the client listed ', code('ext-info-c'), ', so the server may send ', code('SSH_MSG_EXT_INFO'), ' (for example ', code('server-sig-algs'), ') after its first NEWKEYS.']
                : ['off; the client did not list ', code('ext-info-c'), '.']);
        item(ks.includes('ext-info-s') ? 'w-neg-on' : 'w-neg-off', 'Client → server EXT_INFO:',
            ks.includes('ext-info-s')
                ? ['the server listed ', code('ext-info-s'), ', so the client may send ', code('SSH_MSG_EXT_INFO'), '.']
                : ['off; the server did not list ', code('ext-info-s'), '.']);

        const std = kc.includes('kex-strict-c') && ks.includes('kex-strict-s');
        const pre = kc.includes('kex-strict-c-v00@openssh.com') && ks.includes('kex-strict-s-v00@openssh.com');
        const cOffers = kc.some((n) => n.startsWith('kex-strict-c'));
        const sOffers = ks.some((n) => n.startsWith('kex-strict-s'));
        let strict;
        if (std || pre) {
            strict = ['active, via ', code(std ? 'kex-strict-c' : 'kex-strict-c-v00@openssh.com'), ' and ',
                code(std ? 'kex-strict-s' : 'kex-strict-s-v00@openssh.com'),
                '. KEXINIT must be the first packet, only KEX messages are allowed during the initial exchange, and sequence numbers reset after each NEWKEYS.'];
        } else if (cOffers && sOffers) {
            strict = ['off; both sides offer it, but under different name forms (standard versus ', code('-v00@openssh.com'), ').'];
        } else {
            strict = [cOffers ? 'off; the server did not offer it.' : sOffers ? 'off; the client did not offer it.' : 'off; neither side offered it.'];
        }
        item(std || pre ? 'w-neg-on' : 'w-neg-off', 'Strict KEX:', ...strict);

        const hc = p.hostkey.cs.c;
        const hs = p.hostkey.cs.s;
        const kexSame = kc[0] === ks[0];
        const hkSame = hc[0] === hs[0];
        const guess = kexSame && hkSame
            ? ['right: both proposals start with ', code(kc[0] || '—'), ' and ', code(hc[0] || '—'), ', so the guessed packet is used.']
            : ['wrong: the proposals start with different ',
                kexSame ? 'host-key algorithms' : hkSame ? 'KEX methods' : 'KEX methods and host-key algorithms',
                ', so the receiver silently discards the one guessed packet. The check compares only the first entries, not the negotiated result.'];
        item(kexSame && hkSame ? 'w-neg-on' : 'w-neg-off', 'Guessed KEX packet:', 'if a peer sets ', code('first_kex_packet_follows'),
            ', its guess is ', ...guess);

        const wrong = [...kc.filter((n) => MARKERS[n] === 's'), ...ks.filter((n) => MARKERS[n] === 'c')];
        if (wrong.length) {
            item('w-neg-warn', 'Wrong-role marker:', ...wrong.map((n, i) => [i ? ', ' : '', code(n)]),
                ' is listed by the wrong side. Senders must not do this, and the peer may disconnect (RFC 8308 section 2.2).');
        }
        return items;
    }

    // ---- Rendering ----------------------------------------------------------

    const ICON = { chosen: '✓', absent: '✗', marker: '⚑', incompatible: '⚠', unreached: '·' };

    function chips(label, entries) {
        return h('div', { class: 'w-neg-row' },
            h('div', { class: 'w-neg-rowlabel' }, label),
            h('ol', { class: 'w-neg-chips', 'aria-label': label },
                entries.map(({ name, status, why }, i) => h('li', { class: `w-neg-chip w-neg-${status}`, title: why || null },
                    h('span', { class: 'w-neg-rank', 'aria-hidden': 'true' }, `${ICON[status] || ''} ${i + 1}`),
                    ' ', name,
                    why || status === 'chosen' ? h('span', { class: 'w-sr-only' }, ` (${why || 'selected'})`) : null))),
            entries.length ? null : h('div', { class: 'w-neg-empty' }, 'empty list'));
    }

    function explain(res, cat, lists) {
        const passed = res.steps.filter((s) => s.why && s.status !== 'unreached');
        const reasons = passed.length
            ? [' Passed over: ', ...passed.flatMap((s, i) => [i ? '; ' : '', code(s.name), ` (${s.why})`]), '.'] : [];
        if (res.skipped) {
            return h('p', { class: 'w-status w-neg-skip' }, 'Not negotiated: ', code(res.skipped),
                ' is an AEAD cipher with its own integrity tag, so the MAC lists are ignored for this direction.');
        }
        if (res.error) return h('p', { class: 'w-status w-bad' }, `Fails: ${res.error}.`);
        if (!res.chosen) {
            // Absent names are visible in the chips; spell out only the ruled-out ones.
            const ruled = res.steps.filter((s) => s.status === 'incompatible');
            return h('p', { class: 'w-status w-bad' }, `No usable ${cat.what}: the connection fails and both sides disconnect.`,
                res.empty ? ` The ${res.empty}’s list is empty; every list here must name at least one algorithm.` : '',
                ruled.map((s) => [' ', code(s.name), ` is listed by both, but ${s.rule}.`]));
        }
        const rank = res.steps.findIndex((s) => s.status === 'chosen') + 1;
        const serverRank = lists.s.indexOf(res.chosen) + 1;
        return h('p', { class: 'w-status w-good' }, 'Selected: ', code(res.chosen),
            rank === 1 ? ', the client’s first choice' : `, the client’s choice #${rank} and the first one the server also lists`,
            '.', serverRank > 1 ? ` The server lists it #${serverRank}; its order does not matter.` : '', ...reasons);
    }

    SSHWidgets.register('negotiation', (root) => {
        const live = liveRegion();
        let state;
        let views = [];

        const presetSelect = h('select', { onchange: () => load(PRESETS[presetSelect.selectedIndex]) },
            PRESETS.map((preset) => h('option', null, preset.name)));
        const presetNote = h('p', { class: 'w-note' });
        const summary = h('div', { class: 'w-neg-summary' });
        const cards = h('div', { class: 'w-neg-cards' });

        function load(preset) {
            state = { preset, lists: {}, split: {} };
            for (const cat of CATEGORIES) {
                const v = preset[cat.key];
                const pair = ([c, s]) => ({ c, s });
                state.split[cat.key] = !Array.isArray(v);
                state.lists[cat.key] = Array.isArray(v) ? { cs: pair(v), sc: pair(v) } : { cs: pair(v.cs), sc: pair(v.sc) };
            }
            presetNote.textContent = preset.note;
            views = [];
            cards.replaceChildren(...CATEGORIES.map(card));
            update();
        }

        function card(cat) {
            const body = h('div');
            const lists = state.lists[cat.key];
            const fill = () => {
                views = views.filter((v) => v.cat !== cat);
                const groups = !cat.directional ? [['cs']] : state.split[cat.key] ? [['cs'], ['sc']] : [['cs', 'sc']];
                body.replaceChildren(...groups.map((dirs) => section(cat, dirs, !cat.directional ? '' : dirs.length === 2 ? 'Both directions' : cap(DIRS[dirs[0]]))));
            };
            let toggle = null;
            if (cat.directional) {
                toggle = h('input', {
                    type: 'checkbox', checked: state.split[cat.key],
                    onchange: () => {
                        state.split[cat.key] = toggle.checked;
                        if (!toggle.checked) lists.sc = { ...lists.cs };
                        fill();
                        update();
                    },
                });
            }
            fill();
            return h('section', { class: 'w-neg-card' },
                h('div', { class: 'w-neg-cardhead' },
                    h('h4', null, cat.title),
                    toggle ? h('label', { class: 'w-neg-split' }, toggle, ' Separate lists per direction') : null),
                body);
        }

        function section(cat, dirs, heading) {
            const lists = state.lists[cat.key];
            const input = (side) => {
                const el = h('input', {
                    type: 'text', class: 'w-mono', spellcheck: false, autocomplete: 'off', autocapitalize: 'off',
                    value: lists[dirs[0]][side],
                    'aria-label': `${cat.title}${heading ? `, ${heading}` : ''}: ${side === 'c' ? 'client' : 'server'} name-list`,
                    oninput: () => {
                        for (const d of dirs) lists[d][side] = el.value;
                        update();
                    },
                });
                return el;
            };
            const view = { cat, dirs, client: h('div'), server: h('div'), result: h('div') };
            views.push(view);
            return h('div', { class: 'w-neg-section' },
                heading ? h('div', { class: 'w-neg-dir' }, heading) : null,
                h('div', { class: 'w-cols' },
                    h('div', { class: 'w-neg-side' }, field('Client, in preference order', input('c')), view.client),
                    h('div', { class: 'w-neg-side' }, field('Server', input('s')), view.server)),
                view.result);
        }

        function proposals() {
            const p = {};
            for (const cat of CATEGORIES) {
                p[cat.key] = {};
                for (const d of ['cs', 'sc']) {
                    const lists = state.lists[cat.key][d];
                    p[cat.key][d] = { c: parse(lists.c), s: parse(lists.s) };
                }
            }
            return p;
        }

        let lastSaid = '';
        function update() {
            const p = proposals();
            const r = negotiate(p);

            for (const view of views) {
                const res = r[view.cat.key][view.dirs[0]];
                const lists = p[view.cat.key][view.dirs[0]];
                const skippedAll = view.dirs.every((d) => r[view.cat.key][d].skipped);
                view.client.replaceChildren(chips('Client scan',
                    skippedAll ? res.steps.map(({ name }) => ({ name, status: 'plain' })) : res.steps));
                view.client.classList.toggle('w-neg-ignored', skippedAll);
                view.server.replaceChildren(chips('Server list', lists.s.map((name) => ({
                    name,
                    status: !skippedAll && name === res.chosen ? 'chosen' : view.cat.markers && MARKERS[name] ? 'marker' : 'plain',
                }))));
                view.server.classList.toggle('w-neg-ignored', skippedAll);
                const lines = view.dirs.map((d) => explain(r[view.cat.key][d], view.cat, p[view.cat.key][d]));
                if (lines.length === 2 && lines[0].textContent !== lines[1].textContent) {
                    lines.forEach((line, i) => line.prepend(h('strong', null, `${cap(DIRS[view.dirs[i]])}: `)));
                    view.result.replaceChildren(...lines);
                } else {
                    view.result.replaceChildren(lines[0]);
                }
            }

            const failed = [];
            for (const cat of CATEGORIES) {
                for (const d of cat.directional ? ['cs', 'sc'] : ['cs']) {
                    if (!usable(r[cat.key][d])) failed.push(`${cat.what}${cat.directional ? ` (${DIRS[d]})` : ''}`);
                }
            }
            let outcome;
            if (failed.length) {
                const report = opensshError(p, r);
                outcome = [
                    h('p', { class: 'w-status w-bad' }, h('strong', null, 'Negotiation fails'),
                        `: no usable ${failed.join(', ')}. Both sides disconnect; there is no fallback.`),
                    report ? h('p', { class: 'w-note' }, 'An OpenSSH client stops at the first failure it checks and reports:',
                        h('br'), h('code', { class: 'w-neg-report' }, report)) : null,
                ];
            } else {
                const dir = (d) => [code(r.enc[d].chosen), ' with ',
                    r.mac[d].skipped ? 'its built-in tag' : code(r.mac[d].chosen), ', compression ', code(r.comp[d].chosen)];
                outcome = [
                    h('p', { class: 'w-status w-good' }, h('strong', null, 'Negotiation succeeds.'),
                        ' Both peers compute this result from the two KEXINIT messages; neither announces it.'),
                    h('dl', { class: 'w-neg-result' },
                        h('dt', null, 'KEX'), h('dd', null, code(r.kex.cs.chosen)),
                        h('dt', null, 'Host key'), h('dd', null, code(r.hostkey.cs.chosen)),
                        h('dt', null, 'C→S'), h('dd', null, ...dir('cs')),
                        h('dt', null, 'S→C'), h('dd', null, ...dir('sc'))),
                ];
            }
            summary.replaceChildren(...[
                outcome,
                h('ul', { class: `w-neg-features${failed.length ? ' w-neg-ignored' : ''}` }, features(p)),
                failed.length ? h('p', { class: 'w-note' }, 'These features only matter once negotiation succeeds.') : null,
            ].flat().filter(Boolean));

            const said = failed.length ? `Negotiation fails: no usable ${failed.join(', ')}.` : 'Negotiation succeeds.';
            if (said !== lastSaid) live.say(said);
            lastSaid = said;
        }

        root.append(
            h('p', { class: 'w-title' }, 'KEXINIT negotiation playground'),
            h('div', { class: 'w-controls' },
                field('Preset', presetSelect),
                h('button', { type: 'button', onclick: () => load(PRESETS[presetSelect.selectedIndex]) }, 'Reset lists')),
            presetNote,
            summary,
            h('p', { class: 'w-note w-neg-legend' },
                'Each list is a comma-separated name-list. The client’s list is scanned left to right: ',
                '✓ selected, ✗ the server does not list it, ⚠ both list it but it is incompatible, ',
                '⚑ marker (never selected), · not reached. Language lists are omitted; they may be empty and need no match.'),
            cards,
            live);
        load(PRESETS[0]);
    });
})();
