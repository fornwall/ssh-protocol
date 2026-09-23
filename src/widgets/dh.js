// Toy Diffie–Hellman: both sides of a key agreement with small numbers, what
// an eavesdropper sees, and what an attacker in the middle can and cannot do.
// Mode "ff" is finite-field DH (RFC 4253 e/f); mode "ec" is ECDH (RFC 5656
// Q_C/Q_S) on the chapter's toy curve y² = x³ + 2x + 2 (mod 17).
(() => {
    'use strict';

    const { h, append, field, liveRegion, stepper, modPow, mpint, sshString, toHex } = SSHWidgets;

    // ---- Finite-field group ----------------------------------------------

    function isPrime(n) {
        if (n < 2) return false;
        for (let d = 2; d * d <= n; d += 1) if (n % d === 0) return false;
        return true;
    }

    function orderOf(g, p) {
        let x = g % p;
        for (let k = 1; k < p; k += 1) {
            if (x === 1) return k;
            x = (x * g) % p;
        }
        return 0;
    }

    function finiteField(p, g) {
        const P = BigInt(p);
        const order = orderOf(g, p);
        return {
            kind: 'ff', p, g, order, base: BigInt(g),
            min: 2, max: order - 1, // RFC 4253: 1 < x < q, q = order of g
            mul: (k, X) => modPow(X, BigInt(k), P),
            eq: (X, Y) => X === Y,
            fmt: (X) => String(X),
            secret: (X) => X,
            pubText: (k, X) => `${g}^${k} mod ${p} = ${X}`,
            agreeText: (k, Y, K) => `${Y}^${k} mod ${p} = ${K}`,
            pubWire: (X) => mpint(X),
            // The recipient's check. RFC 4253 only demands [1, p − 1]; OpenSSH
            // also rejects 1 and p − 1, the small subgroup of a safe prime.
            reject: (X, name) => (X <= 1n || X >= P - 1n
                ? `OpenSSH accepts a finite-field public value only if 1 < ${name} < p − 1 = ${p - 1}; RFC 4253 alone would let it through`
                : null),
            log(X) { // brute-force discrete logarithm
                let x = 1;
                for (let k = 1; k <= order; k += 1) {
                    x = (x * g) % p;
                    if (BigInt(x) === X) return k;
                }
                return 0;
            },
        };
    }

    // ---- Toy elliptic curve ----------------------------------------------

    const EC = { p: 17n, a: 2n, b: 2n, G: [5n, 1n], n: 19 };
    const mod = (x) => ((x % EC.p) + EC.p) % EC.p;
    const inv = (x) => modPow(mod(x), EC.p - 2n, EC.p);

    // Returns { point, lambda, num, den } so a step can be explained; null is O.
    function ecAdd(P, Q) {
        if (!P) return { point: Q };
        if (!Q) return { point: P };
        const [x1, y1] = P;
        const [x2, y2] = Q;
        if (x1 === x2 && mod(y1 + y2) === 0n) return { point: null, vertical: true };
        const doubling = x1 === x2;
        const num = doubling ? 3n * x1 * x1 + EC.a : y2 - y1;
        const den = doubling ? 2n * y1 : x2 - x1;
        const lambda = mod(num * inv(den));
        const x3 = mod(lambda * lambda - x1 - x2);
        const y3 = mod(lambda * (x1 - x3) - y1);
        return { point: [x3, y3], lambda, num, den, doubling };
    }

    function ecMul(k, P) {
        let R = null;
        for (let i = 0; i < k; i += 1) R = ecAdd(R, P).point;
        return R;
    }

    const fmtPoint = (P) => (P ? `(${P[0]}, ${P[1]})` : 'O');
    const multiples = [null];
    for (let k = 1; k <= EC.n; k += 1) multiples.push(ecMul(k, EC.G));
    const multipleOf = (P) => multiples.findIndex((Q, k) => k > 0 && fmtPoint(Q) === fmtPoint(P));

    const toyCurve = {
        kind: 'ec', base: EC.G, order: EC.n, min: 1, max: EC.n - 1, // RFC 5656: d in [1, n−1]
        mul: (k, P) => ecMul(k, P),
        eq: (P, Q) => fmtPoint(P) === fmtPoint(Q),
        fmt: fmtPoint,
        secret: (P) => P[0], // the x-coordinate
        pubText: (k, P) => `${k}·G = ${fmtPoint(P)}`,
        agreeText(k, Q, K) {
            const m = k * multipleOf(Q);
            const reduced = m > EC.n ? ` = ${m % EC.n}G` : '';
            return `${k}·${fmtPoint(Q)} = ${m}G${reduced} = ${fmtPoint(K)}, so K = ${K[0]}`;
        },
        pubWire: (P) => sshString(Uint8Array.of(4, Number(P[0]), Number(P[1]))),
        reject: (P) => (P ? null : 'it is the point at infinity'),
        log: multipleOf,
    };

    // ---- Protocol wording per mode ---------------------------------------

    const WORDS = {
        ff: {
            init: 'SSH_MSG_KEXDH_INIT (30)', reply: 'SSH_MSG_KEXDH_REPLY (31)',
            e: 'e', f: 'f', type: 'mpint', key: 'computes K',
            hard: 'For a real 2048-bit group this search is out of reach: RFC 9142 rates group 14 at about 112 bits of security.',
        },
        ec: {
            init: 'SSH_MSG_KEX_ECDH_INIT (30)', reply: 'SSH_MSG_KEX_ECDH_REPLY (31)',
            e: 'Q_C', f: 'Q_S', type: 'string', key: 'computes K',
            hard: 'On a 256-bit curve the best generic attacks take about 2^128 steps.',
        },
    };

    function mount(root, config) {
        const num = (value, fallback) => (Number.isInteger(Number(value)) ? Number(value) : fallback);
        const state = { mode: config.mode === 'ec' ? 'ec' : 'ff', mitm: false, forge: 'server' };
        const defaults = {
            ff: { a: num(config.a, 6), b: num(config.b, 15), m1: 9, m2: 13 },
            ec: { a: 3, b: 7, m1: 5, m2: 11 },
        };

        const input = (value) => h('input', {
            type: 'number', inputmode: 'numeric', value: String(value),
            class: 'w-mono', oninput: update,
        });
        const inputs = { p: input(num(config.p, 23)), g: input(num(config.g, 5)) };
        for (const key of ['a', 'b', 'm1', 'm2']) inputs[key] = input(defaults[state.mode][key]);

        const modeButtons = ['ff', 'ec'].map((mode) => h('button', {
            type: 'button',
            onclick: () => setMode(mode),
        }, mode === 'ff' ? 'Finite field (mod p)' : 'Toy elliptic curve'));
        const mitmBox = h('input', {
            type: 'checkbox', onchange: () => { state.mitm = mitmBox.checked; update(); },
        });
        const forgeSelect = h('select', { onchange: () => { state.forge = forgeSelect.value; update(); } },
            h('option', { value: 'server' }, 'the server’s host key and signature'),
            h('option', { value: 'own' }, 'its own host key K_M, signing H1'));

        const groupNote = h('p', { class: 'w-note' });
        const ffPanel = h('div', {},
            h('div', { class: 'w-cols' }, field('Prime p', inputs.p), field('Generator g', inputs.g)),
            groupNote);
        const ecPanel = h('p', { class: 'w-mono dh-params' },
            'Curve y² = x³ + 2x + 2 (mod 17), base point G = (5, 1) of order 19');
        const attackerFields = h('div', { class: 'dh-attacker-fields' },
            h('div', { class: 'w-cols' },
                field('Attacker secret toward server, m1', inputs.m1),
                field('Attacker secret toward client, m2', inputs.m2)),
            field('The attacker’s reply to the client carries', forgeSelect));
        const out = h('div', { class: 'dh-out' });
        const walk = h('div', { class: 'dh-walk' });
        const live = liveRegion();

        root.append(
            h('p', { class: 'w-title' }, 'Toy Diffie–Hellman'),
            h('div', { class: 'w-controls', role: 'group', 'aria-label': 'Group' }, modeButtons),
            ffPanel, ecPanel,
            h('div', { class: 'w-cols' },
                field('Client secret a', inputs.a),
                field('Server secret b', inputs.b)),
            h('div', { class: 'w-controls' },
                h('label', {}, mitmBox, ' Attacker in the middle')),
            attackerFields,
            out, walk, live);

        function setMode(mode) {
            state.mode = mode;
            for (const key of ['a', 'b', 'm1', 'm2']) inputs[key].value = String(defaults[mode][key]);
            update();
        }

        function readGroup() {
            if (state.mode === 'ec') return { group: toyCurve };
            const p = Number(inputs.p.value);
            const g = Number(inputs.g.value);
            if (!Number.isInteger(p) || p < 5 || p > 1000000 || !isPrime(p)) {
                return { error: 'p must be a prime between 5 and 1,000,000.' };
            }
            if (!Number.isInteger(g) || g < 2 || g > p - 2) return { error: `g must be between 2 and ${p - 2}.` };
            const group = finiteField(p, g);
            if (group.order < 4) return { error: `g = ${g} has order ${group.order}: pick a generator of a larger subgroup.` };
            return { group };
        }

        function readSecret(key, group, who) {
            const value = Number(inputs[key].value);
            const ok = Number.isInteger(value) && value >= group.min && value <= group.max;
            inputs[key].setAttribute('aria-invalid', String(!ok));
            return ok ? value : `${who} must be a whole number from ${group.min} to ${group.max}.`;
        }

        function update() {
            modeButtons.forEach((b, i) => b.setAttribute('aria-pressed', String(['ff', 'ec'][i] === state.mode)));
            attackerFields.hidden = !state.mitm;
            renderGroupPanel();
            out.replaceChildren();
            walk.hidden = true;
            const { group, error } = readGroup();
            if (error) return showError(error);
            const s = {
                a: readSecret('a', group, 'The client secret a'),
                b: readSecret('b', group, 'The server secret b'),
            };
            if (state.mitm) {
                s.m1 = readSecret('m1', group, 'The attacker secret m1');
                s.m2 = readSecret('m2', group, 'The attacker secret m2');
            }
            const bad = Object.values(s).find((v) => typeof v === 'string');
            if (bad) return showError(bad);
            render(group, s);
            if (group.kind === 'ec') {
                walk.hidden = false;
                renderWalk(s);
            }
        }

        function showError(text) {
            out.append(h('p', { class: 'w-status w-bad', role: 'alert' }, text));
        }

        function renderGroupPanel() {
            ffPanel.hidden = state.mode !== 'ff';
            ecPanel.hidden = state.mode !== 'ec';
            if (state.mode === 'ec') return;
            const { group } = readGroup();
            let note = '';
            if (group) {
                const q = (group.p - 1) / 2;
                note = `g has order ${group.order}. `;
                note += isPrime(q)
                    ? `p = 2·${q} + 1 is a safe prime.`
                    : `p is not a safe prime ((p − 1)/2 = ${q} is not prime), so rejecting 1 and p − 1 does not rule out every small subgroup.`;
            }
            groupNote.textContent = note;
        }

        function party(title, rows, tag) {
            return h('div', { class: `dh-party ${tag}` }, h('p', { class: 'dh-party-title' }, title),
                h('dl', {}, rows.map(([term, value]) => [h('dt', {}, term), h('dd', { class: 'w-mono' }, value)])));
        }

        function message(from, to, name, fields) {
            return h('li', {}, h('span', { class: 'dh-arrow' }, `${from} → ${to}`), ' ',
                h('strong', {}, name), h('ul', {}, fields.map((f) => h('li', { class: 'w-mono' }, f))));
        }

        function wireField(label, value, bytes) {
            return [`${label} = ${value}`, h('span', { class: 'dh-bytes' }, ` [${toHex(bytes)}]`)];
        }

        function render(G, s) {
            const W = WORDS[G.kind];
            const pub = (k) => G.mul(k, G.base);
            const A = pub(s.a);
            const B = pub(s.b);
            const toServer = state.mitm ? pub(s.m1) : A; // what the server receives as e
            const toClient = state.mitm ? pub(s.m2) : B; // what the client receives as f
            const Kc = G.mul(s.a, toClient);
            const Ks = G.mul(s.b, toServer);
            const K1 = G.secret(Kc);
            const K2 = G.secret(Ks);
            const wire = (label, X) => wireField(`${W.type} ${label}`, G.fmt(X), G.pubWire(X));

            const client = party('Client', [
                ['secret a', String(s.a)],
                [`sends ${W.e} = A`, G.pubText(s.a, A)],
                [`receives ${W.f}`, G.fmt(toClient)],
                [W.key, `${G.agreeText(s.a, toClient, Kc)}`],
            ], 'dh-client');
            const server = party('Server', [
                ['secret b', String(s.b)],
                [`sends ${W.f} = B`, G.pubText(s.b, B)],
                [`receives ${W.e}`, G.fmt(toServer)],
                [W.key, `${G.agreeText(s.b, toServer, Ks)}`],
            ], 'dh-server');

            const parties = [client];
            const messages = [];
            const sigKey = state.forge === 'own' ? 'K_M' : 'K_S';
            if (state.mitm) {
                const M1 = toServer;
                const M2 = toClient;
                parties.push(party('Attacker', [
                    ['secrets m1, m2', `${s.m1}, ${s.m2}`],
                    [`sends server ${W.e} = M1`, G.pubText(s.m1, M1)],
                    [`sends client ${W.f} = M2`, G.pubText(s.m2, M2)],
                    ['K1, shared with the client', G.agreeText(s.m2, A, G.mul(s.m2, A))],
                    ['K2, shared with the server', G.agreeText(s.m1, B, G.mul(s.m1, B))],
                ], 'dh-attacker'));
                messages.push(
                    message('Client', 'Attacker', W.init, [wire(W.e, A)]),
                    message('Attacker', 'Server', W.init, [wire(W.e, M1)]),
                    message('Server', 'Attacker', W.reply, ['string K_S (server host key)', wire(W.f, B), 'string signature of H2 by K_S']),
                    message('Attacker', 'Client', W.reply, [
                        `string ${sigKey} (${state.forge === 'own' ? 'attacker’s' : 'server’s'} host key)`,
                        wire(W.f, M2),
                        `string signature of ${state.forge === 'own' ? 'H1 by K_M' : 'H2 by K_S'}`]));
            } else {
                messages.push(
                    message('Client', 'Server', W.init, [wire(W.e, A)]),
                    message('Server', 'Client', W.reply, ['string K_S (server host key)', wire(W.f, B), 'string signature of H by K_S']));
            }
            parties.push(server);

            append(out, [
                h('div', { class: 'dh-parties' }, parties),
                h('p', { class: 'dh-heading' }, 'On the wire'),
                h('ol', { class: 'dh-wire' }, messages),
                checks(G, toServer, toClient, K1, K2)]);

            if (state.mitm) {
                out.append(mitmStatus(G, W, { A, B, M1: toServer, M2: toClient, K1, K2 }));
                live.say(`Client secret ${K1}, server secret ${K2}. The attacker knows both.`);
            } else {
                out.append(
                    h('p', { class: 'w-status w-good' },
                        `Both sides computed K = ${K1}; neither private value nor K crossed the wire.`),
                    eavesdropper(G, W, A, B));
                live.say(`Both sides computed shared secret ${K1}.`);
            }
        }

        // The recipient's validation of each public value (and, for finite
        // fields, the RFC 4419 check 1 < K < p − 1).
        function checks(G, e, f, K1, K2) {
            const problems = [];
            const W = WORDS[G.kind];
            const r1 = G.reject(e, W.e);
            const r2 = G.reject(f, W.f);
            if (r1) problems.push(`The server rejects ${W.e} = ${G.fmt(e)}: ${r1}.`);
            if (r2) problems.push(`The client rejects ${W.f} = ${G.fmt(f)}: ${r2}.`);
            if (G.kind === 'ff') {
                const P = BigInt(G.p);
                const confined = [...new Set([K1, K2].filter((K) => K <= 1n || K >= P - 1n))];
                if (confined.length) {
                    problems.push(`K = ${confined.join(' or ')} lies in the small subgroup {1, ${G.p - 1}}, where an attacker can simply guess it. RFC 4419 accepts K only if 1 < K < p − 1.`);
                }
            }
            if (!problems.length) return null;
            return h('div', { class: 'w-status w-warn' }, problems.map((t) => h('p', {}, t)));
        }

        function eavesdropper(G, W, A, B) {
            const found = G.log(A);
            const K = G.secret(G.mul(found, B));
            return h('div', { class: 'dh-eve' },
                h('p', { class: 'dh-heading' }, 'A passive eavesdropper'),
                h('p', {}, `Sees the group, ${W.e} = ${G.fmt(A)}, and ${W.f} = ${G.fmt(B)}, but neither secret. `,
                    `In a group this small it can try every ${G.kind === 'ff' ? `exponent: ${G.g}^k` : 'scalar: k·G'} first equals ${G.fmt(A)} at k = ${found}, `,
                    `after ${found} tries, which gives K = ${K}.`),
                h('p', { class: 'w-note' }, W.hard));
        }

        function mitmStatus(G, W, v) {
            const diff = [];
            if (!G.eq(v.A, v.M1)) diff.push(`${W.e} (${G.fmt(v.A)} vs ${G.fmt(v.M1)})`);
            if (!G.eq(v.B, v.M2)) diff.push(`${W.f} (${G.fmt(v.M2)} vs ${G.fmt(v.B)})`);
            if (v.K1 !== v.K2) diff.push(`K (${v.K1} vs ${v.K2})`);
            const same = v.K1 === v.K2
                ? `The two secrets happen to be equal (${v.K1}), but the attacker knows it.`
                : `The client holds K1 = ${v.K1}, the server K2 = ${v.K2}, and the attacker knows both, so it can decrypt, read, and re-encrypt everything it relays.`;
            let verdict;
            if (state.forge === 'own') {
                verdict = h('p', { class: 'w-status w-warn' },
                    'The signature would verify: the attacker signed the client’s own exchange hash H1 with K_M. ',
                    'Only the trust decision can catch this, and OpenSSH makes it first. K_M is not the key recorded for this host, so OpenSSH refuses by default ',
                    '(“REMOTE HOST IDENTIFICATION HAS CHANGED”); on a first connection the user is shown K_M’s fingerprint and must not accept it.');
            } else if (diff.length) {
                verdict = h('p', { class: 'w-status w-good' },
                    'The client computes H1 over the transcript it saw; the server signed H2 over its own. ',
                    `They differ in ${diff.join(', ')}, so the server’s signature does not verify and the client aborts.`);
            } else {
                verdict = h('p', { class: 'w-status w-warn' },
                    'With m1 = a and m2 = b the attacker sends exactly what the endpoints sent, so the transcripts match and the signature verifies; a real attacker cannot know a and b.');
            }
            return h('div', { class: 'dh-mitm' },
                h('p', { class: 'w-status w-bad' }, same),
                verdict,
                h('p', { class: 'w-note' },
                    'Key agreement alone cannot tell the client who is on the other end. The host-key signature over the exchange hash H binds the public values and K to the signer, and the host-key trust check decides whether that signer is the server.'));
        }

        // Step through k·G = (k − 1)·G + G on the toy curve. Built once, so the
        // step position survives edits; renderWalk() only moves the A/B/K tags.
        const chips = multiples.slice(1).map((P, i) => h('li', { class: 'dh-chip' },
            h('span', {}, `${i + 1}G`), h('span', { class: 'w-mono' }, fmtPoint(P)),
            h('span', { class: 'dh-tag' })));
        const explain = h('div', { class: 'dh-step w-mono', 'aria-live': 'polite' });
        const walkNote = h('p', { class: 'w-note' });
        const steps = stepper({
            count: EC.n,
            label: 'k =',
            render(index) {
                chips.forEach((c, i) => c.classList.toggle('dh-current', i === index));
                explain.replaceChildren(...stepLines(index + 1).map((t) => h('div', {}, t)));
            },
        });
        walk.append(
            h('p', { class: 'dh-heading' }, 'Repeated point addition: k·G = (k − 1)·G + G'),
            h('ol', { class: 'dh-chips', 'aria-label': 'Multiples of G' }, chips),
            steps.el, explain, walkNote);
        steps.go(0);

        function renderWalk(s) {
            const shared = (s.a * s.b) % EC.n;
            chips.forEach((chip, i) => {
                const k = i + 1;
                const tags = [s.a === k ? 'A' : '', s.b === k ? 'B' : '', shared === k ? 'K' : '']
                    .filter(Boolean).join(' ');
                chip.classList.toggle('dh-marked', Boolean(tags));
                chip.lastChild.textContent = tags;
            });
            walkNote.textContent = `A = ${s.a}G and B = ${s.b}G. Both sides reach K = ${s.a}·${s.b}G = `
                + `${s.a * s.b}G = ${shared}G = ${fmtPoint(multiples[shared])}, because G has order ${EC.n}.`;
        }

        function stepLines(k) {
            if (k === 1) return ['1·G = G = (5, 1)'];
            const P = multiples[k - 1];
            const r = ecAdd(P, EC.G);
            const head = `${k}·G = ${k - 1}G + G = ${fmtPoint(P)} + ${fmtPoint(EC.G)}`;
            if (r.vertical) return [head, 'Same x, opposite y: the line is vertical, so the sum is O.', `G has order ${EC.n}.`];
            const [x1, y1] = P;
            const [x2] = EC.G;
            const [x3, y3] = r.point;
            const n = mod(r.num);
            const d = mod(r.den);
            const formula = r.doubling ? `(3·${x1}² + 2) / (2·${y1})` : `(${EC.G[1]} − ${y1}) / (${x2} − ${x1})`;
            return [
                head + (r.doubling ? '  (doubling)' : ''),
                `λ = ${formula} ≡ ${n} / ${d} ≡ ${n} · ${inv(d)} ≡ ${r.lambda}   (1/${d} ≡ ${inv(d)} mod 17)`,
                `x3 = λ² − x1 − x2 = ${r.lambda}² − ${x1} − ${x2} ≡ ${x3}`,
                `y3 = λ·(x1 − x3) − y1 = ${r.lambda}·(${x1} − ${x3}) − ${y1} ≡ ${y3}`,
                `${k}G = ${fmtPoint(r.point)}`,
            ];
        }

        update();
    }

    SSHWidgets.register('dh', mount);
})();
