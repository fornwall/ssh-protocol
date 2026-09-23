// SSH key-derivation calculator (RFC 4253, section 7.2).
//
// Derives the six values A–F from a toy shared secret K, an exchange hash H,
// and session_id with real SHA-256, shows exactly which bytes go into each
// hash block, and lets the reader simulate a rekey (new K and H, same
// session_id).
(() => {
    'use strict';

    const { h, field, liveRegion, toHex, fromHex, concat, sshString, mpint, sha256 } = SSHWidgets;

    const LETTERS = [
        { x: 'A', kind: 'iv', what: 'Initial IV', dir: 'client → server', use: 'client sends' },
        { x: 'B', kind: 'iv', what: 'Initial IV', dir: 'server → client', use: 'client receives' },
        { x: 'C', kind: 'enc', what: 'Encryption key', dir: 'client → server', use: 'client sends' },
        { x: 'D', kind: 'enc', what: 'Encryption key', dir: 'server → client', use: 'client receives' },
        { x: 'E', kind: 'mac', what: 'Integrity key', dir: 'client → server', use: 'client sends' },
        { x: 'F', kind: 'mac', what: 'Integrity key', dir: 'server → client', use: 'client receives' },
    ];

    // Bytes taken per letter kind, as in the chapter's table; 0 = unused.
    const PRESETS = [
        { name: 'chacha20-poly1305@openssh.com', iv: 0, enc: 64, mac: 0 },
        { name: 'aes128-gcm@openssh.com', iv: 12, enc: 16, mac: 0 },
        { name: 'aes256-gcm@openssh.com', iv: 12, enc: 32, mac: 0 },
        { name: 'aes128-ctr + hmac-sha2-256-etm@openssh.com', iv: 16, enc: 16, mac: 32 },
        { name: 'aes256-ctr + hmac-sha2-512-etm@openssh.com', iv: 16, enc: 32, mac: 64 },
        { name: 'Custom: the same length for every letter', custom: true },
    ];

    // Colors for the hash inputs, shared by the legend and the byte cells.
    const TAGS = { K: 'w-tag-4', H: 'w-tag-1', X: 'w-tag-3', session_id: 'w-tag-2', prev: 'w-tag-5' };

    function bytesToBigInt(bytes) {
        let value = 0n;
        for (const b of bytes) value = (value << 8n) | BigInt(b);
        return value;
    }

    // K as it enters the hash: an mpint for DH/ECDH, a string for the hybrids.
    function encodeK(bytes, encoding) {
        return encoding === 'string' ? sshString(bytes) : mpint(bytesToBigInt(bytes));
    }

    // RFC 4253, section 7.2. Returns every hash block with its labelled inputs.
    async function derive(kEncoded, H, letter, sessionId, need) {
        const blocks = [];
        let produced = new Uint8Array(0);
        do {
            const parts = [['K', kEncoded], ['H', H]];
            if (blocks.length === 0) {
                parts.push(['X', Uint8Array.of(letter.charCodeAt(0))], ['session_id', sessionId]);
            } else {
                blocks.forEach((block, i) => parts.push([`K${i + 1}`, block.output]));
            }
            const output = await sha256(concat(...parts.map(([, bytes]) => bytes)));
            blocks.push({ parts, output });
            produced = concat(produced, output);
        } while (produced.length < need);
        return { blocks, key: produced.slice(0, Math.max(need, 0)) };
    }

    function parseHex(text, name) {
        try {
            return fromHex(text);
        } catch (error) {
            throw new Error(`${name}: ${error.message}`);
        }
    }

    SSHWidgets.register('kdf', (root, config) => {
        const state = {
            mode: 'initial',
            values: {
                initial: { k: config.k || '05', h: config.h || '11'.repeat(32) },
                rekey: { k: config.rekeyK || 'b7', h: config.rekeyH || '22'.repeat(32) },
            },
            letter: 'C',
        };
        let generation = 0;

        const initialBtn = h('button', { type: 'button', onclick: () => setMode('initial') }, 'Initial key exchange');
        const rekeyBtn = h('button', { type: 'button', onclick: () => setMode('rekey') }, 'After a rekey');
        const kInput = h('input', { type: 'text', class: 'w-mono', spellcheck: false, autocomplete: 'off' });
        const hInput = h('textarea', { rows: 2, class: 'w-mono', spellcheck: false });
        const kHint = h('span', { class: 'w-mono' });
        const kOther = h('span', {});
        const encoding = h('select', {},
            h('option', { value: 'mpint' }, 'mpint: DH, ECDH, curve25519-sha256'),
            h('option', { value: 'string' }, 'string: hybrids such as mlkem768x25519-sha256'));
        const preset = h('select', {}, PRESETS.map((p, i) => h('option', { value: String(i) }, p.name)));
        const custom = h('input', { type: 'number', min: 1, max: 128, value: 32, disabled: true });
        const sessionOut = h('div', { class: 'w-mono w-kdf-hex' });
        const sessionNote = h('div', { class: 'w-hint' });
        const status = h('div', { class: 'w-status', role: 'status' });
        const rows = h('div', { class: 'w-kdf-rows' });
        const detail = h('div', { class: 'w-kdf-detail' });
        const live = liveRegion();

        const legend = h('div', { class: 'w-kdf-legend w-note' }, 'Hash input colors: ',
            ['K', 'H', 'X', 'session_id'].map((name) => h('span', { class: TAGS[name] }, name)),
            h('span', { class: TAGS.prev }, 'earlier blocks K1, K2, …'));

        root.append(
            h('p', { class: 'w-title' }, 'SSH key derivation with HASH = SHA-256'),
            h('div', { class: 'w-controls', role: 'group', 'aria-label': 'Which key exchange' }, initialBtn, rekeyBtn),
            h('div', { class: 'w-cols' },
                h('div', {},
                    field('Shared secret K (hex, big-endian)', kInput, h('span', {}, 'Encoded for the hash: ', kHint, h('br'), kOther)),
                    field('Encoding of K', encoding,
                        'In the hybrids, K is itself a hash output, 32 bytes for SHA-256.')),
                h('div', {},
                    field('Exchange hash H (hex)', hInput),
                    h('div', { class: 'w-field' },
                        h('span', { class: 'w-kdf-label' }, 'session_id'),
                        sessionOut, sessionNote))),
            h('div', { class: 'w-cols' },
                field('Packet protection (sets the bytes needed per letter)', preset),
                field('Custom length in bytes', custom)),
            status, rows, legend, detail, live);

        kInput.addEventListener('input', () => { state.values[state.mode].k = kInput.value; update(); });
        hInput.addEventListener('input', () => { state.values[state.mode].h = hInput.value; update(); });
        encoding.addEventListener('change', update);
        custom.addEventListener('input', update);
        preset.addEventListener('change', () => {
            custom.disabled = !PRESETS[preset.value].custom;
            update();
        });

        function setMode(mode, quiet) {
            state.mode = mode;
            kInput.value = state.values[mode].k;
            hInput.value = state.values[mode].h;
            update();
            if (!quiet) live.say(mode === 'rekey'
                ? 'After a rekey: new K and H, session_id unchanged.'
                : 'Initial key exchange: session_id equals H.');
        }

        function needFor(letter) {
            const p = PRESETS[preset.value];
            if (p.custom) {
                const n = Math.round(Number(custom.value));
                if (!(n >= 1 && n <= 128)) throw new Error('Custom length must be between 1 and 128 bytes.');
                return n;
            }
            return p[letter.kind];
        }

        async function computeAll(values, sessionId, need) {
            const k = parseHex(values.k, 'K');
            if (k.length === 0) throw new Error('K: enter at least one byte.');
            const H = parseHex(values.h, 'H');
            const kEncoded = encodeK(k, encoding.value);
            const results = await Promise.all(LETTERS.map((l) => derive(kEncoded, H, l.x, sessionId, need(l))));
            const other = encodeK(k, encoding.value === 'mpint' ? 'string' : 'mpint');
            return { kEncoded, other, H, results };
        }

        async function update() {
            const mine = ++generation;
            initialBtn.setAttribute('aria-pressed', String(state.mode === 'initial'));
            rekeyBtn.setAttribute('aria-pressed', String(state.mode === 'rekey'));
            let initial;
            let current;
            let sessionId;
            try {
                sessionId = parseHex(state.values.initial.h, 'H of the initial exchange');
                initial = await computeAll(state.values.initial, sessionId, needFor);
                current = state.mode === 'rekey'
                    ? await computeAll(state.values.rekey, sessionId, needFor)
                    : initial;
            } catch (error) {
                if (mine !== generation) return;
                status.className = 'w-status w-bad';
                status.textContent = error.message;
                rows.replaceChildren();
                detail.replaceChildren();
                return;
            }
            if (mine !== generation) return;

            kHint.textContent = toHex(current.kEncoded);
            const otherName = encoding.value === 'mpint' ? 'string' : 'mpint';
            if (toHex(current.other) === toHex(current.kEncoded)) {
                kOther.replaceChildren(`As a ${otherName}, this K happens to encode the same way.`);
            } else {
                kOther.replaceChildren(`As a ${otherName}: `, h('span', { class: 'w-mono' }, toHex(current.other)));
            }
            sessionOut.textContent = toHex(sessionId, '');
            sessionNote.textContent = state.mode === 'rekey'
                ? 'Still the initial exchange’s H: a rekey does not change it.'
                : 'Equals H, because this is the first key exchange.';

            const messages = [];
            let bad = false;
            if (current.H.length !== 32) {
                messages.push(`H is ${current.H.length} bytes; a SHA-256 method’s H is 32 bytes.`);
                bad = true;
            }
            if (state.mode === 'rekey') {
                const changed = current.results.filter((r, i) =>
                    toHex(r.key) !== toHex(initial.results[i].key)
                    || toHex(r.blocks[0].output) !== toHex(initial.results[i].blocks[0].output)).length;
                messages.push(`${changed} of 6 derived values changed; session_id did not.`);
                if (changed < 6) bad = true;
            } else {
                messages.push('First key exchange: session_id = H.');
            }
            status.className = `w-status ${bad ? 'w-warn' : 'w-good'}`;
            status.textContent = messages.join(' ');

            // Re-rendering replaces the letter buttons; keep keyboard focus on the selected one.
            const hadFocus = rows.contains(document.activeElement);
            rows.replaceChildren(...LETTERS.map((letter, i) =>
                renderRow(letter, current.results[i], state.mode === 'rekey' ? initial.results[i] : null)));
            if (hadFocus) rows.querySelector('.w-kdf-selected button').focus();
            const index = LETTERS.findIndex((l) => l.x === state.letter);
            renderDetail(LETTERS[index], current.results[index], needFor(LETTERS[index]));
        }

        function blockHex(result, need) {
            // The value split at hash-block boundaries; unused letters show K1.
            const shown = need > 0 ? need : result.blocks[0].output.length;
            const out = [];
            result.blocks.forEach((block, i) => {
                const take = Math.min(block.output.length, shown - i * 32);
                if (take <= 0) return;
                if (i > 0) out.push(h('span', { class: 'w-kdf-sep', 'aria-hidden': 'true' }, ' ‖ '));
                out.push(toHex(block.output.slice(0, take), ''));
            });
            return out;
        }

        function renderRow(letter, result, before) {
            const need = needFor(letter);
            const selected = state.letter === letter.x;
            const button = h('button', {
                type: 'button',
                class: 'w-kdf-letter w-mono',
                'aria-pressed': String(selected),
                'aria-label': `Show the bytes hashed for ${letter.x}`,
                onclick: () => {
                    state.letter = letter.x;
                    update();
                    live.say(`Showing the hash inputs for letter ${letter.x}.`);
                },
            }, letter.x);
            const size = need > 0
                ? `${need} bytes${need > 32 ? `, ${Math.ceil(need / 32)} blocks` : ''}`
                : 'unused by this algorithm; K1 shown';
            return h('div', { class: `w-kdf-row${need > 0 ? '' : ' w-kdf-unused'}${selected ? ' w-kdf-selected' : ''}` },
                button,
                h('div', { class: 'w-kdf-body' },
                    h('div', {}, h('strong', {}, `${letter.what}, ${letter.dir}`),
                        h('span', { class: 'w-note' }, ` (${letter.use}) · ${size}`)),
                    h('div', { class: 'w-mono w-kdf-hex' }, blockHex(result, need)),
                    before ? h('div', { class: 'w-note w-mono w-kdf-hex' },
                        'before rekey: ', blockHex(before, need)) : null));
        }

        function renderDetail(letter, result, need) {
            const items = [h('p', { class: 'w-title' },
                `Bytes hashed for letter ${letter.x} (${letter.what.toLowerCase()}, ${letter.dir})`)];
            result.blocks.forEach((block, i) => {
                const cells = [];
                const summary = [];
                for (const [name, bytes] of block.parts) {
                    const tag = TAGS[name] || TAGS.prev;
                    summary.push(`${name} (${bytes.length} byte${bytes.length === 1 ? '' : 's'})`);
                    bytes.forEach((b, j) => cells.push(h('span', {
                        class: `w-byte ${tag}${j === 0 ? ' w-kdf-start' : ''}`,
                        title: `${name}, byte ${j + 1} of ${bytes.length}`,
                    }, name === 'X' ? `${b.toString(16)} '${letter.x}'` : b.toString(16).padStart(2, '0'))));
                }
                const formula = i === 0
                    ? 'K1 = HASH(K ‖ H ‖ X ‖ session_id)'
                    : `K${i + 1} = HASH(K ‖ H ‖ ${block.parts.slice(2).map(([n]) => n).join(' ‖ ')})`;
                items.push(
                    h('p', { class: 'w-mono w-kdf-formula' }, formula),
                    h('div', { class: 'w-bytes', role: 'img', 'aria-label': `${summary.join(', ')}; ${block.parts.reduce((n, [, b]) => n + b.length, 0)} bytes in total` }, cells),
                    h('p', { class: 'w-mono w-kdf-hex' }, `K${i + 1} = `, h('span', { class: TAGS.prev }, toHex(block.output, ''))));
            });
            let result_;
            if (need <= 0) {
                result_ = `The selected algorithm does not use ${letter.x}. The derivation still defines it, and OpenSSH derives all six values at one common length.`;
            } else if (result.blocks.length === 1) {
                result_ = need === 32
                    ? `${letter.x} = K1: one 32-byte block is exactly enough.`
                    : `${letter.x} = the first ${need} bytes of K1; the other ${32 - need} bytes are discarded.`;
            } else {
                const chain = result.blocks.map((_, i) => `K${i + 1}`).join(' ‖ ');
                result_ = `${need} bytes exceed one 32-byte SHA-256 output, so ${letter.x} = the first ${need} bytes of ${chain}. Only K1 contains the letter and session_id.`;
            }
            items.push(h('p', { class: 'w-note' }, result_));
            detail.replaceChildren(...items);
        }

        setMode('initial', true);
    });
})();
