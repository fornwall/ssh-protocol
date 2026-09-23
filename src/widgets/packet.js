// Packet dissector: the binary-packets chapter's worked packet as a
// color-coded hex dump, under each packet-protection family.
//
// Padding follows RFC 4253 section 6 and OpenSSH's sender (packet.c): at
// least four bytes, the smallest amount that aligns to max(8, block size).
// Encrypt-and-MAC and unencrypted packets align 4 + packet_length; in
// encrypt-then-MAC and AEAD modes the 4-byte length is left out. Padding and
// MAC bytes are placeholders, not real randomness or cryptography.
(() => {
    'use strict';

    const { h, utf8, u32, toHex, field } = SSHWidgets;

    const PAD_PATTERN = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    const MESSAGES = {
        service: { num: 5, symbol: 'SSH_MSG_SERVICE_REQUEST', text: 'x', textLabel: 'service name' },
        ignore: { num: 2, symbol: 'SSH_MSG_IGNORE', text: 'hi', textLabel: 'data' },
        newkeys: { num: 21, symbol: 'SSH_MSG_NEWKEYS', text: null },
        data: { num: 94, symbol: 'SSH_MSG_CHANNEL_DATA', text: 'hello', textLabel: 'data', channel: true },
    };

    // block: fixed cipher block size, or null when the reader picks one.
    // lengthAligned: whether the 4-byte length is part of the aligned region.
    const MODES = {
        none: {
            label: 'Before keys (initial key exchange)',
            block: 8, blockNote: 'no cipher yet', lengthAligned: true, macLen: 0,
            enc: { len: false, body: false }, auth: false,
            length: 'Reads the first 4 bytes directly.',
            integrity: 'None yet. Until this direction’s first NEWKEYS, packets carry padding but no encryption or MAC.',
            seq: 'Counted from the first binary packet, but no MAC uses it yet. Never sent.',
            lengthField: 'Sent in cleartext.',
            alignSource: 'RFC 4253, section 6',
        },
        eam: {
            label: 'Encrypt-and-MAC (hmac-sha2-256)',
            block: null, lengthAligned: true, macLen: 32, macName: 'MAC',
            enc: { len: true, body: true }, auth: true,
            length: 'Decrypts the first cipher block to read packet_length, before the MAC can be checked.',
            integrity: 'MAC(key, uint32 sequence_number ‖ unencrypted packet): the plaintext from packet_length through padding. The MAC itself is sent unencrypted.',
            seq: 'A MAC input, never sent.',
            lengthField: 'Encrypted with the rest of the packet, so the receiver must decrypt the first block to learn it, before it can verify anything.',
            alignSource: 'RFC 4253, section 6',
        },
        etm: {
            label: 'Encrypt-then-MAC (hmac-sha2-256-etm@openssh.com)',
            block: null, lengthAligned: false, macLen: 32, macName: 'MAC',
            enc: { len: false, body: true }, auth: true,
            length: 'Reads packet_length in the clear, then verifies the MAC before decrypting anything.',
            integrity: 'MAC(key, uint32 sequence_number ‖ packet_length ‖ encrypted packet), computed over the ciphertext.',
            seq: 'A MAC input, never sent.',
            lengthField: 'Sent in cleartext and covered by the MAC, so the receiver can locate the MAC without decrypting.',
            alignSource: 'OpenSSH PROTOCOL section 1.5 and packet.c',
        },
        gcm: {
            label: 'AEAD: aes128-gcm@openssh.com',
            block: 16, blockNote: 'AES', lengthAligned: false, macLen: 16, macName: 'tag',
            enc: { len: false, body: true }, auth: true,
            length: 'Reads packet_length in the clear, then verifies the tag before releasing any plaintext.',
            integrity: '16-byte GCM tag over the associated data (packet_length) and the ciphertext. Nonce: a 4-byte fixed field and an 8-byte invocation counter, both from the KDF IV; the counter increases by one per packet.',
            seq: 'Not a direct input. The nonce’s invocation counter, which advances once per packet, plays its role (RFC 5647, section 8.1). Never sent.',
            lengthField: 'Sent in cleartext as associated data: authenticated by the tag, not encrypted.',
            alignSource: 'RFC 5647, section 7.2',
        },
        chacha: {
            label: 'AEAD: chacha20-poly1305@openssh.com',
            block: 8, blockNote: 'OpenSSH value', lengthAligned: false, macLen: 16, macName: 'tag',
            enc: { len: true, body: true }, auth: true,
            length: 'Decrypts only the 4 length bytes with K_2, then verifies the tag before decrypting the body.',
            integrity: '16-byte Poly1305 tag over encrypted length ‖ ciphertext. Its one-time key is the start of ChaCha20(K_1) with the sequence number as nonce.',
            seq: 'The ChaCha20 nonce for both K_1 and K_2. Never sent.',
            lengthField: 'Encrypted separately under K_2, with the sequence number as nonce; the tag covers the encrypted length.',
            alignSource: 'OpenSSH packet.c; the draft’s test vector agrees',
        },
    };

    const TAGS = { len: 1, padlen: 1, msg: 5, payload: 2, padding: 3, mac: 4, seq: 6 };

    const LEGEND = [
        ['len', 'packet_length'],
        ['padlen', 'padding_length'],
        ['msg', 'message number'],
        ['payload', 'message fields'],
        ['padding', 'random padding'],
        ['mac', 'MAC or tag'],
    ];

    function range(n, fn) {
        return Array.from({ length: n }, (_, i) => fn(i));
    }

    // The payload's fields: the message number, then that message's fields.
    function payloadFields(message, text) {
        const msg = MESSAGES[message];
        const fields = [{
            group: 'msg', caption: 'msg', bytes: [msg.num],
            desc: `byte ${msg.num}: the message number, ${msg.symbol}. The first payload byte selects how the rest is parsed.`,
        }];
        if (msg.channel) {
            fields.push({
                group: 'payload', caption: 'channel', bytes: [...u32(0)],
                desc: 'uint32 0: the recipient channel number.',
            });
        }
        if (msg.text !== null) {
            const data = [...utf8(text)];
            fields.push({
                group: 'payload', caption: 'string length', bytes: [...u32(data.length)],
                desc: `uint32 ${data.length}: the byte length of the ${msg.textLabel} string that follows.`,
            });
            if (data.length) {
                fields.push({
                    group: 'payload', caption: msg.textLabel, bytes: data,
                    desc: `${data.length} bytes of ${msg.textLabel}: ${JSON.stringify(text)}.`,
                });
            }
        }
        return fields;
    }

    // Build the packet's fields and the numbers behind them.
    function layout({ mode, blockSize, message, text, extraBlocks }) {
        const m = MODES[mode];
        const cipherBlock = m.block || blockSize;
        const block = Math.max(8, cipherBlock);
        const payload = payloadFields(message, text);
        const payloadLen = payload.reduce((n, f) => n + f.bytes.length, 0);
        const unpadded = (m.lengthAligned ? 4 : 0) + 1 + payloadLen;
        const minPad = block - (unpadded % block) < 4
            ? 2 * block - (unpadded % block)
            : block - (unpadded % block);
        const extra = Math.max(0, Math.min(extraBlocks, Math.floor((255 - minPad) / block)));
        const pad = minPad + extra * block;
        const packetLength = 1 + payloadLen + pad;
        const aligned = (m.lengthAligned ? 4 : 0) + packetLength;
        const fields = [
            { group: 'len', caption: 'packet_length', bytes: [...u32(packetLength)] },
            { group: 'padlen', caption: 'padding_length', bytes: [pad] },
            ...payload,
            { group: 'padding', caption: 'padding', bytes: range(pad, (i) => PAD_PATTERN[i % PAD_PATTERN.length]) },
        ];
        if (m.macLen) fields.push({ group: 'mac', caption: `${m.macName} (${m.macLen})`, bytes: range(m.macLen, () => null) });
        return { m, cipherBlock, block, payloadLen, minPad, extra, pad, packetLength, aligned, fields };
    }

    function mount(root, config) {
        const state = {
            mode: MODES[config.mode] ? config.mode : 'none',
            blockSize: 16,
            message: 'service',
            text: 'x',
            extraBlocks: 0,
            seq: 3,
        };

        const modeSelect = h('select', {
            onchange: () => { state.mode = modeSelect.value; render(); },
        }, Object.entries(MODES).map(([key, m]) => h('option', { value: key }, m.label)));
        const blockSelect = h('select', {
            onchange: () => { state.blockSize = Number(blockSelect.value); render(); },
        },
        h('option', { value: '8' }, '8 bytes (e.g. 3des-cbc)'),
        h('option', { value: '16' }, '16 bytes (AES, e.g. aes128-ctr)'),
        h('option', { value: 'fixed', hidden: true }));
        const messageSelect = h('select', {
            onchange: () => {
                state.message = messageSelect.value;
                state.text = MESSAGES[state.message].text || '';
                textInput.value = state.text;
                render();
            },
        }, Object.entries(MESSAGES).map(([key, msg]) => h('option', { value: key }, `${msg.symbol.replace('SSH_MSG_', '')} (${msg.num})`)));
        const textInput = h('input', {
            type: 'text', value: state.text, maxlength: '120', spellcheck: 'false', class: 'w-mono',
            oninput: () => { state.text = textInput.value; render(); },
        });
        const extraInput = h('input', {
            type: 'number', min: '0', max: '30', value: '0',
            oninput: () => { state.extraBlocks = Math.max(0, Number(extraInput.value) || 0); render(); },
        });
        const seqInput = h('input', {
            type: 'number', min: '0', max: '4294967295', value: String(state.seq),
            oninput: () => {
                const n = Math.floor(Number(seqInput.value));
                state.seq = Number.isFinite(n) ? Math.max(0, Math.min(2 ** 32 - 1, n)) : 0;
                render();
            },
        });
        modeSelect.value = state.mode;
        blockSelect.value = String(state.blockSize);
        const textField = field('String field', textInput);

        const seqRow = h('div', { class: 'pk-seq' });
        const dump = h('div', { class: 'pk-dump', role: 'group', 'aria-label': 'Packet bytes by field' });
        const legend = h('div', { class: 'pk-legend' });
        const explain = h('div', { class: 'w-status pk-explain', 'aria-live': 'polite' });
        const facts = h('dl', { class: 'pk-facts' });

        root.append(
            h('p', { class: 'w-title' }, 'Packet dissector'),
            h('div', { class: 'w-cols pk-inputs' },
                h('div', { class: 'pk-wide' }, field('Packet protection', modeSelect)),
                field('Cipher block size', blockSelect),
                field('Message', messageSelect),
                textField,
                field('Extra padding blocks', extraInput, 'Padding may be up to 255 bytes. OpenSSH sends the minimum, but pads password packets to a multiple of 64.'),
                field('Sequence number', seqInput, 'Per direction; both peers count it.')),
            seqRow,
            dump,
            legend,
            explain,
            facts,
            h('p', { class: 'w-note' },
                'Bytes are shown before encryption. Padding is drawn as aa bb cc … and MAC or tag bytes as ··; real padding is random and real tags are computed from keys.'));

        let current = null; // result of layout()
        let pinned = null;  // { kind: 'field' | 'group', value }

        function protection(group) {
            const m = current.m;
            if (group === 'mac') return { enc: false, auth: false };
            const enc = group === 'len' ? m.enc.len : m.enc.body;
            return { enc, auth: m.auth };
        }

        function protectionText(group) {
            if (group === 'mac') {
                return current.m.macName === 'tag'
                    ? 'Sent in the clear after the ciphertext.'
                    : 'Sent in the clear after the packet.';
            }
            const p = protection(group);
            if (!p.enc && !p.auth) return 'On the wire: cleartext, unauthenticated.';
            return `On the wire: ${p.enc ? 'encrypted' : 'cleartext'}, authenticated by the ${current.m.macName}.`;
        }

        function describe(f) {
            const { m, packetLength, payloadLen, pad } = current;
            switch (f.group) {
            case 'len':
                return `uint32 ${packetLength}: counts padding_length (1) + payload (${payloadLen}) + padding (${pad}) = ${packetLength} bytes, outlined. It does not count its own 4 bytes${m.macLen ? ` or the ${m.macName}` : ''}. ${m.lengthField}`;
            case 'padlen':
                return `byte ${pad}: the number of random padding bytes, at least 4 and at most 255. ${protectionText('padlen')}`;
            case 'padding':
                return `${pad} bytes of random padding. ${alignmentText()}. The outlined bytes are the aligned region. ${protectionText('padding')}`;
            case 'mac':
                return `${m.macLen}-byte ${m.macName}. Not counted by packet_length. ${m.integrity} ${protectionText('mac')}`;
            default:
                return `${f.desc} ${protectionText(f.group)}`;
            }
        }

        function alignmentText() {
            const { m, block, aligned, packetLength } = current;
            const what = m.lengthAligned ? `4 + packet_length = ${aligned}` : `packet_length = ${packetLength}`;
            return `${what} = ${aligned / block} × ${block}`;
        }

        function show(target) {
            const fieldEls = [...dump.querySelectorAll('.pk-field')];
            fieldEls.forEach((el) => el.classList.remove('is-active', 'is-outlined'));
            legend.querySelectorAll('button').forEach((b) => b.classList.remove('is-active'));
            dump.classList.toggle('pk-focus', Boolean(target));
            if (!target) {
                explain.textContent = 'Hover over, focus, or tap a field to see what it holds.';
                return;
            }
            let text;
            if (target.kind === 'field') {
                const f = current.fields[target.value];
                fieldEls[target.value].classList.add('is-active');
                text = [h('strong', {}, `${f.caption}: `), describe(f)];
                if (f.group === 'len') outline((g) => g !== 'len' && g !== 'mac');
                if (f.group === 'padding') outline((g) => g !== 'mac' && (g !== 'len' || current.m.lengthAligned));
            } else {
                current.fields.forEach((f, i) => {
                    if (f.group === target.value) fieldEls[i].classList.add('is-active');
                });
                legend.querySelector(`[data-group="${target.value}"]`).classList.add('is-active');
                const label = LEGEND.find(([g]) => g === target.value)[1];
                const first = current.fields.find((f) => f.group === target.value);
                text = first
                    ? [h('strong', {}, `${label}: `), target.value === 'payload' ? `the fields of this message after its number. ${protectionText('payload')}` : describe(first)]
                    : [h('strong', {}, `${label}: `), 'not present in this packet.'];
            }
            explain.replaceChildren(...text);

            function outline(test) {
                current.fields.forEach((f, i) => {
                    if (test(f.group)) fieldEls[i].classList.add('is-outlined');
                });
            }
        }

        function hover(target) {
            return {
                onmouseenter: () => show(target),
                onmouseleave: () => show(pinned),
                onfocus: () => show(target),
                onblur: () => show(pinned),
                onclick: () => { pinned = target; show(pinned); },
            };
        }

        function renderSeq() {
            const { m } = current;
            const bytes = [...u32(state.seq)];
            const shown = state.mode === 'chacha' ? [0, 0, 0, 0, ...bytes] : bytes;
            seqRow.replaceChildren(
                h('span', { class: 'pk-seq-label' }, 'Not sent:'),
                h('span', { class: `pk-seq-bytes w-bytes${state.mode === 'gcm' ? ' pk-unused' : ''}` },
                    shown.map((b) => h('span', { class: 'w-byte w-tag-6' }, toHex([b])))),
                h('span', { class: 'pk-seq-text' },
                    h('strong', {}, `Sequence number ${state.seq} (uint${state.mode === 'chacha' ? 64 : 32}). `),
                    m.seq));
        }

        // Field buttons in wire order; the payload's fields share a bracket.
        function renderDump() {
            const buttons = current.fields.map((f, i) => {
                const p = protection(f.group);
                const hex = f.bytes.map((b) => (b === null ? '··' : toHex([b])));
                return h('button', {
                    type: 'button',
                    class: `pk-field${p.enc ? ' is-enc' : ''}${p.auth ? ' is-auth' : ''}`,
                    'aria-label': `${f.caption}, ${f.bytes.length} byte${f.bytes.length === 1 ? '' : 's'}${f.group === 'mac' ? ' (placeholder)' : `: ${hex.join(' ')}`}`,
                    ...hover({ kind: 'field', value: i }),
                },
                h('span', { class: 'w-bytes', 'aria-hidden': 'true' },
                    hex.map((text) => h('span', { class: `w-byte w-tag-${TAGS[f.group]}` }, text))),
                h('span', { class: 'pk-cap', 'aria-hidden': 'true' }, f.caption));
            });
            const inPayload = current.fields.map((f) => f.group === 'msg' || f.group === 'payload');
            const first = inPayload.indexOf(true);
            const count = inPayload.filter(Boolean).length;
            dump.replaceChildren(
                ...buttons.slice(0, first),
                h('div', { class: 'pk-payload' },
                    h('div', { class: 'pk-payload-fields' }, buttons.slice(first, first + count)),
                    h('div', { class: 'pk-bracket' }, `payload (${current.payloadLen} byte${current.payloadLen === 1 ? '' : 's'})`)),
                ...buttons.slice(first + count));
        }

        function renderLegend() {
            const present = new Set(current.fields.map((f) => f.group));
            legend.replaceChildren(
                ...LEGEND.filter(([g]) => present.has(g)).map(([g, label]) => h('button', {
                    type: 'button', class: 'pk-key', dataset: { group: g },
                    ...hover({ kind: 'group', value: g }),
                }, h('span', { class: `pk-swatch w-tag-${TAGS[g]}` }), label)),
                h('span', { class: 'pk-key pk-static' }, h('span', { class: 'pk-swatch pk-enc-swatch' }), 'encrypted'),
                h('span', { class: 'pk-key pk-static' }, h('span', { class: 'pk-swatch pk-auth-swatch' }), 'authenticated'));
        }

        function renderFacts() {
            const { m, block, cipherBlock, payloadLen, pad, minPad, extra, packetLength, aligned } = current;
            const rows = [
                ['packet_length', `1 + ${payloadLen} + ${pad} = ${packetLength}`],
                ['Alignment', `${alignmentText()}, a multiple of max(8, block size ${cipherBlock}) = ${block}${m.lengthAligned ? '' : '; the 4-byte length is outside the aligned region'} (${m.alignSource})`],
                ['Padding', `the smallest amount ≥ 4 that aligns is ${minPad}${extra ? `; plus ${extra} extra block${extra === 1 ? '' : 's'} = ${pad}` : ''}`],
                ['On the wire', `4 + ${packetLength}${m.macLen ? ` + ${m.macLen} (${m.macName})` : ''} = ${4 + packetLength + m.macLen} bytes`],
                ['Receiver finds the length', m.length],
                ['Integrity', m.integrity],
            ];
            facts.replaceChildren(...rows.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));
        }

        function render() {
            const mode = MODES[state.mode];
            blockSelect.disabled = Boolean(mode.block);
            blockSelect.lastChild.textContent = `${mode.block} bytes (${mode.blockNote})`;
            blockSelect.value = mode.block ? 'fixed' : String(state.blockSize);
            const msg = MESSAGES[state.message];
            textInput.disabled = msg.text === null;
            textField.querySelector('label').textContent = msg.text === null ? 'String field (none in this message)' : `String field: ${msg.textLabel}`;
            current = layout({ ...state });
            extraInput.max = String(current.extra + Math.floor((255 - current.pad) / current.block));
            if (pinned && pinned.kind === 'field' && pinned.value >= current.fields.length) pinned = null;
            renderSeq();
            renderDump();
            renderLegend();
            renderFacts();
            show(pinned);
        }

        render();
    }

    SSHWidgets.register('packet', mount);
})();
