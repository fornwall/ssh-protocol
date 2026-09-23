// Channel flow control: two channels multiplexed over one transport.
//
// The guided mode follows the chapter's "Lab: simulate two channels"; free
// play lets the reader send messages and enforces RFC 4254, Section 5.
(() => {
    'use strict';

    const { h, stepper, liveRegion } = SSHWidgets;

    const PEER = { client: 'server', server: 'client' };
    const NAME = { client: 'Client', server: 'Server' };

    // `limits[side]` is what that side advertises about its own receiving:
    // the client in CHANNEL_OPEN, the server in CHANNEL_OPEN_CONFIRMATION.
    // Channel A reproduces the chapter's numbers: client 7, server 42, and a
    // server window of 10 bytes.
    const CHANNELS = [
        {
            name: 'A', tag: 'w-tag-1', id: { client: 7, server: 42 },
            limits: { client: { window: 12, max: 8 }, server: { window: 10, max: 6 } },
        },
        {
            name: 'B', tag: 'w-tag-5', id: { client: 8, server: 51 },
            limits: { client: { window: 12, max: 8 }, server: { window: 12, max: 6 } },
        },
    ];

    function newState() {
        const channels = {};
        for (const conf of CHANNELS) {
            channels[conf.name] = {
                conf,
                opened: { client: false, server: false },
                eof: { client: false, server: false },
                close: { client: false, server: false },
                // Keyed by the sending side: the credit its peer granted and
                // the bytes the peer has received but not yet consumed.
                out: { client: null, server: null },
            };
        }
        return { channels, log: [] };
    }

    // Apply one action. Returns { ok, text }; a refused action changes nothing.
    function apply(state, { kind, ch: name, side, n }) {
        const ch = state.channels[name];
        const { id } = ch.conf;
        const peer = PEER[side];
        const who = NAME[side];
        const fail = (text) => ({ ok: false, text });
        const send = (type, fields) => {
            state.log.push({ from: side, ch: name, type, fields });
            return { ok: true };
        };
        const grant = (to, limits) => {
            ch.out[to] = { window: limits.window, initial: limits.window, max: limits.max, unread: 0 };
        };

        if (kind === 'open') {
            ch.opened.client = true;
            grant('server', ch.conf.limits.client);
            const l = ch.conf.limits.client;
            return send('CHANNEL_OPEN', [['type', '"session"'], ['sender channel', id.client, 'sender'],
                ['initial window', l.window], ['maximum packet', l.max]]);
        }
        if (kind === 'confirm') {
            ch.opened.server = true;
            grant('client', ch.conf.limits.server);
            const l = ch.conf.limits.server;
            return send('CHANNEL_OPEN_CONFIRMATION', [['recipient channel', id.client, 'recipient'],
                ['sender channel', id.server, 'sender'], ['initial window', l.window], ['maximum packet', l.max]]);
        }

        if (!ch.opened.client || !ch.opened.server) return fail(`Channel ${name} is not open yet.`);
        if (ch.close[side]) {
            return fail(`${who} has already sent CLOSE on channel ${name}, so it sends nothing more on it.`);
        }
        if (ch.close[peer] && kind !== 'close') {
            return fail(`${who} has received CLOSE on channel ${name} and must send CLOSE back; `
                + 'this simulator allows only that.');
        }
        const recipient = ['recipient channel', id[peer], 'recipient'];

        if (kind === 'data') {
            const out = ch.out[side];
            if (ch.eof[side]) {
                return fail(`${who} sent EOF on channel ${name}, so it may send no more data in that direction.`);
            }
            if (!Number.isInteger(n) || n < 1) return fail('Enter a whole number of bytes, at least 1.');
            if (out.window === 0) {
                return fail(`${who}'s window on channel ${name} is 0: it must wait for the `
                    + `${PEER[side]} to send CHANNEL_WINDOW_ADJUST.`);
            }
            const allowed = Math.min(out.window, out.max);
            if (n > allowed) {
                return fail(`${who} may send at most min(window ${out.window}, maximum packet ${out.max}) `
                    + `= ${allowed} bytes in one CHANNEL_DATA on channel ${name}.`);
            }
            out.window -= n;
            out.unread += n;
            return send('CHANNEL_DATA', [recipient, ['data', `${n} byte${n === 1 ? '' : 's'}`]]);
        }
        if (kind === 'adjust') {
            // The receiver consumes bytes the peer sent and returns that credit.
            const incoming = ch.out[peer];
            if (!Number.isInteger(n) || n < 1) return fail('Enter a whole number of bytes, at least 1.');
            if (incoming.unread < n) {
                return fail(`${who} holds only ${incoming.unread} unread byte${incoming.unread === 1 ? '' : 's'} `
                    + `on channel ${name}; this simulator returns credit only for bytes consumed.`);
            }
            incoming.unread -= n;
            incoming.window += n;
            return send('CHANNEL_WINDOW_ADJUST', [recipient, ['bytes to add', n]]);
        }
        if (kind === 'eof') {
            if (ch.eof[side]) return fail(`${who} has already sent EOF on channel ${name}.`);
            ch.eof[side] = true;
            return send('CHANNEL_EOF', [recipient]);
        }
        if (kind === 'close') {
            ch.close[side] = true;
            return send('CHANNEL_CLOSE', [recipient]);
        }
        return fail(`Unknown action ${kind}.`);
    }

    function channelStatus(ch) {
        const { id } = ch.conf;
        if (!ch.opened.client) return 'Not open';
        if (!ch.opened.server) return 'Opening: the client waits for confirmation';
        if (ch.close.client && ch.close.server) {
            return `Closed: both sides sent and received CLOSE; ${id.client} and ${id.server} may be reused`;
        }
        for (const side of ['client', 'server']) {
            if (ch.close[side]) {
                return `Closing: ${NAME[side].toLowerCase()} sent CLOSE; ${PEER[side]} must reply with CLOSE`;
            }
        }
        if (ch.eof.client && ch.eof.server) return 'Open, both sides sent EOF: no more data either way';
        for (const side of ['client', 'server']) {
            if (ch.eof[side]) return `Open, ${NAME[side].toLowerCase()} sent EOF: half-closed`;
        }
        return 'Open';
    }

    // The guided run. Step 0 is the empty starting state.
    const SCRIPT = [
        { caption: 'Two channels will share one transport. Each side picks its own local numbers: '
            + 'channel A is 7 at the client and 42 at the server; channel B is 8 and 51. '
            + 'Nothing has been sent yet.' },
        { act: { kind: 'open', ch: 'A', side: 'client' },
            caption: 'The client opens channel A. It introduces its own number, 7, as sender channel and '
            + 'advertises what it can receive: a window of 12 bytes in packets of at most 8. It cannot send '
            + 'data yet: it knows neither the server’s number nor the server’s window.' },
        { act: { kind: 'confirm', ch: 'A', side: 'server' },
            caption: 'The server confirms. Recipient channel is the client’s 7; the server introduces its '
            + 'own number, 42, and grants the client a window of 10 bytes in packets of at most 6.' },
        { act: { kind: 'open', ch: 'B', side: 'client' },
            caption: 'The client opens a second channel, B, with sender channel 8 and the same receive limits. '
            + 'Channel A’s windows are unaffected.' },
        { act: { kind: 'confirm', ch: 'B', side: 'server' },
            caption: 'The server confirms B to recipient 8 as its own channel 51, granting a window of 12 bytes '
            + 'in packets of at most 6. Each channel now has two independent windows, one per direction.' },
        { act: { kind: 'data', ch: 'A', side: 'client', n: 6 },
            caption: 'Lab step 1. The client has 10 bytes of credit on A, but the maximum packet size caps one '
            + 'CHANNEL_DATA at 6. The message names the recipient’s channel, 42. The server buffers the '
            + 'bytes until its application reads them.' },
        { act: { kind: 'data', ch: 'A', side: 'client', n: 4 },
            caption: 'The client spends its last 4 bytes of credit. A’s client-to-server window is now 0, '
            + 'so the client must pause channel A even though the TCP connection is still writable.' },
        { act: { kind: 'data', ch: 'B', side: 'client', n: 6 },
            caption: 'Lab step 2. Channel B has its own window, so the client keeps sending on it (recipient 51). '
            + 'A’s exhausted window does not touch B’s credit.' },
        { act: { kind: 'adjust', ch: 'A', side: 'server', n: 8 },
            caption: 'Lab step 3. The server’s application reads 8 of the 10 buffered bytes on A, and the '
            + 'server returns that credit with CHANNEL_WINDOW_ADJUST to the client’s number, 7. '
            + 'Only channel A gains credit; the client may resume sending on it.' },
        { act: { kind: 'eof', ch: 'B', side: 'client' },
            caption: 'Lab step 4. The client has no more input for B and sends CHANNEL_EOF to recipient 51. '
            + 'This ends only the client-to-server direction, and EOF consumes no window.' },
        { act: { kind: 'data', ch: 'B', side: 'server', n: 5 },
            caption: 'The server still sends final output on B, addressed to the client’s number, 8, '
            + 'and paid for from the 12-byte window the client advertised when it opened B.' },
        { act: { kind: 'eof', ch: 'B', side: 'server' },
            caption: 'The server has finished too and sends its own EOF to 8. No more data flows on B in '
            + 'either direction, but the channel is not closed yet.' },
        { act: { kind: 'close', ch: 'A', side: 'client' },
            caption: 'Lab step 5. The client sends CHANNEL_CLOSE on A to recipient 42, without an EOF first, '
            + 'which RFC 4254 permits. It may not reuse number 7 until the server’s CLOSE arrives.' },
        { act: { kind: 'close', ch: 'A', side: 'server' },
            caption: 'The server answers with CHANNEL_CLOSE to 7. Each side has now sent and received CLOSE, '
            + 'so A is closed: the client may reuse 7 and the server 42. Channel B is untouched.' },
        { act: { kind: 'close', ch: 'B', side: 'server' },
            caption: 'B’s close handshake is independent, and here the server starts it: '
            + 'CHANNEL_CLOSE to recipient 8.' },
        { act: { kind: 'close', ch: 'B', side: 'client' },
            caption: 'The client replies with CHANNEL_CLOSE to 51, and B is closed too. The transport stays up '
            + 'and could carry new channels.' },
    ];

    // Index of the step after which both channels are open.
    const BOTH_OPEN = 4;

    function stateAt(index) {
        const state = newState();
        for (const step of SCRIPT.slice(1, index + 1)) apply(state, step.act);
        return state;
    }

    // ---- Rendering ---------------------------------------------------------

    function renderDirection(ch, side) {
        const out = ch.out[side];
        const receiver = PEER[side];
        const label = h('div', { class: 'w-flow-dir-label' },
            h('strong', null, NAME[side], h('span', { class: 'w-flow-arrow' }, ' → '), receiver));
        if (!out) {
            const when = side === 'client' ? 'CHANNEL_OPEN_CONFIRMATION' : 'CHANNEL_OPEN';
            return h('div', { class: 'w-flow-dir' }, label,
                h('div', { class: 'w-note' }, `No credit until the ${receiver} sends ${when}.`));
        }
        const cells = [];
        for (let i = 0; i < out.initial; i += 1) {
            cells.push(h('span', { class: i < out.window ? 'w-flow-cell w-flow-credit' : 'w-flow-cell w-flow-unread' }));
        }
        const flags = [];
        if (ch.eof[side]) flags.push(h('span', { class: 'w-flow-flag' }, 'EOF sent'));
        if (ch.close[side]) flags.push(h('span', { class: 'w-flow-flag' }, 'CLOSE sent'));
        const summary = `window ${out.window} of ${out.initial}, maximum packet ${out.max}, `
            + `${out.unread} unread at ${receiver}`;
        return h('div', { class: 'w-flow-dir' },
            label,
            h('div', { class: 'w-flow-cells', role: 'img', 'aria-label': summary }, cells, flags),
            h('div', { class: 'w-flow-nums' },
                h('span', null, 'window ', h('strong', null, out.window), ` of ${out.initial}`),
                h('span', null, `max packet ${out.max}`),
                h('span', null, `unread at ${receiver} ${out.unread}`)));
    }

    function renderChannel(ch, highlight) {
        const { name, tag, id } = ch.conf;
        return h('section', { class: `w-flow-channel${highlight ? ' w-flow-active' : ''}` },
            h('div', { class: 'w-flow-head' },
                h('span', { class: `w-flow-badge ${tag}` }, `Channel ${name}`),
                h('span', { class: 'w-mono' }, `client ${id.client} ↔ server ${id.server}`)),
            h('div', { class: 'w-flow-state' }, channelStatus(ch)),
            renderDirection(ch, 'client'),
            renderDirection(ch, 'server'));
    }

    function renderLog(state) {
        if (!state.log.length) return h('p', { class: 'w-note' }, 'No messages yet.');
        const items = state.log.map((entry, i) => {
            const conf = state.channels[entry.ch].conf;
            const fields = entry.fields.map(([key, value, role]) =>
                h('span', { class: role === 'recipient' ? 'w-flow-field w-flow-recipient' : 'w-flow-field' },
                    `${key} `, role === 'recipient' ? h('strong', null, value) : value));
            return h('li', { class: i === state.log.length - 1 ? 'w-flow-last' : null },
                h('span', { class: `w-flow-badge ${conf.tag}` }, entry.ch), ' ',
                h('span', { class: 'w-flow-arrow' }, entry.from === 'client' ? 'C → S' : 'C ← S'), ' ',
                h('span', { class: 'w-mono' }, entry.type), ' ',
                h('span', { class: 'w-mono' }, fields));
        });
        return h('ol', { class: 'w-flow-log' }, items);
    }

    SSHWidgets.register('flow', (root) => {
        let mode = 'guided';
        let free = null;
        const live = liveRegion();
        const status = h('p', { class: 'w-status' });
        const channelsEl = h('div', { class: 'w-cols w-flow-channels' });
        const logEl = h('div', { class: 'w-flow-logbox', tabindex: '0', 'aria-label': 'Messages on the wire' });

        function show(state, text, tone) {
            status.className = `w-status${tone ? ` w-${tone}` : ''}`;
            status.textContent = text;
            live.say(text);
            const last = state.log[state.log.length - 1];
            channelsEl.replaceChildren(...Object.values(state.channels)
                .map((ch) => renderChannel(ch, last && last.ch === ch.conf.name)));
            logEl.replaceChildren(renderLog(state));
            logEl.scrollTop = logEl.scrollHeight;
        }

        const steps = stepper({
            count: SCRIPT.length,
            render: (i) => show(stateAt(i), SCRIPT[i].caption, null),
        });

        // Free-play controls.
        const chSelect = h('select', null, CHANNELS.map((c) => h('option', { value: c.name }, `Channel ${c.name}`)));
        const sideSelect = h('select', null,
            h('option', { value: 'client' }, 'Client'),
            h('option', { value: 'server' }, 'Server'));
        const bytes = h('input', { type: 'number', min: '1', max: '99', value: '4', size: '3' });
        const act = (kind) => () => {
            const action = { kind, ch: chSelect.value, side: sideSelect.value, n: Number(bytes.value) };
            const result = apply(free, action);
            let text = result.text;
            let tone = result.ok ? 'good' : 'bad';
            if (result.ok) {
                const ch = free.channels[action.ch];
                const last = free.log[free.log.length - 1];
                text = `${NAME[action.side]} sent ${last.type} on channel ${action.ch}. ${channelStatus(ch)}.`;
                if (ch.close[action.side] !== ch.close[PEER[action.side]]) tone = 'warn';
            }
            show(free, text, tone);
        };
        const restart = () => {
            free = stateAt(BOTH_OPEN);
            show(free, 'Both channels are open. Pick a channel and a sender, then send messages; '
                + 'rules the protocol forbids are refused with a reason.', null);
        };
        const freeEl = h('div', { class: 'w-flow-free' },
            h('div', { class: 'w-controls' },
                h('label', null, 'Channel ', chSelect),
                h('label', null, 'From ', sideSelect),
                h('label', null, 'Bytes ', bytes)),
            h('div', { class: 'w-controls' },
                h('button', { type: 'button', onclick: act('data') }, 'Send CHANNEL_DATA'),
                h('button', { type: 'button', onclick: act('adjust') }, 'Consume + WINDOW_ADJUST'),
                h('button', { type: 'button', onclick: act('eof') }, 'Send EOF'),
                h('button', { type: 'button', onclick: act('close') }, 'Send CLOSE'),
                h('button', { type: 'button', onclick: restart }, '⏮ Restart')),
            h('p', { class: 'w-note' },
                '“Consume + WINDOW_ADJUST” makes the chosen side read that many bytes it has received and '
                + 'return the credit. A real receiver may grant more, up to a window of 2^32 − 1 bytes.'));

        const guidedBtn = h('button', { type: 'button', 'aria-pressed': 'true', onclick: () => setMode('guided') },
            'Guided lab');
        const freeBtn = h('button', { type: 'button', 'aria-pressed': 'false', onclick: () => setMode('free') },
            'Free play');

        function setMode(next) {
            mode = next;
            guidedBtn.setAttribute('aria-pressed', String(mode === 'guided'));
            freeBtn.setAttribute('aria-pressed', String(mode === 'free'));
            steps.el.hidden = mode !== 'guided';
            freeEl.hidden = mode !== 'free';
            if (mode === 'guided') {
                steps.go(steps.index);
            } else {
                // Continue from the guided step once both channels are open.
                free = stateAt(Math.max(steps.index, BOTH_OPEN));
                show(free, 'Free play, continuing from the guided run with both channels open. '
                    + 'Send messages; rules the protocol forbids are refused with a reason.', null);
            }
        }

        root.append(
            h('p', { class: 'w-title' }, 'Two channels, one transport'),
            h('div', { class: 'w-controls', role: 'group', 'aria-label': 'Mode' }, guidedBtn, freeBtn),
            steps.el, freeEl, status, live,
            channelsEl,
            h('p', { class: 'w-flow-logtitle' }, 'On the wire: one ordered stream, all channels'),
            logEl,
            h('p', { class: 'w-note' },
                'Green cells are send credit; amber cells are bytes the receiver holds unread. Underlined '
                + 'numbers are the recipient channel each message carries. Message names omit the '
                + 'SSH_MSG_ prefix.'));
        freeEl.hidden = true;
        steps.go(0);
    });
})();
