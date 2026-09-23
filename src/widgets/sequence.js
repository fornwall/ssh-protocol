// Whole-connection step-through: one SSH connection message by message, in a
// client | server ladder, with the client's protocol state after each step.
//
// A chapter can replace the default sequence with a JSON child:
//
//   <div class="ssh-widget" data-widget="sequence">
//   <script type="application/json">{ "steps": [ ... ] }</script>
//   </div>
//
// Each step is { from: 'c' | 's', msg, num?, unit?: 'line', group?, detail?,
// caption, note?, links?: [[text, 'chapter.md#anchor'], ...], state? }.
// `state` is merged into the client's state after the step: phase, server,
// session, user, negotiated: { cs, sc }, channels: { name: text | null }.
// Key activation is derived: SSH_MSG_NEWKEYS switches the sender's direction.
SSHWidgets.register('sequence', (root, config) => {
    'use strict';
    const { h, stepper, liveRegion } = SSHWidgets;

    const CIPHER = 'chacha20-poly1305@openssh.com';
    const DEFAULT_STEPS = [
        {
            group: 'Identification', from: 'c', unit: 'line', msg: 'Identification line',
            detail: 'SSH-2.0-OpenSSH_10.5 CR LF',
            caption: 'The client announces that it speaks SSH 2.0 and names its software.',
            note: 'Both peers send their line as soon as TCP connects; neither waits for the other.',
            links: [['The identification line', 'identification.md#the-identification-line']],
            state: { phase: 'Identification' },
        },
        {
            from: 's', unit: 'line', msg: 'Identification line',
            detail: 'SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.6 CR LF',
            caption: 'The server’s line confirms version 2.0; both lines are later hashed into the exchange hash.',
            links: [['Cleartext, authenticated later', 'identification.md#cleartext-authenticated-later']],
        },
        {
            group: 'Negotiation and key exchange', from: 'c', msg: 'SSH_MSG_KEXINIT', num: 20,
            detail: 'cookie, kex_algorithms = mlkem768x25519-sha256,…,ext-info-c,kex-strict-c-v00@openssh.com, …',
            caption: 'The client proposes algorithms in its order of preference and signals extension and strict-KEX support.',
            note: 'Both peers send KEXINIT without waiting for the other.',
            links: [['SSH_MSG_KEXINIT carries proposals', 'version-and-negotiation.md#ssh_msg_kexinit-carries-proposals']],
            state: { phase: 'Key exchange' },
        },
        {
            from: 's', msg: 'SSH_MSG_KEXINIT', num: 20,
            detail: 'cookie, kex_algorithms = mlkem768x25519-sha256,…,ext-info-s,kex-strict-s-v00@openssh.com, …',
            caption: 'With both proposals in hand, each side computes the same choice: mlkem768x25519-sha256, ssh-ed25519, and ChaCha20-Poly1305 each way.',
            note: 'Both lists carry a strict-KEX marker, so strict KEX is active.',
            links: [['Client preference wins', 'version-and-negotiation.md#the-selection-rule-client-preference-wins'],
                ['Strict key exchange', 'version-and-negotiation.md#strict-key-exchange']],
            state: { negotiated: { cs: CIPHER, sc: CIPHER } },
        },
        {
            from: 'c', msg: 'SSH_MSG_KEX_HYBRID_INIT', num: 30,
            detail: 'string C_INIT = ML-KEM-768 public key ‖ X25519 public key (1216 bytes)',
            caption: 'The client sends fresh ephemeral public values for the hybrid key exchange.',
            note: 'Numbers 30 and 31 are method-specific; OpenSSH’s debug log calls the reply SSH2_MSG_KEX_ECDH_REPLY.',
            links: [['The wire view of mlkem768x25519-sha256', 'crypto-post-quantum.md#the-wire-view-of-mlkem768x25519-sha256']],
        },
        {
            from: 's', msg: 'SSH_MSG_KEX_HYBRID_REPLY', num: 31,
            detail: 'string K_S (ssh-ed25519 host key), string S_REPLY (1120 bytes), string signature over H',
            caption: 'The client derives K and H, verifies the host-key signature over H, and checks K_S against known_hosts.',
            note: 'The H of this first exchange becomes the session identifier for the life of the connection.',
            links: [['The host-key signature and the trust decision', 'key-exchange.md#the-host-key-signature-and-the-trust-decision'],
                ['Session identifier versus exchange hash', 'key-exchange.md#session-identifier-versus-exchange-hash']],
            state: { phase: 'Server verified', server: 'yes: signature valid, host key trusted', session: 'set (H of the first key exchange)' },
        },
        {
            group: 'Keys switch on NEWKEYS', from: 'c', msg: 'SSH_MSG_NEWKEYS', num: 21,
            detail: '(no fields)',
            caption: 'The client’s last packet under the old protection; everything it sends afterwards uses the new client-to-server keys.',
            note: 'Strict KEX resets the send sequence number to 0; the trace logs “resetting send seqnr 3”.',
            links: [['Activating keys with SSH_MSG_NEWKEYS', 'key-exchange.md#activating-keys-with-ssh_msg_newkeys']],
        },
        {
            from: 'c', msg: 'SSH_MSG_EXT_INFO', num: 7,
            detail: 'ext-info-in-auth@openssh.com = "0"',
            caption: 'The server’s KEXINIT listed ext-info-s, so the client may send its own extensions, as its first packet after NEWKEYS.',
            note: 'OpenSSH uses it to say it can accept another EXT_INFO during authentication.',
            links: [['Extension negotiation with ext-info-*', 'version-and-negotiation.md#extension-negotiation-with-ext-info-']],
        },
        {
            from: 's', msg: 'SSH_MSG_NEWKEYS', num: 21,
            detail: '(no fields)',
            caption: 'After receiving it, the client expects every server packet under the new server-to-client keys.',
            note: 'The two directions switch independently; the trace logs “resetting read seqnr 3”.',
            links: [['State is directional', 'client-architecture.md#state-is-directional']],
            state: { phase: 'Transport protected' },
        },
        {
            from: 's', msg: 'SSH_MSG_EXT_INFO', num: 7,
            detail: 'server-sig-algs = ssh-ed25519,…; publickey-hostbound@openssh.com = "0"; ping@openssh.com = "0"; …',
            caption: 'The client sent ext-info-c, so the server lists extensions, including the signature algorithms it accepts for user authentication.',
            links: [['Discovering acceptable signature algorithms', 'user-authentication.md#discovering-acceptable-signature-algorithms']],
        },
        {
            group: 'User authentication', from: 'c', msg: 'SSH_MSG_SERVICE_REQUEST', num: 5,
            detail: 'string "ssh-userauth"',
            caption: 'Only now, with the server authenticated and traffic protected, does the client ask to start user authentication.',
            links: [['Entering the authentication service', 'user-authentication.md#entering-the-authentication-service']],
            state: { phase: 'User authentication' },
        },
        {
            from: 's', msg: 'SSH_MSG_SERVICE_ACCEPT', num: 6,
            detail: 'string "ssh-userauth"',
            caption: 'The server agrees; from here on the client may send USERAUTH requests.',
            links: [['Transport control messages', 'binary-packets.md#transport-control-messages']],
        },
        {
            from: 'c', msg: 'SSH_MSG_USERAUTH_REQUEST', num: 50,
            detail: 'user "user", service "ssh-connection", method "none"',
            caption: 'OpenSSH starts with the none method to learn which methods the server will accept.',
            links: [['The none method', 'user-authentication.md#the-none-method']],
        },
        {
            from: 's', msg: 'SSH_MSG_USERAUTH_FAILURE', num: 51,
            detail: 'name-list "publickey,password", partial success FALSE',
            caption: 'The expected refusal lists the methods that can continue.',
            links: [['The server drives policy', 'user-authentication.md#the-server-drives-policy']],
        },
        {
            from: 'c', msg: 'SSH_MSG_USERAUTH_REQUEST', num: 50,
            detail: 'method "publickey", FALSE, "ssh-ed25519", public key blob',
            caption: 'The client asks whether this key is acceptable before unlocking it or signing anything.',
            links: [['Optional key query', 'user-authentication.md#optional-key-query']],
            state: { user: 'no (trying publickey)' },
        },
        {
            from: 's', msg: 'SSH_MSG_USERAUTH_PK_OK', num: 60,
            detail: '"ssh-ed25519", public key blob (echoed)',
            caption: 'The key is acceptable, which invites a signature but is not yet success.',
            note: 'Message 60 means PK_OK only because the pending method is publickey.',
            links: [['Several state machines coexist', 'client-architecture.md#several-state-machines-coexist']],
        },
        {
            from: 'c', msg: 'SSH_MSG_USERAUTH_REQUEST', num: 50,
            detail: 'method "publickey-hostbound-v00@openssh.com", TRUE, "ssh-ed25519", key blob, server host key, signature',
            caption: 'The client signs data that starts with the session identifier, binding the proof to this connection.',
            note: 'The server’s EXT_INFO offered publickey-hostbound@openssh.com, so OpenSSH sends the host-bound form of publickey.',
            links: [['Signed request', 'user-authentication.md#signed-request'],
                ['Host-bound public-key authentication', 'user-authentication.md#host-bound-public-key-authentication']],
        },
        {
            from: 's', msg: 'SSH_MSG_USERAUTH_SUCCESS', num: 52,
            detail: '(no fields)',
            caption: 'The user is authenticated and the ssh-connection service starts on the same transport.',
            links: [['Authentication policy flow', 'user-authentication.md#authentication-policy-flow']],
            state: { phase: 'Connection protocol', user: 'yes (publickey)' },
        },
        {
            group: 'Session channel', from: 'c', msg: 'SSH_MSG_CHANNEL_OPEN', num: 90,
            detail: '"session", sender channel 0, initial window, maximum packet',
            caption: 'The client opens a session channel, naming it 0 and granting the server receive credit.',
            links: [['Opening a channel', 'channels.md#opening-a-channel']],
            state: { channels: { session: 'ours 0, theirs ?: opening' } },
        },
        {
            from: 's', msg: 'SSH_MSG_CHANNEL_OPEN_CONFIRMATION', num: 91,
            detail: 'recipient 0, sender channel 5, initial window, maximum packet',
            caption: 'The server confirms and names its end 5; each side now addresses the channel by the other’s number.',
            links: [['Channel numbers are local', 'channels.md#channel-numbers-are-local']],
            state: { channels: { session: 'ours 0, theirs 5: open' } },
        },
        {
            from: 'c', msg: 'SSH_MSG_CHANNEL_REQUEST', num: 98,
            detail: 'recipient 5, "exec", want reply TRUE, command \'printf "hello from the server\\n"\'',
            caption: 'Opening the channel started nothing; this request asks the server to run the command.',
            links: [['Open, prepare, start', 'sessions.md#open-prepare-start']],
        },
        {
            from: 's', msg: 'SSH_MSG_CHANNEL_SUCCESS', num: 99,
            detail: 'recipient 0',
            caption: 'The server accepted the exec request; this says nothing yet about how the command will end.',
            links: [['Requests are not data', 'channels.md#requests-are-not-data']],
            state: { channels: { session: 'ours 0, theirs 5: open, command running' } },
        },
        {
            from: 's', msg: 'SSH_MSG_CHANNEL_DATA', num: 94,
            detail: 'recipient 0, data "hello from the server\\n" (22 bytes)',
            caption: 'The command’s output arrives as channel data and uses 22 bytes of the window the client granted.',
            links: [['Windows and flow control', 'channels.md#windows-and-flow-control']],
        },
        {
            from: 's', msg: 'SSH_MSG_CHANNEL_EOF', num: 96,
            detail: 'recipient 0',
            caption: 'The server will send no more data on this channel, but requests and CLOSE can still follow.',
            links: [['EOF and CLOSE', 'channels.md#eof-and-close']],
            state: { channels: { session: 'ours 0, theirs 5: server sent EOF' } },
        },
        {
            from: 's', msg: 'SSH_MSG_CHANNEL_REQUEST', num: 98,
            detail: 'recipient 0, "exit-status", want reply FALSE, status 0',
            caption: 'The server reports that the command exited with status 0.',
            links: [['Signals and process completion', 'sessions.md#signals-and-process-completion']],
        },
        {
            from: 's', msg: 'SSH_MSG_CHANNEL_CLOSE', num: 97,
            detail: 'recipient 0',
            caption: 'The server starts closing the channel; the client must answer with its own CLOSE.',
            links: [['EOF and CLOSE', 'channels.md#eof-and-close']],
            state: { channels: { session: 'ours 0, theirs 5: CLOSE received' } },
        },
        {
            from: 'c', msg: 'SSH_MSG_CHANNEL_CLOSE', num: 97,
            detail: 'recipient 5',
            caption: 'Having sent and received CLOSE, the client may reuse its number 0; the server may reuse 5 once this arrives.',
            links: [['EOF and CLOSE', 'channels.md#eof-and-close']],
            state: { channels: { session: null } },
        },
        {
            group: 'End of connection', from: 'c', msg: 'SSH_MSG_DISCONNECT', num: 1,
            detail: 'reason 11 (SSH_DISCONNECT_BY_APPLICATION), "disconnected by user"',
            caption: 'No channels remain, so the client ends the transport and closes TCP.',
            links: [['Transport control messages', 'binary-packets.md#transport-control-messages']],
            state: { phase: 'Closed' },
        },
    ];

    const steps = Array.isArray(config.steps) ? config.steps : DEFAULT_STEPS;
    const history = replay(steps);

    // Fold the steps into the client's state after each one. A packet is
    // protected when its direction had keys at the time it was sent.
    function replay(list) {
        let state = {
            phase: 'TCP connected', server: 'no', session: 'not set', user: 'no',
            negotiated: {}, keys: { cs: null, sc: null }, epochs: { cs: 0, sc: 0 }, channels: {},
        };
        return list.map((step) => {
            const dir = step.from === 'c' ? 'cs' : 'sc';
            const sentUnder = step.unit === 'line' ? null : { key: state.keys[dir], epoch: state.epochs[dir] };
            state = { ...state, keys: { ...state.keys }, epochs: { ...state.epochs }, channels: { ...state.channels } };
            if (step.msg === 'SSH_MSG_NEWKEYS') {
                state.epochs[dir] += 1;
                state.keys[dir] = state.negotiated[dir] || 'the negotiated cipher';
            }
            for (const [key, value] of Object.entries(step.state || {})) {
                if (key === 'channels') {
                    for (const [name, text] of Object.entries(value)) {
                        if (text == null) delete state.channels[name];
                        else state.channels[name] = text;
                    }
                } else {
                    state[key] = value;
                }
            }
            return { step, dir, sentUnder, state };
        });
    }

    const DIR_NAME = { cs: 'client-to-server', sc: 'server-to-client' };

    function protection({ step, dir, sentUnder }) {
        const last = step.msg === 'SSH_MSG_NEWKEYS';
        if (!sentUnder) {
            return { ok: false, label: 'Cleartext line.', text: 'Text on the byte stream, not a binary packet.' };
        }
        if (!sentUnder.key) {
            return {
                ok: false,
                label: 'Cleartext packet.',
                text: last ? 'NEWKEYS is sent under the old protection, which here is none.'
                    : `No ${DIR_NAME[dir]} keys are active yet.`,
            };
        }
        const round = sentUnder.epoch > 1 ? `key exchange ${sentUnder.epoch}` : 'the first key exchange';
        return {
            ok: true,
            label: 'Protected.',
            text: `Encrypted and authenticated with ${sentUnder.key}, using the ${DIR_NAME[dir]} keys from ${round}.`
                + (last ? ' This is the last packet under those keys.' : ''),
        };
    }

    function keyText(state, dir) {
        return state.keys[dir] ? `active (from key exchange ${state.epochs[dir]})` : 'none';
    }

    const STATE_ROWS = [
        ['Transport phase', (s) => s.phase],
        ['Server authenticated', (s) => s.server],
        ['session_id', (s) => s.session],
        ['Keys client → server', (s) => keyText(s, 'cs')],
        ['Keys server → client', (s) => keyText(s, 'sc')],
        ['User authenticated', (s) => s.user],
        ['Open channels', (s) => {
            const entries = Object.entries(s.channels);
            return entries.length ? entries.map(([name, text]) => `${name} (${text})`).join('; ') : 'none';
        }],
    ];

    function linkHref(target) {
        return target.replace(/\.md(?=#|$)/, '.html');
    }

    // ---- Ladder ------------------------------------------------------------

    const rows = [];
    const ladder = h('ol', { class: 'w-seq-ladder', 'aria-label': 'Messages in order' });
    history.forEach((entry, i) => {
        const { step, dir, sentUnder } = entry;
        if (step.group) ladder.append(h('li', { class: 'w-seq-group', 'aria-hidden': 'true' }, step.group));
        const sealed = sentUnder && sentUnder.key;
        const label = step.msg.replace(/^SSH_MSG_/, '');
        const row = h('li', {
            class: `w-seq-row w-seq-${dir} ${sealed ? 'w-seq-sealed' : 'w-seq-clear'}${sentUnder ? '' : ' w-seq-line'}`,
            onclick: () => nav.go(i),
        },
        h('span', { class: 'w-seq-label w-mono' }, label),
        h('span', { class: 'w-seq-arrow', 'aria-hidden': 'true' }),
        h('span', { class: 'w-sr-only' }, dir === 'cs' ? 'client to server' : 'server to client'));
        rows.push(row);
        ladder.append(row);
    });

    const ladderBox = h('div', { class: 'w-seq-ladder-box', tabindex: '0', 'aria-label': 'Message ladder; use the arrow keys to step' },
        h('div', { class: 'w-seq-lanes', 'aria-hidden': 'true' }, h('span', {}, 'Client'), h('span', {}, 'Server')),
        ladder);
    ladderBox.addEventListener('keydown', (event) => {
        if (event.key === 'ArrowDown' || event.key === 'ArrowRight') { nav.next(); event.preventDefault(); }
        if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') { nav.back(); event.preventDefault(); }
    });

    // ---- Detail and state panels -------------------------------------------

    const heading = h('div', { class: 'w-seq-heading' });
    const fields = h('div', { class: 'w-seq-fields w-mono' });
    const shield = h('p', { class: 'w-status' });
    const caption = h('p', { class: 'w-seq-caption' });
    const note = h('p', { class: 'w-note' });
    const links = h('p', { class: 'w-seq-links' });
    const detail = h('div', { class: 'w-seq-detail' }, heading, fields, shield, caption, note, links);

    const stateCells = STATE_ROWS.map(() => h('dd'));
    const stateList = h('dl', { class: 'w-seq-state' },
        STATE_ROWS.map(([name], i) => [h('dt', {}, name), stateCells[i]]));
    const statePanel = h('div', { class: 'w-seq-state-box' },
        h('div', { class: 'w-seq-state-title' }, 'Client state after this message'), stateList);

    const live = liveRegion();

    function render(i) {
        const entry = history[i];
        const { step, dir } = entry;
        rows.forEach((row, j) => {
            row.classList.toggle('w-seq-current', j === i);
            row.classList.toggle('w-seq-future', j > i);
            if (j === i) row.setAttribute('aria-current', 'step');
            else row.removeAttribute('aria-current');
        });
        const row = rows[i];
        const top = row.offsetTop - ladderBox.clientHeight / 2 + row.offsetHeight / 2;
        ladderBox.scrollTop = Math.max(0, top);

        const arrow = dir === 'cs' ? 'Client → Server' : 'Server → Client';
        heading.replaceChildren(
            h('span', { class: 'w-seq-dir' }, arrow),
            h('strong', { class: 'w-mono' }, step.msg));
        if (step.num != null) heading.append(h('span', { class: 'w-seq-num' }, `message ${step.num}`));
        fields.textContent = step.detail || '';
        fields.hidden = !step.detail;
        const prot = protection(entry);
        shield.className = `w-status ${prot.ok ? 'w-good' : 'w-warn'}`;
        shield.replaceChildren(h('strong', {}, prot.label), ' ', prot.text);
        caption.textContent = step.caption || '';
        note.textContent = step.note || '';
        note.hidden = !step.note;
        links.replaceChildren(...(step.links || []).flatMap(([text, target], k) => [
            k === 0 ? 'Read more: ' : ' · ',
            h('a', { href: linkHref(target) }, text),
        ]));
        links.hidden = !(step.links || []).length;

        const before = i > 0 ? history[i - 1].state : null;
        STATE_ROWS.forEach(([, get], k) => {
            const value = get(entry.state);
            stateCells[k].textContent = value;
            stateCells[k].classList.toggle('w-seq-changed', before !== null && get(before) !== value);
        });
        live.say(`${arrow}: ${step.msg}. ${prot.label}`);
    }

    const nav = stepper({ count: steps.length, render, label: 'Message' });

    root.append(
        h('p', { class: 'w-title' }, config.title || 'One OpenSSH connection, message by message'),
        nav.el,
        h('div', { class: 'w-seq-cols' }, ladderBox, h('div', {}, detail, statePanel)),
        h('p', { class: 'w-note' }, config.omitted || 'Omitted for clarity: a second server EXT_INFO during authentication, GLOBAL_REQUESTs (no-more-sessions@openssh.com, hostkeys-00@openssh.com), DEBUG, WINDOW_ADJUST, and the eow@openssh.com channel request.'),
        live);
    nav.go(0);
});
