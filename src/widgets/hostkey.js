// Host-key decision explorer: how OpenSSH's client decides whether the host
// key in the key-exchange reply is trusted. The rules follow verify_host_key() and
// check_host_key() in OpenSSH's sshconnect.c; the printed messages are those
// of OpenSSH 10 (UserKnownHostsFile only, CheckHostIP off, default port).
(() => {
    'use strict';

    const { h, field, liveRegion } = SSHWidgets;

    const HOST = 'db1.example.com';
    const FILE = '/home/alice/.ssh/known_hosts';
    const KRL = '/etc/ssh/revoked_hosts';
    const FP = 'SHA256:IkbzLKatRpLW9ZEh3mFFAiXcBcgvDCPh6Jd/E1VdCAg';
    const CA_FP = 'SHA256:2V1EXQ+AjTlX8lua2/7WtpXdrC47f8XvUlnhRn45Vtg';
    const OTHER_CA_FP = 'SHA256:Fva3+wSXjhvO6AhxEQ9a97KPaln99z5W01FxFom3+bw';
    const KEY = {
        host: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJQ7n6eh…',
        other: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOVt+duV…',
        rsa: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCt…',
        ca: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOdCCGWr…',
    };

    const OPTIONS = {
        present: [
            ['plain', 'A plain host key'],
            ['cert', 'A host certificate'],
        ],
        cert: [
            ['ok', 'Valid: trusted CA, principal db1.example.com, in date'],
            ['untrusted', 'Signed by a CA not trusted for this name'],
            ['principal', 'Its only principal is web1.example.com'],
            ['expired', 'Outside its validity interval'],
            ['carevoked', 'Its CA key is marked @revoked'],
        ],
        known: [
            ['none', 'No entry'],
            ['match', 'This exact key'],
            ['changed', 'A different ssh-ed25519 key'],
            ['othertype', 'Only an ssh-rsa key'],
            ['revoked', 'This key, marked @revoked'],
        ],
        strict: [
            ['yes', 'yes'],
            ['accept-new', 'accept-new'],
            ['ask', 'ask (the default)'],
            ['no', 'no (or off)'],
        ],
        answer: [
            ['yes', 'yes, after checking the fingerprint'],
            ['no', 'no'],
        ],
    };

    const PRESETS = [
        ['First contact', { present: 'plain', known: 'none', strict: 'ask', answer: 'yes', krl: false }],
        ['Known server', { present: 'plain', known: 'match', strict: 'ask', krl: false }],
        ['Attacker’s key', { present: 'plain', known: 'changed', strict: 'ask', krl: false }],
        ['Changed key, no checking', { present: 'plain', known: 'changed', strict: 'no', krl: false }],
        ['Certificate for web1', { present: 'cert', cert: 'principal', known: 'none', strict: 'ask', answer: 'yes', krl: false }],
    ];

    // ---- Messages ssh prints -----------------------------------------------

    const BANNER = '@'.repeat(59);
    const failed = 'Host key verification failed.';

    function changedLines(offending, line) {
        return [
            BANNER,
            '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @',
            BANNER,
            'IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!',
            'Someone could be eavesdropping on you right now (man-in-the-middle attack)!',
            'It is also possible that a host key has just been changed.',
            'The fingerprint for the ED25519 key sent by the remote host is',
            `${FP}.`,
            'Please contact your system administrator.',
            `Add correct host key in ${FILE} to get rid of this message.`,
            `Offending ${offending} key in ${FILE}:${line}`,
        ];
    }

    function revokedLines(type) {
        return [
            BANNER,
            '@       WARNING: REVOKED HOST KEY DETECTED!               @',
            BANNER,
            `The ${type} host key for ${HOST} is marked as revoked.`,
            'This could mean that a stolen key is being used to',
            'impersonate this host.',
        ];
    }

    const UNSAFE = [
        'Password authentication is disabled to avoid man-in-the-middle attacks.',
        'Keyboard-interactive authentication is disabled to avoid man-in-the-middle attacks.',
        'Agent forwarding is disabled to avoid man-in-the-middle attacks.',
        'X11 forwarding is disabled to avoid man-in-the-middle attacks.',
        'Port forwarding is disabled to avoid man-in-the-middle attacks.',
        'Tunnel forwarding is disabled to avoid man-in-the-middle attacks.',
        'UpdateHostkeys is disabled because the host key is not trusted.',
    ];
    const UNSAFE_NOTE = 'Each “disabled” line appears only for a feature that was enabled or requested.';

    const PROMPT = [
        `The authenticity of host '${HOST} (192.0.2.10)' can't be established.`,
        `ED25519 key fingerprint is: ${FP}`,
        'This key is not known by any other names.',
    ];
    const ask = (answer) => `Are you sure you want to continue connecting (yes/no/[fingerprint])? ${answer}`;
    const added = `Warning: Permanently added '${HOST}' (ED25519) to the list of known hosts.`;

    const UNSAFE_SECURITY = 'ssh continues to a peer it cannot authenticate. It turns off what an '
        + 'attacker in the middle could exploit directly: password and keyboard-interactive '
        + 'authentication, and agent, X11, port, and tunnel forwarding. Public-key authentication '
        + 'still runs; its signature covers this session’s identifier, so it cannot be relayed to '
        + 'the real server, but an attacker can accept it and show you a fake shell. Treat '
        + 'everything you type or read in the session as exposed.';

    // Outcomes, keyed by the rule that fired. type is ED25519 or ED25519-CERT;
    // offending is the type of the recorded key that did not match, on line.
    function outcome(key, type, offending, line) {
        const catalog = {
            krl: ['bad', 'Refuses to connect: revoked host key',
                [`Host key ${type} ${FP} revoked by file ${KRL}`, failed], null,
                'Not applicable: no connection.',
                'The RevokedHostKeys file is checked before known_hosts, and no StrictHostKeyChecking value overrides it.'],
            'revoked-refuse': ['bad', 'Refuses to connect: revoked host key',
                [...revokedLines(type), `${type} host key for ${HOST} was revoked and you have requested strict checking.`, failed], null,
                'Not applicable: no connection.',
                'ssh stops before user authentication. Revocation overrides any matching line, and a revoked certificate is not retried as a plain key.'],
            'revoked-unsafe': ['warn', 'Connects anyway, with protections disabled',
                [...revokedLines(type), ...UNSAFE], null,
                'Turned off: the host key is not trusted.',
                UNSAFE_SECURITY],
            certok: ['good', 'Connects without asking',
                [`debug1: Host '${HOST}' is known and matches the ED25519-CERT host certificate.`], null,
                'Turned off: the host was authenticated with a certificate.',
                'Trust rests on the CA: its key vouches for every name that matches both the @cert-authority pattern and a certificate principal. Nothing is written to known_hosts.'],
            match: ['good', 'Connects without asking',
                [`debug1: Host '${HOST}' is known and matches the ED25519 host key.`], null,
                'Stays on: the key was already in your own known_hosts (a match from the system-wide file would turn it off).',
                'The peer holds the private key recorded for this name. That is only as trustworthy as the way the line got into known_hosts.'],
            'new-refuse': ['bad', 'Refuses to connect: no known key',
                [`No ED25519 host key is known for ${HOST} and you have requested strict checking.`, failed], null,
                'Not applicable: no connection.',
                'ssh stops before user authentication. To connect, first add the key from a trusted source (pre-provisioning).'],
            'new-add': ['warn', 'Records the key and connects without asking',
                [added], 'add',
                'Turned off: the key was neither already known nor explicitly accepted.',
                'Unverified trust on first use: no one looks at the fingerprint. If an attacker is on the path now, its key is recorded, and the real server will later trigger the changed-key warning instead.'],
            'ask-yes': ['good', 'Asks, then records the key and connects',
                [...PROMPT, ask('yes'), added], 'add',
                'Stays on: you explicitly accepted the key.',
                'Safe only if the fingerprint was compared with one obtained through an independent channel. Answering yes without checking is the same bet as accept-new. Pasting the expected fingerprint instead of yes makes ssh compare it for you.'],
            'ask-no': ['bad', 'Asks, and stops when the user declines',
                [...PROMPT, ask('no'), failed], null,
                'Not applicable: no connection.',
                'ssh stops before user authentication, and known_hosts is unchanged.'],
            'changed-refuse': ['bad', 'Refuses to connect: REMOTE HOST IDENTIFICATION HAS CHANGED',
                [...changedLines(offending, line), `Host key for ${HOST} has changed and you have requested strict checking.`, failed], null,
                'Not applicable: no connection.',
                'ssh stops before user authentication, so no credentials reach the peer, and it never replaces the stored key itself. Investigate as described under Host-key changes.'],
            'changed-unsafe': ['warn', 'Connects anyway, with protections disabled',
                [...changedLines(offending, line), ...UNSAFE], null,
                'Turned off: the host key is not trusted.',
                `${UNSAFE_SECURITY} known_hosts is not updated, so the warning repeats next time.`],
        };
        const [tone, verdict, prints, kh, update, security] = catalog[key];
        return { key, tone, verdict, prints, kh, update, security };
    }

    // ---- Decision logic ----------------------------------------------------

    // Returns { steps: [{ label, state, detail }], result }.
    // state: pass, fail, info, fire (this rule decided), or skip.
    function decide(s) {
        const cert = s.present === 'cert';
        const type = cert ? 'ED25519-CERT' : 'ED25519';
        const c = { status: null, fallback: null };
        const notRelevant = { state: 'skip', detail: 'Not relevant: the key is revoked.' };

        const rules = [
            ['RevokedHostKeys file', () => (s.krl
                ? { state: 'fire', detail: 'The key is listed, so ssh refuses before it reads known_hosts.', result: 'krl' }
                : { state: 'pass', detail: 'The key is not listed.' })],
            ['@revoked lines in known_hosts', () => {
                if (s.known === 'revoked' || (cert && s.cert === 'carevoked')) {
                    c.status = 'revoked';
                    return { state: 'fail', detail: `The ${s.known === 'revoked' ? 'host key' : 'CA key'} is marked @revoked. That overrides any matching line.` };
                }
                return { state: 'pass', detail: cert ? 'Neither the key nor its CA is revoked.' : 'The key is not revoked.' };
            }],
            cert && ['@cert-authority line for the signing CA', () => {
                if (c.status) return notRelevant;
                if (s.cert === 'untrusted') {
                    c.fallback = 'untrusted';
                    return { state: 'fail', detail: `No @cert-authority line with this CA key has a pattern matching ${HOST}.` };
                }
                return { state: 'pass', detail: `CA ${CA_FP} is trusted for *.example.com, which matches ${HOST}.` };
            }],
            cert && ['Certificate contents', () => {
                if (c.status) return notRelevant;
                if (c.fallback) return { state: 'skip', detail: 'Not checked: no trusted CA.' };
                if (s.cert === 'principal') {
                    c.fallback = 'principal';
                    return { state: 'fail', detail: `The only principal, web1.example.com, does not match ${HOST}.` };
                }
                if (s.cert === 'expired') {
                    c.fallback = 'expired';
                    return { state: 'fail', detail: 'The current time is outside the validity interval.' };
                }
                return { state: 'fire', detail: `A host certificate with principal ${HOST}, in date, with no critical options.`, result: 'certok' };
            }],
            cert && ['Retry as a plain key', () => (c.status ? notRelevant
                : { state: 'info', detail: 'The certificate failed, so ssh drops it and checks the certified key like any plain host key.' })],
            [`Plain-key lines for ${HOST}`, () => {
                if (c.status) return notRelevant;
                if (s.known === 'match') {
                    return { state: 'fire', detail: 'A line holds exactly this key. Known keys are accepted in every StrictHostKeyChecking mode.', result: 'match' };
                }
                if (s.known === 'none') {
                    c.status = 'new';
                    return { state: 'info', detail: 'No line for this name: the key is new.' };
                }
                c.status = 'changed';
                return s.known === 'changed'
                    ? { state: 'fail', detail: 'A different ssh-ed25519 key is recorded: the key has changed.' }
                    : { state: 'fail', detail: 'Only an ssh-rsa key is recorded. Any recorded key that does not match counts as changed, whatever its type.' };
            }],
            [`StrictHostKeyChecking ${s.strict}`, () => {
                const lax = s.strict === 'no';
                if (c.status === 'revoked' || c.status === 'changed') {
                    return lax
                        ? { state: 'fire', detail: 'no: continue, but disable features an attacker could abuse.', result: `${c.status}-unsafe` }
                        : { state: 'fire', detail: `${s.strict}: a ${c.status} key stops the connection.`, result: `${c.status}-refuse` };
                }
                if (s.strict === 'yes') return { state: 'fire', detail: 'yes: never add keys automatically.', result: 'new-refuse' };
                if (s.strict === 'ask') return { state: 'info', detail: 'ask: show the fingerprint and ask the user.' };
                return { state: 'fire', detail: `${s.strict}: add the new key without asking.`, result: 'new-add' };
            }],
            s.strict === 'ask' && ['User answers the prompt', () => (s.answer === 'yes'
                ? { state: 'fire', detail: 'yes: record the key and continue.', result: 'ask-yes' }
                : { state: 'fire', detail: 'no: stop.', result: 'ask-no' })],
        ].filter(Boolean);

        const steps = [];
        let result = null;
        for (const [label, run] of rules) {
            if (result) {
                steps.push({ label, state: 'skip', detail: 'Not reached.' });
                continue;
            }
            const r = run();
            steps.push({ label, state: r.state, detail: r.detail });
            if (r.result) result = r.result;
        }

        const out = outcome(result, type, s.known === 'othertype' ? 'RSA' : 'ED25519', knownHostsLines(s).length);
        // A certificate that failed its checks prints why before the plain-key result.
        if (c.fallback === 'principal') out.prints.unshift('Certificate invalid: name is not a listed principal');
        if (c.fallback === 'expired') out.prints.unshift('Certificate invalid: expired');
        out.fallback = Boolean(c.fallback);
        return { steps, result: out };
    }

    // ---- View --------------------------------------------------------------

    const MARKS = {
        pass: ['✓', 'passed'],
        fail: ['✗', 'failed'],
        info: ['•', 'continue'],
        fire: ['➜', 'decides'],
        skip: ['–', 'skipped'],
    };

    function knownHostsLines(s) {
        const lines = [];
        if (s.present === 'cert' && s.cert !== 'untrusted') lines.push(`@cert-authority *.example.com ${KEY.ca}`);
        if (s.present === 'cert' && s.cert === 'carevoked') lines.push(`@revoked * ${KEY.ca}`);
        if (s.known === 'match') lines.push(`${HOST} ${KEY.host}`);
        if (s.known === 'changed') lines.push(`${HOST} ${KEY.other}`);
        if (s.known === 'othertype') lines.push(`${HOST} ${KEY.rsa}`);
        if (s.known === 'revoked') lines.push(`@revoked * ${KEY.host}`);
        return lines;
    }

    function presented(s) {
        if (s.present === 'plain') return [`${KEY.host}`, `fingerprint ${FP}`];
        const principal = s.cert === 'principal' ? 'web1.example.com' : HOST;
        const validity = s.cert === 'expired' ? 'from 2020-01-01 to 2020-02-01' : 'forever';
        const ca = s.cert === 'untrusted' ? OTHER_CA_FP : CA_FP;
        return [
            'ssh-ed25519-cert-v01@openssh.com host certificate',
            `key fingerprint ${FP}`,
            `signed by CA ${ca}`,
            `principals: ${principal}`,
            `valid: ${validity}`,
        ];
    }

    SSHWidgets.register('hostkey', (root) => {
        const state = { present: 'plain', cert: 'ok', known: 'none', strict: 'ask', answer: 'yes', krl: false };
        const controls = {};
        const fields = {};

        function select(key, label) {
            const el = h('select', { onchange: () => { state[key] = el.value; update(); } },
                OPTIONS[key].map(([value, text]) => h('option', { value }, text)));
            controls[key] = el;
            fields[key] = field(label, el);
            return fields[key];
        }

        const krl = h('input', { type: 'checkbox', onchange: () => { state.krl = krl.checked; update(); } });
        controls.krl = krl;

        const presets = h('div', { class: 'w-controls hk-presets', role: 'group', 'aria-label': 'Examples' },
            h('span', { class: 'w-note' }, 'Try:'),
            PRESETS.map(([label, preset]) => h('button', {
                type: 'button',
                onclick: () => { Object.assign(state, preset); update(); },
            }, label)));

        const presentedBox = h('pre', { class: 'hk-lines' });
        const knownBox = h('pre', { class: 'hk-lines' });
        const trace = h('ol', { class: 'hk-trace' });
        const verdict = h('p', { class: 'hk-verdict' });
        const prints = h('pre', { class: 'hk-prints' });
        const printsNote = h('p', { class: 'w-note' });
        const khAfter = h('dd');
        const updateKeys = h('dd');
        const security = h('dd');
        const status = h('div', { class: 'w-status' }, verdict,
            h('div', { class: 'hk-sub' }, 'What ssh prints'), prints, printsNote,
            h('dl', { class: 'hk-facts' },
                h('dt', {}, 'known_hosts afterwards'), khAfter,
                h('dt', {}, 'UpdateHostKeys (on by default)'), updateKeys,
                h('dt', {}, 'Security'), security));
        const live = liveRegion();

        root.append(
            h('p', { class: 'w-title' }, `Connecting to ${HOST}: is the host key in the key-exchange reply trusted for this name?`),
            presets,
            h('div', { class: 'w-cols' },
                h('div', {},
                    select('present', 'The server presents'),
                    select('cert', 'The certificate'),
                    select('known', `Plain-key lines for ${HOST} in known_hosts`),
                    select('strict', 'StrictHostKeyChecking'),
                    select('answer', 'At the prompt, the user answers'),
                    h('label', { class: 'hk-check' }, krl, ' The key is listed in the RevokedHostKeys file')),
                h('div', {},
                    h('div', { class: 'hk-sub' }, 'Presented as K_S'), presentedBox,
                    h('div', { class: 'hk-sub' }, 'Relevant known_hosts lines'), knownBox)),
            h('div', { class: 'hk-sub' }, 'Decision path'),
            trace,
            status,
            live);

        function update() {
            for (const key of ['present', 'cert', 'known', 'strict', 'answer']) controls[key].value = state[key];
            krl.checked = state.krl;
            fields.cert.hidden = state.present !== 'cert';
            fields.answer.hidden = state.strict !== 'ask';

            presentedBox.textContent = presented(state).join('\n');
            const lines = knownHostsLines(state);
            knownBox.textContent = lines.length ? lines.join('\n') : `# no line matches ${HOST}`;

            const { steps, result } = decide(state);
            trace.replaceChildren(...steps.map(({ label, state: st, detail }) => h('li', { class: `hk-${st}` },
                h('span', { class: 'hk-mark', 'aria-hidden': 'true' }, MARKS[st][0]),
                h('span', {},
                    h('span', { class: 'w-sr-only' }, `${MARKS[st][1]}: `),
                    h('strong', {}, label), ' ', detail))));

            status.className = `w-status w-${result.tone}`;
            verdict.textContent = result.verdict;
            prints.textContent = result.prints.join('\n');
            printsNote.textContent = result.prints[result.prints.length - 1].startsWith('debug1')
                ? 'Nothing is printed; the debug1 line appears with ssh -v.'
                : (result.prints.includes(UNSAFE[0]) ? UNSAFE_NOTE : '');
            printsNote.hidden = !printsNote.textContent;
            khAfter.replaceChildren(...(result.kh
                ? ['Gains the line ', h('code', {}, `${HOST} ${KEY.host}`),
                    result.fallback ? ': the bare key, not the certificate or its CA.' : '.']
                : ['Unchanged.']));
            updateKeys.textContent = result.update;
            security.textContent = result.security;
            live.say(result.verdict);
        }

        update();
    });
})();
