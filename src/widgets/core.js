// Shared runtime for the guide's interactive figures.
//
// A chapter embeds a figure with
//
//   <div class="ssh-widget" data-widget="NAME" data-option="value">
//   <p class="w-fallback">What the figure shows, for readers without JavaScript.</p>
//   </div>
//
// This script is loaded on every page (see theme/head.hbs). For each
// [data-widget] element it loads widgets/NAME.css and widgets/NAME.js once,
// and then calls the mount function that NAME.js registered:
//
//   SSHWidgets.register('NAME', (root, config) => { ... });
//
// `config` holds the element's data-* attributes, merged with the JSON from an
// optional <script type="application/json"> child. The runtime has no
// dependencies and works offline.
(() => {
    'use strict';

    const base = document.currentScript.src.replace(/core\.js(?:[?#].*)?$/, '');
    const mounts = new Map();
    const waiting = new Map();
    const loading = new Map();

    function register(name, mount) {
        mounts.set(name, mount);
        const resolve = waiting.get(name);
        if (resolve) {
            waiting.delete(name);
            resolve(mount);
        }
    }

    function load(name) {
        if (mounts.has(name)) return Promise.resolve(mounts.get(name));
        if (loading.has(name)) return loading.get(name);
        const promise = new Promise((resolve, reject) => {
            waiting.set(name, resolve);
            const css = document.createElement('link');
            css.rel = 'stylesheet';
            css.href = `${base}${name}.css`;
            document.head.appendChild(css);
            const js = document.createElement('script');
            js.src = `${base}${name}.js`;
            js.onerror = () => reject(new Error(`could not load widget “${name}”`));
            document.head.appendChild(js);
        });
        loading.set(name, promise);
        return promise;
    }

    function readConfig(root) {
        const config = { ...root.dataset };
        delete config.widget;
        const json = root.querySelector(':scope > script[type="application/json"]');
        if (json) Object.assign(config, JSON.parse(json.textContent));
        return config;
    }

    async function mountOne(root) {
        if (root.dataset.mounted) return;
        root.dataset.mounted = 'true';
        const name = root.dataset.widget;
        try {
            const mount = await load(name);
            const config = readConfig(root);
            root.replaceChildren();
            root.classList.add('ssh-widget', `w-${name}`);
            mount(root, config);
        } catch (error) {
            console.error(error);
            root.append(h('p', { class: 'w-status w-bad' }, `Interactive figure failed to load: ${error.message}`));
        }
    }

    function mountAll(scope = document) {
        scope.querySelectorAll('[data-widget]').forEach(mountOne);
    }

    // ---- DOM helpers -------------------------------------------------------

    // h('button', { class: 'x', onclick: fn, 'aria-label': 'y' }, 'text', node, [more])
    function h(tag, props, ...children) {
        const el = document.createElement(tag);
        for (const [key, value] of Object.entries(props || {})) {
            if (value == null || value === false) continue;
            if (key.startsWith('on') && typeof value === 'function') {
                el.addEventListener(key.slice(2), value);
            } else if (key === 'style' && typeof value === 'object') {
                Object.assign(el.style, value);
            } else if (key === 'dataset') {
                Object.assign(el.dataset, value);
            } else if (key in el && typeof value !== 'string') {
                el[key] = value; // value, checked, disabled, …
            } else {
                el.setAttribute(key, value === true ? '' : value);
            }
        }
        append(el, children);
        return el;
    }

    function append(el, children) {
        for (const child of children.flat(Infinity)) {
            if (child == null || child === false) continue;
            el.append(child instanceof Node ? child : String(child));
        }
        return el;
    }

    let nextId = 0;
    function uid(prefix = 'w') {
        nextId += 1;
        return `${prefix}-${nextId}`;
    }

    // A labelled form control: field('Client list', input).
    function field(label, control, hint) {
        if (!control.id) control.id = uid('field');
        return h('div', { class: 'w-field' },
            h('label', { for: control.id }, label),
            control,
            hint ? h('div', { class: 'w-hint' }, hint) : null);
    }

    // A polite screen-reader announcement area; call .say(text) to update it.
    function liveRegion() {
        const el = h('div', { class: 'w-sr-only', 'aria-live': 'polite' });
        el.say = (text) => { el.textContent = text; };
        return el;
    }

    // Step-through controls. render(index) is called with 0 ≤ index < count.
    // Returns { el, go(index), next(), back(), index }.
    function stepper({ count, render, label = 'Step' }) {
        let index = 0;
        const counter = h('span', { class: 'w-counter', 'aria-live': 'polite' });
        const reset = h('button', { type: 'button', onclick: () => go(0) }, '⏮ Reset');
        const back = h('button', { type: 'button', onclick: () => go(index - 1) }, '◀ Back');
        const next = h('button', { type: 'button', class: 'w-primary', onclick: () => go(index + 1) }, 'Next ▶');
        const el = h('div', { class: 'w-controls w-stepper' }, reset, back, next, counter);
        el.addEventListener('keydown', (event) => {
            if (event.key === 'ArrowRight') { go(index + 1); event.preventDefault(); }
            if (event.key === 'ArrowLeft') { go(index - 1); event.preventDefault(); }
        });
        function go(i) {
            index = Math.max(0, Math.min(count - 1, i));
            reset.disabled = back.disabled = index === 0;
            next.disabled = index === count - 1;
            counter.textContent = `${label} ${index + 1} of ${count}`;
            api.index = index;
            render(index);
        }
        const api = { el, go, next: () => go(index + 1), back: () => go(index - 1), index };
        return api;
    }

    // ---- Byte and wire-format helpers --------------------------------------

    const encoder = new TextEncoder();

    function utf8(text) {
        return encoder.encode(text);
    }

    function concat(...parts) {
        const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
        let offset = 0;
        for (const part of parts) {
            out.set(part, offset);
            offset += part.length;
        }
        return out;
    }

    function toHex(bytes, separator = ' ') {
        return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(separator);
    }

    function fromHex(text) {
        const clean = text.replace(/[^0-9a-f]/gi, '');
        if (clean.length % 2) throw new Error('odd number of hex digits');
        return Uint8Array.from(clean.match(/../g) || [], (pair) => parseInt(pair, 16));
    }

    function u32(n) {
        return Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
    }

    // RFC 4251 string: uint32 length followed by the bytes.
    function sshString(value) {
        const bytes = typeof value === 'string' ? utf8(value) : value;
        return concat(u32(bytes.length), bytes);
    }

    // RFC 4251 name-list: a string of comma-separated names.
    function nameList(names) {
        return sshString(names.join(','));
    }

    // RFC 4251 mpint for a non-negative BigInt: two's complement, big-endian,
    // minimal length, with a leading zero byte when the top bit is set.
    function mpint(value) {
        if (value < 0n) throw new Error('mpint helper only encodes non-negative values');
        if (value === 0n) return u32(0);
        let hex = value.toString(16);
        if (hex.length % 2) hex = `0${hex}`;
        let bytes = fromHex(hex);
        if (bytes[0] & 0x80) bytes = concat(Uint8Array.of(0), bytes);
        return sshString(bytes);
    }

    // ---- Arithmetic and hashing --------------------------------------------

    function modPow(base_, exponent, modulus) {
        let result = 1n;
        let b = ((base_ % modulus) + modulus) % modulus;
        let e = exponent;
        while (e > 0n) {
            if (e & 1n) result = (result * b) % modulus;
            b = (b * b) % modulus;
            e >>= 1n;
        }
        return result;
    }

    // SHA-256 via Web Crypto. Resolves to a Uint8Array.
    async function sha256(bytes) {
        if (!globalThis.crypto || !crypto.subtle) {
            throw new Error('Web Crypto is unavailable; open the guide over https or localhost');
        }
        return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    }

    window.SSHWidgets = {
        register, mountAll, h, append, uid, field, liveRegion, stepper,
        utf8, concat, toHex, fromHex, u32, sshString, nameList, mpint,
        modPow, sha256,
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => mountAll());
    } else {
        mountAll();
    }
})();
