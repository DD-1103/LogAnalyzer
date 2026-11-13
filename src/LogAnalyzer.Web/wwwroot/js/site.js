// Site-wide behaviour. Kept in a file (no inline scripts or on* attributes) so the
// Content-Security-Policy can forbid inline JavaScript.
//   1. Theme: light / dark / auto, with a circular reveal when switching
//   2. Liquid glass: pointer-following light on glass surfaces
//   3. Press ripple on buttons
//   4. Scroll reveal for cards, panels and table rows; count-up numbers
//   5. Navigation: scrolled state, nav badges
//   6. Forms: js-confirm, js-autosubmit
(function () {
    'use strict';

    const root = document.documentElement;
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
    const motion = () => !reducedMotion.matches;

    // ------------------------------------------------------------------ 1. Theme
    const THEME_KEY = 'la-theme';
    const ORDER = ['light', 'dark', 'auto'];
    const LABEL = { light: 'Theme: light', dark: 'Theme: dark', auto: 'Theme: automatic (follows your system)' };

    function storedPref() {
        try {
            const v = localStorage.getItem(THEME_KEY);
            return v === 'light' || v === 'dark' ? v : 'auto';
        } catch { return 'auto'; }
    }

    function resolve(pref) {
        return pref === 'auto' ? (prefersDark.matches ? 'dark' : 'light') : pref;
    }

    function applyTheme(pref) {
        const theme = resolve(pref);
        const changed = root.getAttribute('data-bs-theme') !== theme;
        root.setAttribute('data-bs-theme', theme);
        root.setAttribute('data-theme-pref', pref);
        document.querySelectorAll('.js-theme-toggle').forEach(btn => {
            btn.setAttribute('aria-label', LABEL[pref]);
            btn.setAttribute('title', LABEL[pref]);
        });
        if (changed) document.dispatchEvent(new CustomEvent('lg:themechange', { detail: { theme } }));
    }

    function switchTheme(pref, origin) {
        try { localStorage.setItem(THEME_KEY, pref); } catch { /* private mode */ }
        const willChange = resolve(pref) !== root.getAttribute('data-bs-theme');
        if (!willChange || !document.startViewTransition || !motion() || !origin) {
            applyTheme(pref);
            return;
        }
        // Circular reveal from the toggle button (View Transitions API, Chromium/Safari 18+)
        const r = origin.getBoundingClientRect();
        const x = r.left + r.width / 2;
        const y = r.top + r.height / 2;
        const radius = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
        const transition = document.startViewTransition(() => applyTheme(pref));
        transition.ready.then(() => {
            root.animate(
                { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${radius}px at ${x}px ${y}px)`] },
                { duration: 700, easing: 'cubic-bezier(.2,.8,.2,1)', pseudoElement: '::view-transition-new(root)' });
        }).catch(() => { /* transition skipped */ });
    }

    applyTheme(storedPref());

    document.addEventListener('click', e => {
        const btn = e.target.closest('.js-theme-toggle');
        if (!btn) return;
        const current = storedPref();
        switchTheme(ORDER[(ORDER.indexOf(current) + 1) % ORDER.length], btn);
    });

    prefersDark.addEventListener('change', () => {
        if (storedPref() === 'auto') applyTheme('auto');
    });

    // Other tabs changed the theme
    window.addEventListener('storage', e => {
        if (e.key === THEME_KEY) applyTheme(storedPref());
    });

    // ------------------------------------------------------------------ 2. Liquid glass light
    // The rim and sheen of glass surfaces follow the pointer through --mx / --my.
    const GLASS = '.card, .lg-panel, .lg-glass, .table-responsive';
    let litEl = null;
    let pending = null;

    function paintLight() {
        if (!pending) return;
        const { el, x, y } = pending;
        pending = null;
        const r = el.getBoundingClientRect();
        el.style.setProperty('--mx', `${x - r.left}px`);
        el.style.setProperty('--my', `${y - r.top}px`);
    }

    document.addEventListener('pointermove', e => {
        if (e.pointerType === 'touch') return;
        const el = e.target.closest(GLASS);
        if (el !== litEl) {
            litEl?.classList.remove('lg-lit');
            litEl = el;
            el?.classList.add('lg-lit');
        }
        if (!el) return;
        const first = !pending;
        pending = { el, x: e.clientX, y: e.clientY };
        if (first) requestAnimationFrame(paintLight);
    }, { passive: true });

    document.addEventListener('pointerleave', () => {
        litEl?.classList.remove('lg-lit');
        litEl = null;
    });

    // ------------------------------------------------------------------ 3. Press ripple
    document.addEventListener('pointerdown', e => {
        if (!motion() || e.button !== 0) return;
        const btn = e.target.closest('.btn, .lg-icon-btn');
        if (!btn || btn.disabled || btn.classList.contains('disabled')) return;
        const r = btn.getBoundingClientRect();
        const ripple = document.createElement('span');
        ripple.className = 'lg-ripple';
        ripple.style.left = `${e.clientX - r.left}px`;
        ripple.style.top = `${e.clientY - r.top}px`;
        ripple.style.setProperty('--lg-ripple-scale', String(Math.ceil(Math.hypot(r.width, r.height) / 6)));
        btn.appendChild(ripple);
        ripple.addEventListener('animationend', () => ripple.remove(), { once: true });
        setTimeout(() => ripple.remove(), 1000);
    }, { passive: true });

    // ------------------------------------------------------------------ 4. Scroll reveal + count-up
    const REVEAL = [
        'main .lg-page-header',
        'main .card',
        'main .lg-panel',
        'main .lg-toolbar',
        'main .table-responsive',
        'main .table > tbody > tr',
        'main .list-group-flush > .list-group-item',
        'main > nav[aria-label="breadcrumb"]'
    ].join(',');

    function formatLike(sample, value) {
        // Keep the server's thousands separator (e.g. "2,930" or "2.930")
        const sep = (sample.match(/\d([.,\s  ])\d{3}(?!\d)/) || [])[1];
        const s = Math.round(value).toString();
        return sep ? s.replace(/\B(?=(\d{3})+(?!\d))/g, sep) : s;
    }

    function countUp(el) {
        const text = el.textContent.trim();
        const match = text.match(/^([^\d-]*)(-?[\d.,\s  ]*\d)(.*)$/);
        if (!match) return;
        const digits = match[2].replace(/[^\d-]/g, '');
        const target = Number(digits);
        if (!Number.isFinite(target) || target === 0 || match[2].replace(/[\s  ,]/g, '').includes('.')) return;
        const start = performance.now();
        const duration = Math.min(1600, 600 + Math.log10(Math.abs(target) + 1) * 250);
        const step = now => {
            const t = Math.min(1, (now - start) / duration);
            const eased = 1 - Math.pow(1 - t, 4);
            el.textContent = match[1] + formatLike(match[2], target * eased) + match[3];
            if (t < 1) requestAnimationFrame(step);
            else el.textContent = text;
        };
        requestAnimationFrame(step);
    }

    function setupReveal() {
        const items = Array.from(document.querySelectorAll(REVEAL));
        if (!motion() || !('IntersectionObserver' in window)) return;

        items.forEach(el => el.setAttribute('data-reveal', ''));
        let batch = 0;
        let batchTimer = null;

        const io = new IntersectionObserver(entries => {
            entries.forEach(entry => {
                if (!entry.isIntersecting) return;
                const el = entry.target;
                // Stagger elements that enter together; rows faster than cards
                const step = el.tagName === 'TR' ? 22 : 70;
                el.style.setProperty('--lg-delay', `${Math.min(batch * step, 420)}ms`);
                batch++;
                el.classList.add('is-in');
                io.unobserve(el);
                el.querySelectorAll('[data-countup]').forEach(countUp);
                if (el.matches('[data-countup]')) countUp(el);
                // Drop the delay once shown so hover transitions stay instant
                setTimeout(() => el.style.removeProperty('--lg-delay'), 1400);
            });
            clearTimeout(batchTimer);
            batchTimer = setTimeout(() => { batch = 0; }, 120);
        }, { rootMargin: '0px 0px -6% 0px', threshold: 0.06 });

        items.forEach(el => io.observe(el));

        // Count-up numbers that are not inside a revealed element
        document.querySelectorAll('[data-countup]').forEach(el => {
            if (!el.closest('[data-reveal]')) countUp(el);
        });
    }

    // ------------------------------------------------------------------ 5. Navigation
    let scrollQueued = false;
    function onScroll() {
        if (scrollQueued) return;
        scrollQueued = true;
        requestAnimationFrame(() => {
            scrollQueued = false;
            const y = window.scrollY;
            root.classList.toggle('lg-scrolled', y > 8);
            if (motion()) root.style.setProperty('--lg-scroll', String(Math.round(y)));
        });
    }
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();

    function setupNavBadges() {
        const url = document.body.getAttribute('data-navcounts');
        if (!url) return;

        function setBadge(id, value, prefix) {
            const badge = document.getElementById(id);
            if (!badge) return;
            badge.querySelector('.count').textContent = value > 0 ? prefix + value : '';
            badge.classList.toggle('d-none', !(value > 0));
        }

        async function refresh() {
            try {
                const res = await fetch(url, { headers: { 'Accept': 'application/json' }, cache: 'no-store' });
                if (!res.ok) return;
                const c = await res.json();
                setBadge('badge-files', c.processing, '');
                setBadge('badge-alerts', c.newAlerts, '+');
                setBadge('badge-rules', c.firingRules, '+');
            } catch { /* offline or session expired: keep the last values */ }
        }

        refresh();
        setInterval(refresh, 10000);
    }

    // ------------------------------------------------------------------ 6. Forms
    // <form class="js-confirm" data-confirm="Question?"> asks before submitting.
    document.addEventListener('submit', e => {
        const form = e.target.closest('form.js-confirm');
        if (form && !window.confirm(form.getAttribute('data-confirm') || 'Are you sure?')) {
            e.preventDefault();
        }
    });

    // <select class="js-autosubmit"> submits its form when the value changes.
    document.addEventListener('change', e => {
        if (e.target.matches('select.js-autosubmit')) {
            e.target.form.submit();
        }
    });

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => { setupReveal(); setupNavBadges(); });
    } else {
        setupReveal();
        setupNavBadges();
    }
})();
