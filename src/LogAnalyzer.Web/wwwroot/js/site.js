// Site-wide behaviour. Kept in a file (no inline scripts or on* attributes) so the
// Content-Security-Policy can forbid inline JavaScript.
(function () {
    // <form class="js-confirm" data-confirm="Question?"> asks before submitting.
    document.addEventListener('submit', function (e) {
        const form = e.target.closest('form.js-confirm');
        if (form && !window.confirm(form.getAttribute('data-confirm') || 'Are you sure?')) {
            e.preventDefault();
        }
    });

    // <select class="js-autosubmit"> submits its form when the value changes.
    document.addEventListener('change', function (e) {
        if (e.target.matches('select.js-autosubmit')) {
            e.target.form.submit();
        }
    });

    // Navigation badges (files processing, new alerts, rules that fired), refreshed every 10 s.
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
})();
