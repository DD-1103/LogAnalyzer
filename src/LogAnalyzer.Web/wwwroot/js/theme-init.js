// Runs synchronously in <head> before the page paints, so there is no flash of the wrong theme.
// Preference is stored per browser: "light", "dark" or "auto" (follow the operating system).
(function () {
    var root = document.documentElement;
    var pref = 'auto';
    try { pref = localStorage.getItem('la-theme') || 'auto'; } catch (e) { /* storage blocked */ }
    if (pref !== 'light' && pref !== 'dark') pref = 'auto';
    var dark = pref === 'dark' || (pref === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    root.setAttribute('data-bs-theme', dark ? 'dark' : 'light');
    root.setAttribute('data-theme-pref', pref);
    if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) root.classList.add('lg-motion');
})();
