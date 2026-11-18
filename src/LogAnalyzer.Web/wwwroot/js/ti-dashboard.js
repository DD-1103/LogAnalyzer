// Threat-intel result page: doughnut of the provider answers around the LogAnalyzer verdict.
// Colours come from the design tokens (--lg-*-rgb), so the chart follows light and dark mode.
(function () {
    'use strict';

    const canvas = document.getElementById('ti-chart');
    const dataEl = document.getElementById('ti-chart-data');
    if (!canvas || !dataEl || typeof Chart === 'undefined') return;

    let data;
    try { data = JSON.parse(dataEl.textContent); } catch { return; }

    const token = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const rgb = (name, alpha) => `rgba(${token(name)}, ${alpha})`;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let chart;
    function build() {
        const slices = [
            { label: 'Malicious', value: data.malicious, color: rgb('--lg-red-rgb', 0.9) },
            { label: 'Suspicious', value: data.suspicious, color: rgb('--lg-orange-rgb', 0.9) },
            { label: 'Benign', value: data.benign, color: rgb('--lg-green-rgb', 0.85) },
            { label: 'No findings', value: data.none, color: rgb('--lg-gray-rgb', 0.45) },
            { label: 'Failed', value: data.failed, color: rgb('--lg-gray-rgb', 0.2) }
        ].filter(s => s.value > 0);
        const empty = slices.length === 0;

        if (chart) chart.destroy();
        chart = new Chart(canvas, {
            type: 'doughnut',
            data: {
                labels: empty ? ['No answers'] : slices.map(s => s.label),
                datasets: [{
                    data: empty ? [1] : slices.map(s => s.value),
                    backgroundColor: empty ? [rgb('--lg-gray-rgb', 0.15)] : slices.map(s => s.color),
                    borderColor: token('--lg-rim-glow') || 'transparent',
                    borderWidth: 2,
                    hoverOffset: empty ? 0 : 6
                }]
            },
            options: {
                cutout: '74%',
                maintainAspectRatio: true,
                animation: reduced ? false : { animateRotate: true, duration: 900 },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        enabled: !empty,
                        callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed} provider(s)` }
                    }
                }
            }
        });
    }

    build();
    document.addEventListener('lg:themechange', build);
})();
