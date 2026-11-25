// Dashboard charts (Chart.js) and attack map (Leaflet).
// Colours come from the Liquid Glass CSS tokens, so the charts follow the light / dark theme
// and are rebuilt when site.js announces a theme change (event "lg:themechange").
(function () {
    // Data is embedded as JSON (not executable), so the page needs no inline script (CSP).
    const el = document.getElementById('dashboard-data');
    if (!el || typeof Chart === 'undefined') return;
    const data = JSON.parse(el.textContent);
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const rgb = (name, a) => `rgba(${css(name)}, ${a === undefined ? 1 : a})`;

    function palette() {
        return {
            text: css('--lg-text-2'),
            grid: css('--lg-hairline'),
            surface: css('--lg-surface-strong'),
            textStrong: css('--lg-text'),
            accent: name => rgb('--lg-accent-rgb', name),
            red: a => rgb('--lg-red-rgb', a),
            severity: {
                Critical: rgb('--lg-red-rgb'),
                High: rgb('--lg-orange-rgb'),
                Medium: rgb('--lg-teal-rgb'),
                Low: rgb('--lg-gray-rgb')
            }
        };
    }

    // Vertical gradient fill under a line, recomputed when the chart area changes
    function gradient(ctx, area, top, bottom) {
        const g = ctx.createLinearGradient(0, area.top, 0, area.bottom);
        g.addColorStop(0, top);
        g.addColorStop(1, bottom);
        return g;
    }

    const charts = [];

    function applyDefaults(p) {
        Chart.defaults.color = p.text;
        Chart.defaults.borderColor = p.grid;
        Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
        Chart.defaults.maintainAspectRatio = false;
        // Modify the existing defaults object: replacing it breaks Chart.js' option resolver (nothing draws)
        Chart.defaults.animation.duration = reduced ? 0 : 900;
        Chart.defaults.animation.easing = 'easeOutQuart';
        Chart.defaults.plugins.tooltip.backgroundColor = p.surface;
        Chart.defaults.plugins.tooltip.titleColor = p.textStrong;
        Chart.defaults.plugins.tooltip.bodyColor = p.textStrong;
        Chart.defaults.plugins.tooltip.borderColor = p.grid;
        Chart.defaults.plugins.tooltip.borderWidth = 1;
        Chart.defaults.plugins.tooltip.padding = 10;
        Chart.defaults.plugins.tooltip.cornerRadius = 12;
        Chart.defaults.plugins.tooltip.boxPadding = 4;
        // Legends in full-strength text and semibold: readable on a projector in both themes
        Chart.defaults.font.size = 12.5;
        Chart.defaults.plugins.legend.labels.color = p.textStrong;
        Chart.defaults.plugins.legend.labels.font = { weight: '600' };
        Chart.defaults.plugins.legend.labels.usePointStyle = true;
        Chart.defaults.plugins.legend.labels.pointStyle = 'circle';
        Chart.defaults.plugins.legend.labels.boxWidth = 8;
        Chart.defaults.plugins.legend.labels.boxHeight = 8;
    }

    function build() {
        charts.splice(0).forEach(c => c.destroy());
        const p = palette();
        applyDefaults(p);

        const timeline = document.getElementById('chartTimeline');
        if (timeline) {
            charts.push(new Chart(timeline, {
                type: 'line',
                data: {
                    labels: data.hours,
                    datasets: [
                        {
                            label: 'All events', data: data.total, borderColor: p.accent(1), borderWidth: 2,
                            backgroundColor: c => c.chart.chartArea ? gradient(c.chart.ctx, c.chart.chartArea, p.accent(.32), p.accent(0)) : p.accent(.15),
                            fill: true, tension: 0.35, pointRadius: 0, pointHoverRadius: 5, pointHoverBackgroundColor: p.accent(1)
                        },
                        {
                            label: 'Malicious', data: data.malicious, borderColor: p.red(1), borderWidth: 2,
                            backgroundColor: c => c.chart.chartArea ? gradient(c.chart.ctx, c.chart.chartArea, p.red(.38), p.red(0)) : p.red(.2),
                            fill: true, tension: 0.35, pointRadius: 0, pointHoverRadius: 5, pointHoverBackgroundColor: p.red(1)
                        }
                    ]
                },
                options: {
                    interaction: { mode: 'index', intersect: false },
                    plugins: { legend: { align: 'end' } },
                    scales: {
                        x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkipPadding: 18 } },
                        y: { beginAtZero: true, border: { display: false }, grid: { color: p.grid } }
                    }
                }
            }));
        }

        const severity = document.getElementById('chartSeverity');
        if (severity) {
            charts.push(new Chart(severity, {
                type: 'doughnut',
                data: {
                    labels: data.severity.map(s => s.name),
                    datasets: [{
                        data: data.severity.map(s => s.count),
                        backgroundColor: data.severity.map(s => p.severity[s.name] || p.severity.Low),
                        borderWidth: 0,
                        borderRadius: 6,
                        spacing: 3,
                        hoverOffset: 8
                    }]
                },
                options: { plugins: { legend: { position: 'bottom' } }, cutout: '68%' }
            }));
        }

        const types = document.getElementById('chartTypes');
        if (types) {
            charts.push(new Chart(types, {
                type: 'bar',
                data: {
                    labels: data.types.map(t => t.name),
                    datasets: [{
                        label: 'Malicious events',
                        data: data.types.map(t => t.count),
                        backgroundColor: c => c.chart.chartArea
                            ? (() => {
                                const g = c.chart.ctx.createLinearGradient(c.chart.chartArea.left, 0, c.chart.chartArea.right, 0);
                                g.addColorStop(0, p.red(.55));
                                g.addColorStop(1, p.red(.95));
                                return g;
                            })()
                            : p.red(.8),
                        borderRadius: 8,
                        borderSkipped: false,
                        maxBarThickness: 22
                    }]
                },
                options: {
                    indexAxis: 'y',
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { beginAtZero: true, border: { display: false }, grid: { color: p.grid } },
                        y: { grid: { display: false }, border: { display: false } }
                    }
                }
            }));
        }
    }

    build();
    document.addEventListener('lg:themechange', build);

    // ---------------------------------------------------------------- Attack map
    const mapEl = document.getElementById('map');
    if (mapEl && typeof L !== 'undefined') {
        const map = L.map(mapEl, { worldCopyJump: true, scrollWheelZoom: false }).setView([30, 10], 2);
        // Standard OpenStreetMap tiles (no API key); filtered with CSS per theme (site.css).
        L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors',
            maxZoom: 10,
            className: 'map-tiles-dark'
        }).addTo(map);

        const markers = [];
        function colorFor(severityName) {
            const p = palette();
            return p.severity[severityName] || p.severity.Low;
        }

        for (const pt of data.points) {
            const color = colorFor(pt.severity);
            const marker = L.circleMarker([pt.lat, pt.lon], {
                radius: Math.min(6 + pt.alerts * 2, 16), color: color, fillColor: color, fillOpacity: 0.55, weight: 2
            }).addTo(map);
            markers.push({ marker, severity: pt.severity });

            // Build the popup with textContent so values from logs are never interpreted as HTML.
            const box = document.createElement('div');
            const title = document.createElement('strong');
            title.textContent = pt.ip;
            const place = document.createElement('div');
            place.textContent = [pt.city, pt.country].filter(Boolean).join(', ') || 'Unknown location';
            const stats = document.createElement('div');
            stats.textContent = pt.alerts + ' alert(s), ' + pt.events + ' malicious events';
            box.append(title, place, stats);
            marker.bindPopup(box);
        }

        document.addEventListener('lg:themechange', () => {
            markers.forEach(m => {
                const c = colorFor(m.severity);
                m.marker.setStyle({ color: c, fillColor: c });
            });
        });

        // The map is created while its card may still be animating in: fix the tile layout once visible
        setTimeout(() => map.invalidateSize(), 900);
    }
})();
