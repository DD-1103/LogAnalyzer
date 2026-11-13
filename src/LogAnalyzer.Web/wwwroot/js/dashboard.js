// Dashboard charts (Chart.js) and attack map (Leaflet).
(function () {
    // Data is embedded as JSON (not executable), so the page needs no inline script (CSP).
    const el = document.getElementById('dashboard-data');
    if (!el) return;
    const data = JSON.parse(el.textContent);

    const severityColors = { Critical: '#dc3545', High: '#ffc107', Medium: '#0dcaf0', Low: '#6c757d' };

    Chart.defaults.color = '#adb5bd';
    Chart.defaults.borderColor = 'rgba(255,255,255,0.08)';
    Chart.defaults.maintainAspectRatio = false;

    const timeline = document.getElementById('chartTimeline');
    if (timeline) {
        new Chart(timeline, {
            type: 'line',
            data: {
                labels: data.hours,
                datasets: [
                    { label: 'All requests', data: data.total, borderColor: '#0d6efd', backgroundColor: 'rgba(13,110,253,0.15)', fill: true, tension: 0.25, pointRadius: 0 },
                    { label: 'Malicious', data: data.malicious, borderColor: '#dc3545', backgroundColor: 'rgba(220,53,69,0.25)', fill: true, tension: 0.25, pointRadius: 0 }
                ]
            },
            options: { interaction: { mode: 'index', intersect: false }, scales: { y: { beginAtZero: true } } }
        });
    }

    const severity = document.getElementById('chartSeverity');
    if (severity) {
        new Chart(severity, {
            type: 'doughnut',
            data: {
                labels: data.severity.map(s => s.name),
                datasets: [{ data: data.severity.map(s => s.count), backgroundColor: data.severity.map(s => severityColors[s.name]), borderWidth: 0 }]
            },
            options: { plugins: { legend: { position: 'bottom' } }, cutout: '60%' }
        });
    }

    const types = document.getElementById('chartTypes');
    if (types) {
        new Chart(types, {
            type: 'bar',
            data: {
                labels: data.types.map(t => t.name),
                datasets: [{ label: 'Malicious requests', data: data.types.map(t => t.count), backgroundColor: '#dc3545' }]
            },
            options: { indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true } } }
        });
    }

    const mapEl = document.getElementById('map');
    if (mapEl) {
        const map = L.map(mapEl, { worldCopyJump: true, scrollWheelZoom: false }).setView([30, 10], 2);
        // Standard OpenStreetMap tiles (no API key); darkened with CSS to match the theme.
        L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors',
            maxZoom: 10,
            className: 'map-tiles-dark'
        }).addTo(map);

        for (const p of data.points) {
            const color = severityColors[p.severity] || '#6c757d';
            const marker = L.circleMarker([p.lat, p.lon], {
                radius: Math.min(6 + p.alerts * 2, 16), color: color, fillColor: color, fillOpacity: 0.6, weight: 1
            }).addTo(map);

            // Build the popup with textContent so values from logs are never interpreted as HTML.
            const box = document.createElement('div');
            const title = document.createElement('strong');
            title.textContent = p.ip;
            const place = document.createElement('div');
            place.textContent = [p.city, p.country].filter(Boolean).join(', ') || 'Unknown location';
            const stats = document.createElement('div');
            stats.textContent = p.alerts + ' alert(s), ' + p.events + ' malicious requests';
            box.append(title, place, stats);
            marker.bindPopup(box);
        }
    }
})();
