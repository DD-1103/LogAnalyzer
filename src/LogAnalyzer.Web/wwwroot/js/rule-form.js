// Shows only the inputs that apply to the selected rule kind (0 Signature / 1 Threshold / 2 Anomaly).
// Hidden inputs are disabled so they are not posted (threshold and anomaly both have a "Threshold" field).
(function () {
    const kind = document.getElementById('Kind');
    if (!kind) return;
    function update() {
        document.querySelectorAll('[data-kind]').forEach(el => {
            const visible = el.getAttribute('data-kind').split(' ').includes(kind.value);
            el.classList.toggle('d-none', !visible);
            el.querySelectorAll('input, select, textarea').forEach(i => { i.disabled = !visible; });
        });
    }
    kind.addEventListener('change', update);
    update();
})();
