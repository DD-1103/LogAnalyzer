// Rule form: shows only the inputs that apply to the chosen log kind (AppliesTo: 0 web access / 1 firewall) and
// rule kind (Kind: 0 Signature / 1 Threshold / 2 Anomaly / 3 Distinct count).
// - data-show="w0 f1 ..." on an element = the combinations it belongs to (w = web, f = firewall + kind number).
//   Hidden inputs are disabled so they are not posted (several inputs share the name "Threshold").
// - data-sources="0 1" on an <option> = the log kinds it is offered for (rule kinds, fields, test log files).
(function () {
    const kind = document.getElementById('Kind');
    const source = document.getElementById('AppliesTo');
    if (!kind || !source) return;
    const field = document.getElementById('Field');
    const testFile = document.getElementById('TestLogFileId');
    const testPicker = document.getElementById('TestPicker');
    const noTestFiles = document.getElementById('NoTestFiles');

    // Hides and disables the options that do not belong to the log kind; keeps (or picks) a valid choice.
    function filterOptions(select, src) {
        if (!select) return 0;
        let count = 0;
        let first = null;
        Array.from(select.options).forEach(o => {
            const list = o.getAttribute('data-sources');
            const ok = list === null || list.split(' ').includes(src);
            o.hidden = !ok;
            o.disabled = !ok;
            if (ok) {
                count++;
                if (!first) first = o;
            }
        });
        const current = select.options[select.selectedIndex];
        if (!current || current.disabled) {
            if (first) first.selected = true;
            else select.selectedIndex = -1;
        }
        return count;
    }

    function update() {
        const src = source.value === '1' ? '1' : '0';
        filterOptions(kind, src); // e.g. Anomaly is web only, Distinct count firewall only
        filterOptions(field, src);
        const token = (src === '1' ? 'f' : 'w') + kind.value;

        document.querySelectorAll('[data-show]').forEach(el => {
            const visible = el.getAttribute('data-show').split(' ').includes(token);
            el.classList.toggle('d-none', !visible);
            // Only top-level groups switch inputs; nested data-show elements are help texts without inputs.
            if (el.parentElement && el.parentElement.closest('[data-show]')) return;
            el.querySelectorAll('input, select, textarea').forEach(i => { i.disabled = !visible; });
        });

        if (testFile) {
            const files = filterOptions(testFile, src);
            if (testPicker) testPicker.classList.toggle('d-none', files === 0);
            if (noTestFiles) noTestFiles.classList.toggle('d-none', files !== 0);
        } else if (noTestFiles) {
            noTestFiles.classList.remove('d-none');
        }
    }

    kind.addEventListener('change', update);
    source.addEventListener('change', update);
    update();
})();
