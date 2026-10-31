// Dashboard Interactions and Dynamic Table Filtering

document.addEventListener('DOMContentLoaded', () => {
    // Quick target presets on Index page
    const presetBtns = document.querySelectorAll('.target-preset-btn');
    const targetInput = document.getElementById('target_url');
    const scanModeInput = document.getElementById('scan_mode');

    if (presetBtns && targetInput) {
        presetBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                targetInput.value = btn.getAttribute('data-url');
                if (scanModeInput && btn.getAttribute('data-mode')) {
                    scanModeInput.value = btn.getAttribute('data-mode');
                }
            });
        });
    }

    // Findings Table Search & Severity Filter (Results Page)
    const searchInput = document.getElementById('findingsSearch');
    const severityFilter = document.getElementById('severityFilter');
    const findingsRows = document.querySelectorAll('.finding-row');

    function filterFindings() {
        if (!findingsRows.length) return;
        const query = (searchInput ? searchInput.value : '').toLowerCase().trim();
        const selectedSev = (severityFilter ? severityFilter.value : 'all').toLowerCase();

        findingsRows.forEach(row => {
            const title = (row.getAttribute('data-title') || '').toLowerCase();
            const category = (row.getAttribute('data-category') || '').toLowerCase();
            const cwe = (row.getAttribute('data-cwe') || '').toLowerCase();
            const sev = (row.getAttribute('data-severity') || '').toLowerCase();

            const matchesQuery = !query || title.includes(query) || category.includes(query) || cwe.includes(query);
            const matchesSev = selectedSev === 'all' || sev === selectedSev;

            if (matchesQuery && matchesSev) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    if (searchInput) searchInput.addEventListener('input', filterFindings);
    if (severityFilter) severityFilter.addEventListener('change', filterFindings);
});
