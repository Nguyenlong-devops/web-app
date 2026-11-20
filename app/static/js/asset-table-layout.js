'use strict';
(() => {
    let queued = false;
    function fit() {
        queued = false;
        const viewport = document.getElementById('assetTableViewport');
        if (!viewport || !viewport.getClientRects().length) return;
        const screenHeight = window.visualViewport?.height || window.innerHeight;
        const height = Math.max(240, Math.floor(screenHeight - viewport.getBoundingClientRect().top - 24));
        const value = height + 'px';
        if (viewport.style.height !== value) viewport.style.height = value;
        const table = document.getElementById('assetTable');
        if (table) {
            // Keep status, username and actions readable; share the remaining width by weight.
            const width = Math.max(1280, viewport.clientWidth);
            table.style.width = width + 'px';
            const columns = Array.from(table.querySelectorAll('col[data-weight]'));
            const fixedColumns = Array.from(table.querySelectorAll('col[data-fixed-width]'));
            const fixedWidth = fixedColumns.reduce((sum, col) => {
                const pixels = Number(col.dataset.fixedWidth);
                col.style.width = pixels + 'px';
                return sum + pixels;
            }, 0) || 156;
            const total = columns.reduce((sum, col) => sum + Number(col.dataset.weight), 0);
            if (total) columns.forEach(col => {
                col.style.width = ((width - fixedWidth) * Number(col.dataset.weight) / total) + 'px';
            });
        }
    }
    function schedule() {
        if (!queued) { queued = true; requestAnimationFrame(fit); }
    }
    document.addEventListener('DOMContentLoaded', () => {
        const section = document.getElementById('section-computers');
        const assets = document.getElementById('tab_panel_assets');
        if (!section || !assets) return;
        window.addEventListener('resize', schedule);
        window.visualViewport?.addEventListener('resize', schedule);
        if (window.ResizeObserver) {
            const observer = new ResizeObserver(schedule);
            section.querySelectorAll('.page-header, .computer-tabs, [data-warranty-alert], #assetBulkBar, #tab_panel_assets > .content-card:not(.asset-table-card)').forEach(el => observer.observe(el));
            const topbar = document.querySelector('.topbar');
            if (topbar) observer.observe(topbar);
        }
        const visibility = new MutationObserver(schedule);
        for (const el of [section, assets]) visibility.observe(el, {attributes: true, attributeFilter: ['class', 'style']});
        schedule();
    });
})();
