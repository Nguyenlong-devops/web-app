'use strict';
(() => {
    let trigger = null;
    window.openAssetQrModal = (id, button) => {
        const cid = Number(id);
        if (!Number.isSafeInteger(cid) || cid < 1) return;
        const dialog = document.getElementById('assetQrDialog');
        const frame = document.getElementById('assetQrFrame');
        const status = document.getElementById('assetQrStatus');
        trigger = button || document.activeElement;
        status.textContent = 'Đang tải mã QR…';
        status.classList.remove('error'); status.hidden = false; frame.hidden = true;
        frame.dataset.expectedPath = `/assets/${cid}/qr`;
        frame.src = frame.dataset.expectedPath + '?embedded=1';
        if (!dialog.open) dialog.showModal();
    };
    window.closeAssetQrModal = () => document.getElementById('assetQrDialog').close();
    document.addEventListener('DOMContentLoaded', () => {
        const dialog = document.getElementById('assetQrDialog');
        if (!dialog) return;
        const frame = document.getElementById('assetQrFrame');
        const status = document.getElementById('assetQrStatus');
        frame.addEventListener('load', () => {
            if (!dialog.open) return;
            try {
                const url = frame.contentWindow.location;
                if (url.href === 'about:blank') return;
                if (url.pathname === '/login' || url.pathname === '/connect-domain') throw Error('Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại rồi mở QR.');
                if (url.pathname !== frame.dataset.expectedPath) return;
                const image = frame.contentDocument.querySelector('[data-qr-page] .label img');
                if (!image || !image.complete || !image.naturalWidth) throw Error('Không tải được QR thiết bị. Vui lòng đóng pop-up và thử lại.');
                status.hidden = true; frame.hidden = false;
            } catch(error) {
                status.textContent = error.name === 'SecurityError' ? 'Không tải được trang QR. Vui lòng kiểm tra kết nối, đăng nhập lại rồi thử lại.' : error.message;
                status.classList.add('error'); status.hidden = false; frame.hidden = true;
            }
        });
        dialog.addEventListener('close', () => {
            // A queued close event must not clear a QR opened immediately afterward.
            if (dialog.open) return;
            frame.hidden = true; delete frame.dataset.expectedPath; frame.src = 'about:blank';
            if (trigger?.isConnected) trigger.focus({preventScroll:true});
            trigger = null;
        });
        dialog.addEventListener('click', event => {
            if (event.target !== dialog) return;
            const rect = dialog.getBoundingClientRect();
            if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) dialog.close();
        });
    });
})();
