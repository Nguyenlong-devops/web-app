'use strict';
(() => {
const $ = id => document.getElementById(id);
const config = JSON.parse($('inventory-config').textContent);
const outcomes = config.outcomes;
const fields = Object.fromEntries(['asset_code','computer_name','device_type','brand','model','cpu','ram','ssd','hdd','os_windows','project','location','status','purchase_date','warranty_expiry_date','notes'].map(k => [k, config.fields[k]]));
const token = document.querySelector('meta[name="csrf-token"]').content;
let round = null, items = [], selected = null, dirty = false, stream = null, scanTimer = null, busy = false;
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const time = value => DateUI.dateTime(value);
function message(text, error = false) {
    $('message').textContent = text; $('message').classList.toggle('error', error); $('message').hidden = false;
}
async function api(path, options = {}) {
    const response = await fetch(path, {...options, headers:{'Accept':'application/json', 'Content-Type':'application/json', 'X-CSRF-Token':token, ...options.headers}});
    if (response.status === 401 || response.redirected) throw Error('Phiên đăng nhập đã hết hạn. Nội dung đang nhập được giữ trên trang; hãy đăng nhập lại trong tab khác rồi thử lưu.');
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.status === 'error') throw Error(data.message || `Không thể xử lý yêu cầu (${response.status}).`);
    return data;
}
const run = fn => async event => { try { await fn(event); } catch (error) { message(error.message, true); } };
async function loadRounds(id) {
    const data = await api('/api/inventory/rounds');
    $('round-select').innerHTML = '<option value="">Chọn đợt kiểm kê…</option>' + data.rounds.map(r => `<option value="${r.id}">${esc(r.name)} · ${r.checked}/${r.total} · ${r.status === 'open' ? 'Đang kiểm kê' : 'Đã đóng'}</option>`).join('');
    if (id) $('round-select').value = String(id);
    if ($('round-select').value) await loadRound();
    else { $('workspace').hidden = true; $('round-info').textContent = data.rounds.length ? 'Chọn một đợt để tiếp tục.' : 'Chưa có đợt. Nhập CSV tại Quản lý Computer rồi tạo đợt đầu tiên.'; }
}
async function loadRound() {
    const id = $('round-select').value;
    if (!id) { round = null; $('workspace').hidden = true; return; }
    const data = await api(`/api/inventory/rounds/${id}/items`);
    round = data.round; items = data.items; localStorage.setItem('inventory_round', id);
    $('workspace').hidden = false;
    $('round-info').textContent = `${round.status === 'open' ? 'Đang kiểm kê' : 'Đã đóng'} · Tạo bởi ${round.created_by} · ${time(round.created_at)} · Phạm vi: ${round.location || 'Tất cả thiết bị'}${round.notes ? ' · ' + round.notes : ''}`;
    const checked = items.filter(i => i.completed).length;
    $('round-select').selectedOptions[0].textContent = `${round.name} · ${checked}/${items.length} · ${round.status === 'open' ? 'Đang kiểm kê' : 'Đã đóng'}`;
    $('total').textContent = items.length; $('checked').textContent = checked; $('remaining').textContent = items.length - checked;
    $('progress').value = items.length ? checked / items.length * 100 : 0;
    $('export').href = `/inventory/rounds/${id}/export.xlsx`;
    $('toggle-round').textContent = round.status === 'open' ? 'Đóng đợt' : 'Mở lại đợt';
    $('history').replaceChildren(); renderItems();
}
function renderItems() {
    const q = $('search').value.trim().toLocaleLowerCase();
    const filter = $('filter').value;
    const list = items.filter(i => {
        const identifiers = [i.observed.computer_name, i.observed.asset_code, i.baseline.computer_name, i.baseline.asset_code];
        return identifiers.some(v => (v || '').toLocaleLowerCase().includes(q)) &&
            (filter === 'all' || filter === 'done' && i.completed || filter === 'pending' && !i.completed ||
             filter === 'changed' && Object.keys(fields).some(k => i.baseline[k] !== i.observed[k]));
    });
    $('result-count').textContent = `${list.length} thiết bị phù hợp / ${items.length} thiết bị trong đợt`;
    $('empty').hidden = list.length !== 0;
    $('device-list').innerHTML = list.map(i => `<article class="device ${i.completed ? 'done' : ''}"><div><h3>${esc(i.observed.computer_name)}</h3><p>${esc(i.observed.asset_code || 'Chưa có mã tài sản')} · ${esc(i.observed.location || 'Chưa có vị trí')}</p><span class="badge">${i.completed ? '✓ Đã kiểm kê' : 'Chưa kiểm kê'}</span>${i.completed ? `<p>${esc(outcomes[i.outcome])} · ${esc(i.completed_by)} · ${time(i.completed_at)}</p>` : ''}</div><button data-item="${i.id}" class="${i.completed ? 'secondary' : ''}">${round.status === 'closed' ? 'Xem' : i.completed ? 'Chỉnh sửa' : 'Kiểm kê'}</button></article>`).join('');
}
async function openItem(id) {
    const data = await api(`/api/inventory/items/${id}`);
    selected = data; dirty = false;
    const i = data.item, values = data.current || i.observed, readonly = data.round.status === 'closed' || !data.current;
    $('editor-title').textContent = i.observed.computer_name;
    $('completion-info').textContent = `${i.completed ? '✓ Hoàn thành bởi ' + i.completed_by + ' · ' + time(i.completed_at) : 'Chưa hoàn thành'} · Cập nhật: ${time(i.updated_at)}${!data.current ? ' · Thiết bị đã xóa khỏi danh mục' : ''}`;
    $('device-fields').innerHTML = Object.entries(fields).map(([key,label]) => `<div class="field-row"><label for="field-${key}">${esc(label)}</label>${key === 'status' ? `<select id="field-${key}" name="${key}" ${readonly ? 'disabled' : ''}><option value="in_use">Đang sử dụng</option><option value="storage">Lưu kho</option></select>` : `<input id="field-${key}" name="${key}" type="text" ${key.endsWith('_date') ? 'data-date placeholder="DD/MM/YYYY" inputmode="text" maxlength="10"' : ''} value="${esc(key.endsWith('_date') ? DateUI.format(values[key]) : values[key])}" ${key === 'computer_name' ? 'required' : ''} ${readonly ? 'disabled' : ''}>`}</div>`).join('');
    $('device-form').elements.status.value = values.status || 'in_use';
    $('device-form').elements.outcome.value = i.outcome;
    $('device-form').elements.note.value = i.note;
    $('device-form').elements.outcome.disabled = readonly;
    $('device-form').elements.note.disabled = data.round.status === 'closed';
    $('baseline').innerHTML = Object.entries(fields).map(([k,label]) => `<dt>${esc(label)}</dt><dd>${esc((k.endsWith('_date') ? DateUI.format(i.baseline[k]) : i.baseline[k]) || 'Chưa có thông tin')}</dd>`).join('');
    $('save-draft').hidden = readonly; $('complete').hidden = readonly || i.completed;
    $('save-draft').textContent = i.completed ? 'Lưu chỉnh sửa' : 'Lưu thay đổi';
    $('reopen').hidden = data.round.status === 'closed' || !i.completed;
    $('editor-error').textContent = ''; $('diff').textContent = '';
    $('editor').showModal();
}
function getValues() { return Object.fromEntries(Object.keys(fields).map(k => [k, k.endsWith('_date') ? DateUI.normalize($('device-form').elements[k].value) : $('device-form').elements[k].value.trim()])); }
function preview() {
    dirty = true;
    const values = getValues(), before = selected.current || selected.item.observed;
    $('diff').textContent = Object.entries(fields).filter(([k]) => values[k] !== before[k]).map(([k,label]) => `${label}: ${(k.endsWith('_date') ? DateUI.format(before[k]) : before[k]) || 'Trống'} → ${(k.endsWith('_date') ? DateUI.format(values[k]) : values[k]) || 'Trống'}`).join('\n') || 'Không thay đổi thông tin thiết bị.';
}
async function save(action) {
    if (busy) return;
    if (action !== 'reopen' && !$('device-form').reportValidity()) return;
    if (action === 'reopen' && !$('device-form').elements.note.value.trim()) { $('editor-error').textContent = 'Nhập lý do trong ghi chú trước khi mở lại.'; return; }
    const payload = {values:getValues(), version:selected.item.version, revision:selected.revision, action,
        outcome:$('device-form').elements.outcome.value, note:$('device-form').elements.note.value};
    busy = true; $('editor-error').textContent = '';
    $('editor').querySelectorAll('button').forEach(b => b.disabled = true);
    try {
        await api(`/api/inventory/items/${selected.item.id}`, {method:'PUT', body:JSON.stringify(payload)});
        dirty = false; $('editor').close();
        message(action === 'complete' ? 'Đã lưu và hoàn thành. Có thể quét máy tiếp theo.' : 'Đã lưu kết quả và lịch sử.');
        await loadRound();
    } catch(error) { $('editor-error').textContent = error.message; }
    finally { busy = false; $('editor').querySelectorAll('button').forEach(b => b.disabled = false); }
}
async function loadHistory() {
    const data = await api(`/api/inventory/rounds/${round.id}/history`);
    const labels = {CREATE:'Tạo đợt',SAVE:'Lưu / chỉnh sửa',COMPLETE:'Hoàn thành',REOPEN:'Mở lại',CLOSE:'Đóng đợt'};
    $('history').innerHTML = data.events.map(e => {
        const diff = e.changes.fields || {};
        let lines = Object.entries(diff).map(([k,v]) => `${fields[k] || k}: ${(k.endsWith('_date') ? DateUI.format(v.before) : v.before) || 'Trống'} → ${(k.endsWith('_date') ? DateUI.format(v.after) : v.after) || 'Trống'}`);
        for (const [k,v] of Object.entries(e.changes.master_fields || {})) {
            if (!diff[k] || diff[k].before !== v.before) lines.push(`Danh mục — ${fields[k] || k}: ${(k.endsWith('_date') ? DateUI.format(v.before) : v.before) || 'Trống'} → ${(k.endsWith('_date') ? DateUI.format(v.after) : v.after) || 'Trống'}`);
        }
        if (e.changes.outcome && e.changes.outcome.before !== e.changes.outcome.after) lines.push(`Kết quả: ${outcomes[e.changes.outcome.before]} → ${outcomes[e.changes.outcome.after]}`);
        return `<article class="event"><strong>${esc(labels[e.action] || e.action)}${e.computer_name ? ' · ' + esc(e.computer_name) : ''}</strong><p class="muted">${esc(e.actor)} · ${time(e.ts)}</p>${lines.map(line => `<p>${esc(line)}</p>`).join('')}${e.note ? `<p>Ghi chú: ${esc(e.note)}</p>` : ''}</article>`;
    }).join('') || '<p class="muted">Chưa có lịch sử.</p>';
}
function stopScanner() {
    clearTimeout(scanTimer); if (stream) stream.getTracks().forEach(track => track.stop());
    stream = null; $('video').srcObject = null;
}
async function startScanner() {
    if (!window.isSecureContext || !navigator.mediaDevices?.getUserMedia) { message('Camera cần HTTPS với chứng chỉ được điện thoại tin cậy. Bạn vẫn có thể nhập tên máy hoặc mã tài sản.', true); return; }
    if (!window.jsQR) { message('Không tải được thư viện đọc QR. Hãy tải lại trang.', true); return; }
    $('scan-error').textContent = ''; $('scanner').showModal();
    try {
        const camera = await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'}},audio:false});
        if (!$('scanner').open) { camera.getTracks().forEach(t => t.stop()); return; }
        stream = camera; $('video').srcObject = stream; await $('video').play();
        const canvas = $('scan-canvas'), ctx = canvas.getContext('2d', {willReadFrequently:true});
        const tick = async () => {
            if (!stream) return;
            try {
                const video = $('video');
                if (video.readyState >= 2 && video.videoWidth) {
                    const scale = Math.min(1, 900 / video.videoWidth);
                    canvas.width = video.videoWidth * scale; canvas.height = video.videoHeight * scale;
                    ctx.drawImage(video,0,0,canvas.width,canvas.height);
                    const pixels = ctx.getImageData(0,0,canvas.width,canvas.height);
                    const code = window.jsQR(pixels.data,canvas.width,canvas.height,{inversionAttempts:'dontInvert'});
                    if (code?.data.trim()) {
                        const value = code.data.trim(); stopScanner(); $('scanner').close();
                        let assetId = null;
                        try {
                            const link = new URL(value);
                            const match = link.pathname.match(/^\/assets\/(\d+)\/?$/);
                            if (link.origin === location.origin && match) assetId = Number(match[1]);
                        } catch (_) { /* Legacy labels contain a plain name or asset code. */ }
                        if (assetId !== null) {
                            const matching = items.filter(i => i.computer_id === assetId);
                            if (matching.length === 1) {
                                $('search').value = matching[0].observed.computer_name;
                                $('filter').value = 'all'; renderItems();
                                await openItem(matching[0].id);
                            } else message('Thiết bị trong QR không thuộc đợt đang chọn.', true);
                            return;
                        }
                        $('search').value = value; $('filter').value = 'all'; renderItems();
                        const exact = items.filter(i => [i.observed.computer_name,i.observed.asset_code,i.baseline.computer_name,i.baseline.asset_code].some(v => v && v.toLowerCase() === value.toLowerCase()));
                        if (exact.length === 1) await openItem(exact[0].id);
                        else message(exact.length ? 'Có nhiều máy trùng tên/mã. Hãy chọn đúng thiết bị trong danh sách.' : 'QR chưa khớp thiết bị trong đợt. Kiểm tra lại tên/mã trong danh sách.', !exact.length);
                        return;
                    }
                }
                scanTimer = setTimeout(tick,180);
            } catch(error) { stopScanner(); $('scan-error').textContent = error.message; }
        };
        tick();
    } catch(error) { stopScanner(); $('scan-error').textContent = 'Không mở được camera. Kiểm tra quyền camera của trình duyệt. ' + error.message; }
}
$('show-create').onclick = () => { $('create-form').hidden = false; $('create-form').elements.name.focus(); };
$('cancel-create').onclick = () => { $('create-form').hidden = true; };
$('create-form').onsubmit = run(async event => {
    event.preventDefault(); const button = event.submitter; button.disabled = true;
    try { const data = await api('/api/inventory/rounds',{method:'POST',body:JSON.stringify(Object.fromEntries(new FormData(event.target)))}); event.target.reset(); event.target.hidden = true; await loadRounds(data.id); message('Đã tạo đợt và chốt danh sách thiết bị.'); }
    finally { button.disabled = false; }
});
$('round-select').onchange = run(loadRound); $('search').oninput = renderItems; $('filter').onchange = renderItems;
$('device-list').onclick = run(async event => { const button = event.target.closest('[data-item]'); if (button) await openItem(button.dataset.item); });
$('device-form').oninput = preview;
$('device-form').onsubmit = event => { event.preventDefault(); save('complete'); };
$('save-draft').onclick = () => save('save'); $('reopen').onclick = () => save('reopen');
function closeEditor(event) { if (busy || dirty && !confirm('Bỏ các thay đổi chưa lưu?')) { event?.preventDefault(); return; } dirty = false; $('editor').close(); }
$('close-editor').onclick = closeEditor; $('editor').addEventListener('cancel',closeEditor);
$('load-history').onclick = run(loadHistory);
$('toggle-round').onclick = run(async () => {
    const next = round.status === 'open' ? 'closed' : 'open';
    const pending = items.filter(i => !i.completed).length;
    const reason = prompt(`${next === 'closed' ? `Đóng đợt (còn ${pending} máy chưa hoàn thành)` : 'Mở lại đợt'} — nhập lý do:`);
    if (!reason?.trim()) return;
    await api(`/api/inventory/rounds/${round.id}/status`,{method:'POST',body:JSON.stringify({status:next,reason,version:round.version})});
    await loadRounds(round.id); message(next === 'closed' ? 'Đã đóng đợt.' : 'Đã mở lại đợt.');
});
$('scan').onclick = run(startScanner); $('stop-scan').onclick = () => { stopScanner(); $('scanner').close(); };
$('scanner').addEventListener('close',stopScanner); $('scanner').addEventListener('cancel',stopScanner);
document.addEventListener('visibilitychange',() => { if (document.hidden) { stopScanner(); $('scanner').close(); } });
window.addEventListener('beforeunload', event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } });
async function startInventory() {
    const params = new URLSearchParams(location.search);
    const roundId = params.get('round_id'), itemId = params.get('item_id');
    if (roundId === null && itemId === null) {
        await loadRounds(localStorage.getItem('inventory_round'));
        return;
    }
    if (!/^[1-9]\d*$/.test(roundId || '') || !/^[1-9]\d*$/.test(itemId || '') ||
        !Number.isSafeInteger(Number(roundId)) || !Number.isSafeInteger(Number(itemId))) {
        await loadRounds();
        throw Error('Liên kết kiểm kê không hợp lệ. Hãy quét lại QR thiết bị.');
    }
    await loadRounds(roundId);
    if (!round || String(round.id) !== roundId) throw Error('Không tìm thấy đợt kiểm kê trong liên kết. Hãy quét lại QR.');
    if (round.status !== 'open') throw Error('Đợt kiểm kê đã đóng. Hãy quay lại thông tin thiết bị để chọn đợt đang mở.');
    const target = items.find(i => String(i.id) === itemId);
    if (!target) throw Error('Thiết bị không thuộc đợt kiểm kê này. Hãy quét lại QR.');
    $('search').value = target.observed.computer_name || target.observed.asset_code || '';
    $('filter').value = 'all'; renderItems();
    await openItem(target.id);
}
startInventory().catch(error => message(error.message,true));
})();
