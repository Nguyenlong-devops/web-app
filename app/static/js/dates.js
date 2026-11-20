'use strict';
window.DateUI = (() => {
    function toISO(value) {
        const text = String(value || '').trim();
        if (!text) return '';
        let y, m, d, match;
        if ((match = text.match(/^(\d{2})\/(\d{2})\/(\d{4})$/))) [,d,m,y] = match;
        else if ((match = text.match(/^(\d{4})-(\d{2})-(\d{2})$/))) [,y,m,d] = match;
        else throw Error('Nhập ngày theo định dạng DD/MM/YYYY.');
        const check = new Date(`${y}-${m}-${d}T12:00:00Z`);
        if (+y < 1 || isNaN(check) || check.getUTCFullYear() !== +y || check.getUTCMonth()+1 !== +m || check.getUTCDate() !== +d) throw Error('Ngày không hợp lệ. Dùng DD/MM/YYYY.');
        return `${y}-${m}-${d}`;
    }
    function format(value) {
        if (!value) return '';
        try { const [y,m,d] = toISO(value).split('-'); return `${d}/${m}/${y}`; }
        catch (_) { return String(value); }
    }
    function normalize(value) { try { return toISO(value); } catch (_) { return String(value || '').trim(); } }
    function dateTime(value) {
        if (!value) return '—';
        const date = new Date(value);
        if (isNaN(date)) return '—';
        const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', {timeZone:'Asia/Ho_Chi_Minh',day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}).formatToParts(date).map(p=>[p.type,p.value]));
        return `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}:${p.second}`;
    }
    function todayISO() { return toISO(dateTime(new Date()).slice(0,10)); }
    if (typeof document !== 'undefined') document.addEventListener('input',event => {
        if (!event.target.matches('input[data-date]')) return;
        try { toISO(event.target.value); event.target.setCustomValidity(''); }
        catch(error) { event.target.setCustomValidity(error.message); }
    });
    if (typeof document !== 'undefined') document.addEventListener('blur',event => {
        if (event.target.matches('input[data-date]') && event.target.value) {
            try { event.target.value = format(toISO(event.target.value)); } catch (_) { /* Keep invalid text for correction. */ }
        }
    }, true);
    function warranty(value, today = todayISO(), warningDays = 30) {
        if (!value) return {status:'unknown',days:null,label:'Chưa có ngày hết hạn'};
        let expiry, current;
        try { expiry=toISO(value); current=toISO(today); }
        catch (_) { return {status:'unknown',days:null,label:'Ngày hết hạn không hợp lệ'}; }
        const days=Math.round((Date.parse(expiry+'T00:00:00Z')-Date.parse(current+'T00:00:00Z'))/86400000);
        if (days<0) return {status:'expired',days,label:`Đã hết hạn ${-days} ngày`};
        if (days===0) return {status:'due',days,label:'Hết hạn hôm nay'};
        if (days<=warningDays) return {status:'due',days,label:`Sắp hết hạn · còn ${days} ngày`};
        return {status:'valid',days,label:`Còn hạn · ${days} ngày`};
    }
    return {toISO,format,normalize,dateTime,todayISO,warranty};
})();
