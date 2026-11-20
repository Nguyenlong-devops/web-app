'use strict';
document.addEventListener('DOMContentLoaded', () => {
    const sidebar=document.getElementById('sidebar'),toggle=document.getElementById('sidebarToggle'),backdrop=document.getElementById('sidebarBackdrop');
    if(!sidebar||!toggle||!backdrop)return;
    const mobile=window.matchMedia('(max-width:768px)');
    const reducedMotion=window.matchMedia('(prefers-reduced-motion:reduce)');
    let motionTimer=null;
    function finishMotion(){
        clearTimeout(motionTimer);
        document.documentElement.classList.remove('sidebar-animating');
        window.dispatchEvent(new Event('sidebar:layout-settled'));
    }
    function beginMotion(){
        clearTimeout(motionTimer);
        if(reducedMotion.matches)return;
        document.documentElement.classList.add('sidebar-animating');
        motionTimer=setTimeout(finishMotion,220);
    }
    sidebar.addEventListener('transitionend',event=>{
        if(event.target===sidebar&&event.propertyName==='width')finishMotion();
    });
    sidebar.querySelectorAll('.nav-item').forEach(item=>{
        const label=item.querySelector('.nav-label')?.textContent.trim()||item.textContent.trim();
        item.title=label;item.setAttribute('aria-label',label);
    });
    for(const selector of ['.sidebar-user','.domain-status']){
        const element=sidebar.querySelector(selector);
        if(element)element.title=element.textContent.trim().replace(/\s+/g,' ');
    }
    function sync(){
        const expanded=mobile.matches?sidebar.classList.contains('open'):!document.documentElement.classList.contains('sidebar-collapsed');
        const label=mobile.matches?(expanded?'Đóng menu':'Mở menu'):(expanded?'Thu gọn menu':'Mở rộng menu');
        toggle.setAttribute('aria-expanded',String(expanded));toggle.setAttribute('aria-label',label);toggle.title=label;
        const overlay=mobile.matches&&expanded;backdrop.hidden=!overlay;document.body.classList.toggle('sidebar-mobile-open',overlay);
        window.dispatchEvent(new Event('resize'));
    }
    function closeMobile(){sidebar.classList.remove('open');sync();}
    toggle.addEventListener('click',()=>{
        if(mobile.matches)sidebar.classList.toggle('open');
        else{
            beginMotion();
            const collapsed=document.documentElement.classList.toggle('sidebar-collapsed');
            try{localStorage.setItem('pv_sidebar_collapsed',collapsed?'1':'0');}catch(_){}
        }
        sync();
    });
    backdrop.addEventListener('click',closeMobile);
    sidebar.addEventListener('click',event=>{if(mobile.matches&&event.target.closest('.nav-item'))closeMobile();});
    document.addEventListener('keydown',event=>{if(event.key==='Escape'&&mobile.matches&&sidebar.classList.contains('open')){closeMobile();toggle.focus({preventScroll:true});}});
    mobile.addEventListener('change',()=>{finishMotion();sidebar.classList.remove('open');sync();});
    sync();
});
