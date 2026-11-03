/**
 * Язык страницы: ставит data-l и lang на <html> и отмечает кнопку.
 * Выбор помнится в localStorage; без него остаётся русский.
 * @param {string} l — 'ru' | 'kk' | 'en'
 */
function setLang(l){
  if(!['ru','kk','en'].includes(l)) l='ru';
  const h=document.documentElement;
  h.dataset.l=l; h.lang=l;
  document.querySelectorAll('.langs button').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.set===l)));
  try{localStorage.setItem('zmk-lang',l);}catch(e){/* хранилище недоступно — язык просто не запомнится */}
}
document.querySelectorAll('.langs button').forEach(b=>b.addEventListener('click',()=>setLang(b.dataset.set)));
try{const s=localStorage.getItem('zmk-lang'); if(s) setLang(s);}catch(e){/* хранилище недоступно — остаётся русский */}

/** Меню на телефоне: открыть/закрыть, закрыть после выбора пункта. */
const burger=document.getElementById('burger'), nav=document.getElementById('nav');
burger.addEventListener('click',()=>{const o=nav.classList.toggle('open'); burger.setAttribute('aria-expanded',String(o));});
nav.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>{nav.classList.remove('open'); burger.setAttribute('aria-expanded','false');}));

/** Кнопки WhatsApp: готовый текст сообщения с выбранным вариантом. */
document.querySelectorAll('a[data-wa]').forEach(a=>{
  const what=a.dataset.wa;
  const text='Здравствуйте! Интересует ZMK'+(what?': '+what:'');
  a.href='https://wa.me/77072669154?text='+encodeURIComponent(text);
  a.target='_blank'; a.rel='noopener';
});

/** Лента разделов: отметить текущую страницу и показать её пункт в ленте. */
(function markCurrent(){
  const here = location.pathname.split('/').pop() || 'sos.html';
  const strip = document.getElementById('nav');
  if (!strip) return;
  const link = [...strip.querySelectorAll('a')].find(a => a.getAttribute('href').split('#')[0] === here);
  if (!link) return;
  link.classList.add('on'); link.setAttribute('aria-current', 'page');
  strip.scrollLeft = Math.max(0, link.offsetLeft - (strip.clientWidth - link.offsetWidth) / 2);
})();

/**
 * Свайп по странице на телефоне: влево — следующий раздел, вправо — предыдущий.
 * Порядок берётся из ленты разделов (только ссылки на страницы, без «Контакты»).
 * Не срабатывает: у краёв экрана (там системный жест «назад»), внутри
 * горизонтально прокручиваемых лент (фото, экраны приложения, сама лента),
 * при двух пальцах, при выделении текста, при открытом меню,
 * а также если жест короткий, медленный или не горизонтальный.
 */
(function swipePages(){
  const strip = document.getElementById('nav');
  if (!strip || !('ontouchstart' in window)) return;
  const pages = [];
  strip.querySelectorAll('a').forEach(a => {
    const p = (a.getAttribute('href') || '').split('#')[0];
    if (p && /\.html$/.test(p) && !pages.includes(p)) pages.push(p);
  });
  const here = location.pathname.split('/').pop() || 'sos.html';
  const idx = pages.indexOf(here);
  if (idx < 0) return;

  const EDGE = 28, MIN_DX = 90, RATIO = 2.2, MAX_MS = 700;
  let s = null;

  /** Есть ли между элементом и страницей своя горизонтальная прокрутка. */
  function inHScroll(el){
    for (; el && el !== document.body; el = el.parentElement) {
      if (el.scrollWidth > el.clientWidth + 2) {
        const ox = getComputedStyle(el).overflowX;
        if (ox === 'auto' || ox === 'scroll') return true;
      }
    }
    return false;
  }

  document.addEventListener('touchstart', e => {
    s = null;
    if (e.touches.length !== 1 || strip.classList.contains('open')) return;
    const t = e.touches[0];
    if (t.clientX < EDGE || t.clientX > innerWidth - EDGE) return;
    if (e.target.closest('input,textarea,select,video,[data-noswipe]') || inHScroll(e.target)) return;
    s = { x: t.clientX, y: t.clientY, t: Date.now() };
  }, { passive: true });

  document.addEventListener('touchmove', e => { if (e.touches.length > 1) s = null; }, { passive: true });

  document.addEventListener('touchend', e => {
    if (!s) return;
    const t = e.changedTouches[0];
    const dx = t.clientX - s.x, dy = t.clientY - s.y, dt = Date.now() - s.t;
    s = null;
    if (dt > MAX_MS || Math.abs(dx) < MIN_DX || Math.abs(dx) < RATIO * Math.abs(dy)) return;
    const sel = window.getSelection && String(window.getSelection());
    if (sel) return;
    const next = idx + (dx < 0 ? 1 : -1);
    if (next < 0 || next >= pages.length) return;
    location.href = pages[next];
  }, { passive: true });
})();
