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

/**
 * Кнопки WhatsApp: готовый текст сообщения с выбранным вариантом (data-wa)
 * и неисправностями, которые посетитель отметил в списке .pick.
 * Ссылки пересчитываются при каждом изменении отметок.
 */
const WA_PHONE = '77072669154';
function waHref(what){
  const faults = [...document.querySelectorAll('.pick input:checked')].map(i => String(i.value).slice(0, 120));
  let text = 'Здравствуйте! Интересует ZMK' + (what ? ': ' + what : '');
  if (faults.length) text += '\nНеисправность: ' + faults.join('; ');
  return 'https://wa.me/' + WA_PHONE + '?text=' + encodeURIComponent(text);
}
function updateWa(){
  document.querySelectorAll('a[data-wa]').forEach(a => { a.href = waHref(a.dataset.wa || ''); });
}
document.querySelectorAll('a[data-wa]').forEach(a => { a.target = '_blank'; a.rel = 'noopener'; });
document.querySelectorAll('.pick input').forEach(i => i.addEventListener('change', updateWa));
updateWa();

/** Лента разделов: отметить текущую страницу и показать её пункт в ленте. */
(function markCurrent(){
  const here = (location.pathname.split('/').pop().replace(/^index\.html$/, '') || 'sos.html');
  const strip = document.getElementById('nav');
  if (!strip) return;
  const link = [...strip.querySelectorAll('a')].find(a => a.getAttribute('href').split('#')[0] === here);
  if (!link) return;
  link.classList.add('on'); link.setAttribute('aria-current', 'page');
  strip.scrollLeft = Math.max(0, link.offsetLeft - (strip.clientWidth - link.offsetWidth) / 2);
})();

/**
 * Перелистывание страниц пальцем с предпросмотром.
 * Страница едет за пальцем, а с края выезжает начало соседней страницы
 * (её первый экран загружается заранее). Отпустили дальше трети экрана
 * или резким движением — открывается соседняя страница, иначе всё
 * возвращается на место. На первой и последней странице — лёгкое «пружинение».
 * Жест не перехватывается: у краёв экрана (системное «назад»), внутри лент
 * с горизонтальной прокруткой, при открытом меню, при двух пальцах,
 * и пока движение больше вертикальное, чем горизонтальное.
 */
(function swipePages(){
  const strip = document.getElementById('nav');
  const main = document.querySelector('main');
  if (!strip || !main || !('ontouchstart' in window)) return;
  const pages = [];
  strip.querySelectorAll('a').forEach(a => {
    const p = (a.getAttribute('href') || '').split('#')[0];
    if (p && /\.html$/.test(p) && !pages.includes(p)) pages.push(p);
  });
  const here = (location.pathname.split('/').pop().replace(/^index\.html$/, '') || 'sos.html');
  const idx = pages.indexOf(here);
  if (idx < 0) return;
  const prev = idx > 0 ? pages[idx - 1] : null, next = idx < pages.length - 1 ? pages[idx + 1] : null;

  /** Первый экран соседней страницы (HTML-строка) — грузится заранее, один раз. */
  const cache = {};
  function prefetch(u){
    if (!u || u in cache) return;
    cache[u] = '';
    fetch(u, {credentials: 'same-origin'}).then(r => r.ok ? r.text() : '').then(html => {
      if (!html) return;
      const d = new DOMParser().parseFromString(html, 'text/html');
      const hero = d.querySelector('main .hero');
      cache[u] = hero ? hero.outerHTML : '';
    }).catch(() => { cache[u] = ''; /* нет сети — будет только сдвиг без предпросмотра */ });
  }
  const idle = window.requestIdleCallback || (f => setTimeout(f, 800));
  idle(() => { prefetch(prev); prefetch(next); });

  const EDGE = 24, LOCK = 12, RATIO = 1.3;
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let s = null, peek = null;

  function inHScroll(el){
    for (; el && el !== document.body; el = el.parentElement) {
      if (el.scrollWidth > el.clientWidth + 2) {
        const ox = getComputedStyle(el).overflowX;
        if (ox === 'auto' || ox === 'scroll') return true;
      }
    }
    return false;
  }
  function headerBottom(){
    const h = document.querySelector('header');
    return h ? Math.max(0, h.getBoundingClientRect().bottom) : 0;
  }
  function makePeek(u, dir){
    removePeek();
    peek = document.createElement('div');
    peek.id = 'peek';
    peek.setAttribute('aria-hidden', 'true');
    peek.style.top = headerBottom() + 'px';
    peek.innerHTML = '<div class="wrap">' + (cache[u] || '') + '</div>';
    // язык предпросмотра — как у текущей страницы
    peek.querySelectorAll('img').forEach(i => { i.loading = 'eager'; });
    peek.dataset.dir = dir;
    document.body.appendChild(peek);
  }
  function removePeek(){ if (peek) { peek.remove(); peek = null; } }
  function setX(x){
    main.style.transform = x ? 'translate3d(' + x + 'px,0,0)' : '';
    if (peek) {
      const w = innerWidth;
      const base = peek.dataset.dir === 'next' ? w : -w;
      peek.style.transform = 'translate3d(' + (base + x) + 'px,0,0)';
    }
  }
  function animateTo(x, done){
    const dur = reduce ? 0 : 220;
    const els = [main, peek].filter(Boolean);
    els.forEach(e => { e.style.transition = 'transform ' + dur + 'ms ease-out'; });
    setX(x);
    setTimeout(() => { els.forEach(e => { e.style.transition = ''; }); done && done(); }, dur + 20);
  }
  function reset(){ main.classList.remove('swiping'); main.style.transition = ''; setX(0); removePeek(); }
  // возврат кнопкой «назад» из кэша браузера — страница должна стоять на месте
  window.addEventListener('pageshow', reset);

  document.addEventListener('touchstart', e => {
    s = null;
    if (e.touches.length !== 1 || strip.classList.contains('open')) return;
    const t = e.touches[0];
    if (t.clientX < EDGE || t.clientX > innerWidth - EDGE) return;
    if (e.target.closest('input,textarea,select,video,summary,[data-noswipe]') || inHScroll(e.target)) return;
    s = { x: t.clientX, y: t.clientY, t: Date.now(), mode: null, dx: 0 };
  }, { passive: true });

  document.addEventListener('touchmove', e => {
    if (!s) return;
    if (e.touches.length > 1) { if (s.mode === 'h') animateTo(0, reset); s = null; return; }
    const t = e.touches[0];
    const dx = t.clientX - s.x, dy = t.clientY - s.y;
    if (!s.mode) {
      if (Math.abs(dx) < LOCK && Math.abs(dy) < LOCK) return;
      if (Math.abs(dx) > RATIO * Math.abs(dy)) {
        s.mode = 'h';
        const target = dx < 0 ? next : prev;
        if (target) makePeek(target, dx < 0 ? 'next' : 'prev');
        main.classList.add('swiping');
      } else { s = null; return; }   // вертикальная прокрутка — не мешаем
    }
    e.preventDefault();
    const target = dx < 0 ? next : prev;
    // сменилось направление — переставить предпросмотр
    if (target && (!peek || peek.dataset.dir !== (dx < 0 ? 'next' : 'prev'))) makePeek(target, dx < 0 ? 'next' : 'prev');
    if (!target) removePeek();
    s.dx = target ? dx : dx * 0.25;    // на краю списка — пружина
    setX(s.dx);
  }, { passive: false });

  function finish(){
    if (!s || s.mode !== 'h') { s = null; return; }
    const dx = s.dx, dt = Math.max(1, Date.now() - s.t);
    const target = dx < 0 ? next : prev;
    const fast = Math.abs(dx) / dt > 0.6 && Math.abs(dx) > 40;
    s = null;
    if (target && (Math.abs(dx) > innerWidth / 3 || fast)) {
      animateTo(dx < 0 ? -innerWidth : innerWidth, () => { location.href = target; });
    } else {
      animateTo(0, reset);
    }
  }
  document.addEventListener('touchend', finish, { passive: true });
  document.addEventListener('touchcancel', () => { if (s && s.mode === 'h') animateTo(0, reset); s = null; }, { passive: true });
})();
