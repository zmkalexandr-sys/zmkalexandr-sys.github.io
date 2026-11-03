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
