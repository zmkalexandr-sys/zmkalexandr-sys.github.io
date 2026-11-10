/**
 * @file z.js — экран страницы ссылок ZMK (/z/).
 *
 * «#g…» — пропуск гостя или курьера: кнопка «Открыть» по Bluetooth прямо из
 * Chrome на Android (обмен — zmk-guest.js). Остальное — «Скопировать ссылку»
 * для приложения ZMK.
 *
 * Ключ телефона гостя создаётся при первом заходе и хранится в IndexedDB
 * (неизвлекаемый CryptoKey). Хранилище не работает (инкогнито, запрет) —
 * кнопка не включается: иначе первое открытие «сожгло» бы ссылку ключом,
 * который пропадёт с закрытием вкладки.
 */
(function () {
  'use strict';
  const G = window.ZmkGuest;
  const $ = (id) => document.getElementById(id);
  const DB_NAME = 'zmk-guest';
  const DB_STORE = 'keys';
  const KEEP_AFTER_S = 7 * 86400; // ключ живёт неделю после конца пропуска — и стирается

  /** Текст и вид строки состояния. @param {string} cls '', 'ok', 'bad', 'warn' */
  function state(text, cls) {
    const s = $('gstate');
    s.className = 'state' + (cls ? ' ' + cls : '');
    s.textContent = text;
  }

  // ── Копирование ссылки (общая часть) ────────────────────────────────────
  /**
   * Копирует адрес страницы целиком. Запасной путь — выделение текста.
   * @param {function(boolean): void} done
   */
  function copyLink(done) {
    const link = location.href;
    const fallback = () => {
      const raw = $('raw');
      try {
        raw.value = link;
        raw.select();
        raw.setSelectionRange(0, link.length);
        done(document.execCommand('copy'));
      } catch (e) {
        console.warn('[ZMK] копирование не вышло:', e && e.name);
        done(false);
      }
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(link).then(() => done(true), fallback);
    } else {
      fallback();
    }
  }

  /** Ссылки для приложения: «Скопировать ссылку». */
  function copyMain() {
    const msg = $('msg');
    const btn = $('copy');
    if (!location.hash || location.hash.length < 2) {
      btn.disabled = true;
      msg.className = 'note bad';
      msg.textContent = 'Ссылка неполная — попросите прислать её заново целиком.';
      return;
    }
    btn.addEventListener('click', () =>
      copyLink((ok) => {
        msg.className = ok ? 'note ok' : 'note bad';
        msg.textContent = ok
          ? 'Скопировано. Теперь откройте ZMK → «Добавить устройство» → «Есть ссылка ZMK» → «Вставить».'
          : 'Не удалось скопировать. Нажмите и удерживайте адрес в строке браузера → «Копировать».';
      }),
    );
  }

  // ── Хранилище ключей (IndexedDB) ────────────────────────────────────────
  /** @returns {Promise<IDBDatabase>} */
  function dbOpen() {
    return new Promise((resolve, reject) => {
      if (!window.indexedDB) {
        reject(new Error('IndexedDB нет'));
        return;
      }
      const r = indexedDB.open(DB_NAME, 1);
      r.onupgradeneeded = () => r.result.createObjectStore(DB_STORE);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error || new Error('IndexedDB не открылась'));
      r.onblocked = () => reject(new Error('IndexedDB занята другой вкладкой'));
    });
  }

  /**
   * Одна операция с хранилищем.
   * @param {IDBDatabase} db @param {'readonly'|'readwrite'} mode
   * @param {function(IDBObjectStore): IDBRequest} op
   */
  function dbDo(db, mode, op) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(DB_STORE, mode);
      const req = op(tx.objectStore(DB_STORE));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error || new Error('IndexedDB: сбой'));
      tx.onabort = () => reject(tx.error || new Error('IndexedDB: отменено'));
    });
  }

  /** Стирает ключи пропусков, кончившихся больше недели назад. */
  async function dbSweep(db) {
    const now = G.phoneGateNow();
    const keys = await dbDo(db, 'readonly', (s) => s.getAllKeys());
    for (const k of keys) {
      const v = await dbDo(db, 'readonly', (s) => s.get(k));
      if (!v || typeof v.notAfter !== 'number' || v.notAfter + KEEP_AFTER_S < now) {
        await dbDo(db, 'readwrite', (s) => s.delete(k));
      }
    }
  }

  /**
   * Ключ этого телефона для пропуска: есть — тот же, нет — новый (и сразу в
   * хранилище, с чтением обратно: ключ, который не сохранился, не годится).
   * @returns {Promise<{privateKey: CryptoKey, pub: Uint8Array, bound: boolean}>}
   */
  async function keyFor(db, id, notAfter) {
    const old = await dbDo(db, 'readonly', (s) => s.get(id));
    if (old && old.privateKey && old.pub instanceof Uint8Array && old.pub.length === G.C.PUB_LEN) {
      return { privateKey: old.privateKey, pub: old.pub, bound: !!old.bound };
    }
    const k = await G.newKey(crypto.subtle);
    const rec = { privateKey: k.privateKey, publicKey: k.publicKey, pub: k.pub, bound: false, notAfter,
      created: Date.now() };
    await dbDo(db, 'readwrite', (s) => s.put(rec, id));
    const back = await dbDo(db, 'readonly', (s) => s.get(id));
    if (!back || !back.privateKey || !G.equal(back.pub, k.pub)) throw new Error('ключ не сохранился');
    return { privateKey: k.privateKey, pub: k.pub, bound: false };
  }

  /** Пометка «привязан к этому телефону» — только для надписи. */
  async function markBound(db, id) {
    const v = await dbDo(db, 'readonly', (s) => s.get(id));
    if (!v || v.bound) return;
    v.bound = true;
    await dbDo(db, 'readwrite', (s) => s.put(v, id));
  }

  // ── Почему не открыть из этого браузера ─────────────────────────────────
  /** @returns {string|null} Текст причины или null — можно. */
  function whyNoBluetooth() {
    const ua = navigator.userAgent || '';
    const ios = /iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
    if (navigator.bluetooth && typeof navigator.bluetooth.requestDevice === 'function') return null;
    if (ios) {
      return 'На iPhone браузер не умеет Bluetooth — эта ссылка открывает ворота только с Android. ' +
        'Попросите того, кто прислал ссылку, открыть вам ворота.';
    }
    if (/; wv\)|FBAN|FBAV|Instagram|Line\//.test(ua)) {
      return 'Ссылка открылась внутри мессенджера. Нажмите ⋮ → «Открыть в Chrome» ' +
        '(или скопируйте ссылку и вставьте в Chrome).';
    }
    return 'Этот браузер не умеет Bluetooth. Откройте ссылку в Google Chrome на Android.';
  }

  /**
   * Текст ошибки обмена.
   * @param {*} e
   * @param {string} ble
   */
  function errorText(e, ble) {
    const pick = ble ? '«' + ble + '»' : 'ворота ZMK';
    if (e instanceof G.ZmkGuestError) {
      switch (e.code) {
        case 'gate': return 'Это другие ворота. Нажмите «Открыть» снова и выберите ' + pick + '.';
        case 'old': return 'Ворота ещё не обновлены для пропусков гостей. Попросите жильца открыть вам.';
        case 'unclaimed': return 'Ворота ещё не настроены администратором.';
        case 'timeout': return 'Ворота не ответили. Подойдите ближе и нажмите снова.';
        default: return 'Непонятный ответ ворот. Нажмите снова.';
      }
    }
    const name = e && e.name;
    if (name === 'NotFoundError') {
      return 'Ворота не выбраны. Нажмите «Открыть» и выберите ' + pick +
        '. Нет в списке — подойдите ближе; если кто-то рядом открывает с телефона, подождите полминуты.';
    }
    if (name === 'NetworkError') return 'Связь с воротами прервалась. Подойдите ближе и нажмите снова.';
    if (name === 'SecurityError' || name === 'NotAllowedError') {
      return 'Браузер не дал доступ к Bluetooth. Разрешите «Устройства поблизости» для Chrome и нажмите снова.';
    }
    if (name === 'NotSupportedError') return 'Bluetooth на этом телефоне недоступен для браузера.';
    return 'Не получилось. Включите Bluetooth и нажмите снова.';
  }

  // ── Пропуск гостя ───────────────────────────────────────────────────────
  /** @param {Uint8Array} payload Байты ссылки после «#g». */
  async function guestMain(payload) {
    $('copyview').hidden = true;
    $('kkview').hidden = true;
    $('enview').hidden = true;
    $('guest').hidden = false;
    const btn = $('gopen');
    if (!window.isSecureContext || !window.crypto || !crypto.subtle) {
      state('Откройте ссылку по https:// в Google Chrome.', 'bad');
      return;
    }
    let link;
    try {
      link = await G.parseGuestPayload(payload, crypto.subtle);
    } catch (e) {
      console.warn('[ZMK] ссылка не разобралась:', e && e.message);
      state('Ссылка испорчена — попросите прислать её заново целиком.', 'bad');
      return;
    }
    const courier = link.g.type === G.C.TYPE_COURIER;
    $('gkind').textContent = courier ? 'Курьер' : 'Гость';
    $('gtitle').textContent = courier ? 'Пропуск курьера' : 'Пропуск гостя';
    if (link.label) {
      $('gname').textContent = link.label;
      $('gname').hidden = false;
    }
    if (link.ble) $('gble').textContent = '«' + link.ble + '»';
    $('guntil').textContent = 'Действует до ' + G.gateTimeText(link.g.notAfter) +
      (link.g.maxUses ? ' · открытий: ' + link.g.maxUses : '');
    const late = G.phoneGateNow() > link.g.notAfter + 300;

    const why = whyNoBluetooth();
    if (why !== null) {
      state(why, 'warn');
      $('gopen').hidden = true;
      $('gcopy').hidden = false;
      $('gcopy').addEventListener('click', () =>
        copyLink((ok) => state(ok ? 'Ссылка скопирована. Вставьте её в Chrome.' :
          'Не удалось скопировать — удерживайте адрес в строке браузера.', ok ? 'ok' : 'bad')));
      return;
    }

    const id = G.hex(link.g.issuer) + ':' + link.g.serial;
    let db;
    let key;
    try {
      db = await dbOpen();
      await dbSweep(db);
      key = await keyFor(db, id, link.g.notAfter);
      if (navigator.storage && navigator.storage.persist) {
        navigator.storage.persist().then(
          (p) => console.info('[ZMK] хранилище стойкое:', p),
          (e) => console.warn('[ZMK] persist:', e && e.name),
        );
      }
    } catch (e) {
      console.warn('[ZMK] хранилище:', e && e.message);
      state('Браузер не сохраняет данные (режим инкогнито?). Откройте ссылку в обычной вкладке Chrome — ' +
        'иначе пропуск привяжется к ключу, который пропадёт.', 'bad');
      return;
    }
    if (key.bound) $('gonce').textContent = 'Пропуск привязан к этому телефону.';
    state(late ? 'Срок пропуска, похоже, закончился — можно попробовать.' : '', late ? 'warn' : '');
    btn.disabled = false;

    let busy = false;
    btn.addEventListener('click', async () => {
      if (busy) return;
      busy = true;
      btn.disabled = true;
      let device = null;
      try {
        state('Выберите ворота в списке…');
        // Первым делом — список устройств: браузер требует, чтобы это было
        // прямо от нажатия, без ожиданий перед ним.
        device = await navigator.bluetooth.requestDevice({ filters: [{ services: [G.C.SVC_UUID] }] });
        state('Подключаюсь…');
        const server = await device.gatt.connect();
        const svc = await server.getPrimaryService(G.C.SVC_UUID);
        const chr = await svc.getCharacteristic(G.C.CHR_PASS_UUID);
        const ch = new G.Channel({ write: (c) => chr.writeValueWithResponse(c) });
        chr.addEventListener('characteristicvaluechanged', (ev) => {
          const v = ev.target.value;
          ch.onNotify(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
        });
        await chr.startNotifications();
        state('Проверяю пропуск…');
        const r = await G.openWithLink(ch, link, key, crypto.subtle);
        const t = G.replyText(r, link.ble);
        state(t.text, t.ok ? 'ok' : 'bad');
        if (r.code === G.R.OK) {
          await markBound(db, id);
          $('gonce').textContent = 'Пропуск привязан к этому телефону.';
        }
      } catch (e) {
        console.warn('[ZMK] открыть:', e && (e.code || e.name), e && e.message);
        state(errorText(e, link.ble), 'bad');
      } finally {
        if (device && device.gatt && device.gatt.connected) device.gatt.disconnect(); // ворота снова видны другим
        busy = false;
        btn.disabled = false;
      }
    });
  }

  const frag = G.parseFragment(location.hash);
  if (frag !== null && frag.letter === 'g') {
    guestMain(frag.payload).catch((e) => {
      console.error('[ZMK] страница гостя:', e);
      state('Сбой страницы. Обновите её.', 'bad');
    });
  } else {
    copyMain();
  }
})();
