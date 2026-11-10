/**
 * @file zmk-guest.js — пропуск гостя и курьера ZMK по ссылке: разбор ссылки,
 *       сообщения канала пропусков, ответы платы, весь обмен «открыть».
 *
 * Спецификация — docs/arhitektura-propuskov.md, раздел 7.3 (прошивка r18d).
 * Эталон — tool/zmk_pch_ref.py (векторы test/vectors/zmk_pch_v1.json, «r18d»).
 *
 * Без внешних библиотек и сетевых запросов. Работает в браузере (window.ZmkGuest)
 * и в Node 20+ (module.exports) — так этот же код проверяется с настоящей
 * прошивкой на стенде (stend/bin/scen_zmk18_pipe).
 *
 * БЕЗОПАСНОСТЬ (Zero-Trust):
 *  - всё из ссылки и из эфира проверяется по длине и полям, иначе — отказ;
 *  - секрет ссылки и закрытый ключ никуда не печатаются и не уходят, кроме платы;
 *  - закрытый ключ телефона гостя — неизвлекаемый ключ WebCrypto (CryptoKey).
 */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.ZmkGuest = api;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ── Константы протокола (те же имена — в прошивке ZMK_PCH_* и в эталоне) ──
  const C = Object.freeze({
    SVC_UUID: '7a3e0001-6c5f-4b2a-9d31-8e6f0a5c1b40',
    CHR_PASS_UUID: '7a3e0004-6c5f-4b2a-9d31-8e6f0a5c1b40',
    LINK_BASE: 'https://zmkalexandr-sys.github.io/z/',
    PASS_LEN: 144,
    PASS_BODY: 80,
    SECRET_LEN: 16,
    PUB_LEN: 33,
    SIG_LEN: 64,
    CHAL_LEN: 16,
    GROUP_LEN: 8,
    KID_LEN: 8,
    T_HELLO: 0x01,
    T_GUEST: 0x0e,
    G_BIND: 1,
    G_OPEN: 2,
    REPLY: 0x80,
    R_CHANNEL: 0xc0,
    KIND_OPEN: 0x02,
    KIND_BIND: 0x03,
    CMD_OPEN: 1,
    F_CLAIMED: 0x01,
    F_GUESTS: 0x80,
    TYPE_RESIDENT: 1,
    TYPE_GUEST: 2,
    TYPE_COURIER: 3,
    TYPE_GUARD: 4,
    HELLO_REPLY_LEN: 37,
    GUEST_REPLY_LEN: 19,
    GBIND_LEN: 403,
    GOPEN_LEN: 354,
    LINK_PAYLOAD_BASE: 304,
    LABEL_MAX: 48,
    BLE_MAX: 24,
    CHUNK_BIG: 180, // данных в куске: Android сам дробит длинную запись
    CHUNK_SMALL: 18, // запасной путь: кусок влезает в пакет 23 байта
    HEAVY_GAP_MS: 1600, // плата: тяжёлое сообщение с подключения — не чаще 1,5 с
    REPLY_TIMEOUT_MS: 8000,
  });

  /** Причины ответа платы (раздел 9 и канал 7.1–7.3). */
  const R = Object.freeze({
    OK: 0,
    FORMAT: 1,
    GROUP: 4,
    GATE: 5,
    SIGNATURE: 7,
    REVOKED: 8,
    RETIRED: 9,
    NOT_YET: 10,
    EXPIRED: 11,
    SCHEDULE: 12,
    RIGHTS: 13,
    CHAIN: 14,
    DELEGATION: 15,
    USES: 16,
    HOLDER: 17,
    BUSY: 0x40,
    RATE: 0x41,
    NOCHAL: 0x42,
    CHUNK: 0x43,
    UNCLAIMED: 0x44,
    TYPE: 0x45,
    LEN: 0x46,
    STORE: 0x47,
    LATE: 0x48,
    NOSTORE: 0x49,
    FULL: 0x4b,
    BOUND: 0x4f,
    UNBOUND: 0x50,
    DAYLIMIT: 0x51,
  });

  /** Код реле в ответе (старый протокол платы). */
  const RELAY = Object.freeze({ OK: 0, BUSY: 7, RELAY: 8, MODE: 10, NONE: 0xff });

  /** Ошибка разбора или обмена с понятной причиной (code — для текста человеку). */
  class ZmkGuestError extends Error {
    /**
     * @param {string} code Машинная причина ('link', 'gate', 'old', 'timeout', …).
     * @param {string} message Пояснение для журнала разработчика (без секретов).
     */
    constructor(code, message) {
      super(message);
      this.name = 'ZmkGuestError';
      this.code = code;
    }
  }

  // ── Байты ───────────────────────────────────────────────────────────────
  /**
   * Склеивает куски байт.
   * @param {...Uint8Array} parts
   * @returns {Uint8Array}
   */
  function concat(...parts) {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let k = 0;
    for (const p of parts) {
      out.set(p, k);
      k += p.length;
    }
    return out;
  }

  /** @param {Uint8Array} b @returns {string} */
  function hex(b) {
    let s = '';
    for (const x of b) s += x.toString(16).padStart(2, '0');
    return s;
  }

  /**
   * Строгий разбор hex: только чётная длина и знаки 0-9a-f.
   * @param {string} s
   * @returns {Uint8Array|null}
   */
  function unhex(s) {
    if (typeof s !== 'string' || s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  /** @param {Uint8Array} a @param {Uint8Array} b @returns {boolean} */
  function equal(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  /** @param {Uint8Array} b @param {number} o @returns {number} */
  function rd16(b, o) {
    return b[o] | (b[o + 1] << 8);
  }

  /** @param {Uint8Array} b @param {number} o @returns {number} */
  function rd32(b, o) {
    return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  }

  /**
   * base64url без «=» → байты. Строго: только [A-Za-z0-9_-], длина не 4k+1.
   * @param {string} s
   * @returns {Uint8Array|null}
   */
  function b64urlDecode(s) {
    if (typeof s !== 'string' || s.length === 0 || s.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(s)) {
      return null;
    }
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const out = new Uint8Array(Math.floor((s.length * 3) / 4));
    let bits = 0;
    let acc = 0;
    let k = 0;
    for (const ch of s) {
      acc = (acc << 6) | A.indexOf(ch);
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[k++] = (acc >> bits) & 0xff;
      }
    }
    // Хвостовые биты обязаны быть нулями: иначе у одной ссылки две записи.
    if ((acc & ((1 << bits) - 1)) !== 0) return null;
    return out.subarray(0, k);
  }

  /** @param {Uint8Array} b @returns {string} base64url без «=». */
  function b64urlEncode(b) {
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let s = '';
    let i = 0;
    for (; i + 2 < b.length; i += 3) {
      const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
      s += A[(n >> 18) & 63] + A[(n >> 12) & 63] + A[(n >> 6) & 63] + A[n & 63];
    }
    if (i < b.length) {
      const n = (b[i] << 16) | ((i + 1 < b.length ? b[i + 1] : 0) << 8);
      s += A[(n >> 18) & 63] + A[(n >> 12) & 63];
      if (i + 1 < b.length) s += A[(n >> 6) & 63];
    }
    return s;
  }

  // ── Пропуск ─────────────────────────────────────────────────────────────
  /**
   * Разбор пропуска v1 (без подписи — её проверяет плата). Поля вне формата —
   * отказ, без попыток «понять».
   * @param {Uint8Array} b 144 байта.
   * @returns {object|null}
   */
  function decodePass(b) {
    if (!(b instanceof Uint8Array) || b.length !== C.PASS_LEN || b[0] !== 1) return null;
    const p = {
      raw: b,
      ver: b[0],
      type: b[1],
      group: b.slice(2, 10),
      gates: rd16(b, 10),
      rights: rd16(b, 12),
      serial: rd32(b, 14),
      issuer: b.slice(18, 26),
      holder: b.slice(26, 59),
      notBefore: rd32(b, 59),
      notAfter: rd32(b, 63),
      schedule: rd32(b, 67),
      maxUses: b[71],
      flags: b[72],
      durationMin: rd16(b, 73),
      guestMaxHours: rd16(b, 75),
      guestsPerDay: b[77],
    };
    if (p.type < C.TYPE_RESIDENT || p.type > C.TYPE_GUARD || p.gates === 0) return null;
    if (b[78] !== 0 || b[79] !== 0) return null;
    if (p.notAfter !== 0 && p.notAfter <= p.notBefore) return null;
    return p;
  }

  /**
   * Пропуск гостя или курьера.
   * @param {number} t Вид пропуска.
   */
  function isGuestType(t) {
    return t === C.TYPE_GUEST || t === C.TYPE_COURIER;
  }

  /**
   * Номер ворот пропуска гостя (ровно один бит). -1 — не один.
   * @param {number} gates
   */
  function singleGate(gates) {
    if (gates === 0 || (gates & (gates - 1)) !== 0) return -1;
    let g = 0;
    while (((gates >> g) & 1) === 0) g++;
    return g;
  }

  // ── Ссылка ──────────────────────────────────────────────────────────────
  /**
   * Часть ссылки после «#»: буква вида и base64url. Иначе — null.
   * @param {string} hash location.hash или часть после «#».
   * @returns {{letter: string, payload: Uint8Array}|null}
   */
  function parseFragment(hash) {
    if (typeof hash !== 'string') return null;
    const f = hash.startsWith('#') ? hash.slice(1) : hash;
    if (f.length < 2 || f.length > 12000) return null;
    const payload = b64urlDecode(f.slice(1));
    if (payload === null || payload.length === 0) return null;
    return { letter: f[0], payload };
  }

  /**
   * Строка UTF-8 строго (испорченная — null).
   * @param {Uint8Array} b
   */
  function utf8(b) {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(b);
    } catch (e) {
      if (e instanceof TypeError) return null; // не UTF-8 — подсказка испорчена
      throw e;
    }
  }

  /**
   * Полезные байты ссылки гостя: гость ‖ жилец ‖ секрет [‖ длина ‖ название ‖
   * длина ‖ имя платы]. Проверяет форму и цепочку без подписей (подписи —
   * дело платы), секрет — по отпечатку в пропуске.
   * @param {Uint8Array} payload
   * @param {SubtleCrypto} subtle
   * @returns {Promise<object>} {guest, resident, secret, g, r, label, ble}
   * @throws {ZmkGuestError} code 'link' — ссылка испорчена или не та.
   */
  async function parseGuestPayload(payload, subtle) {
    const bad = (why) => new ZmkGuestError('link', why);
    if (!(payload instanceof Uint8Array) || payload.length < C.LINK_PAYLOAD_BASE) throw bad('коротко');
    const guest = payload.slice(0, C.PASS_LEN);
    const resident = payload.slice(C.PASS_LEN, 2 * C.PASS_LEN);
    const secret = payload.slice(2 * C.PASS_LEN, C.LINK_PAYLOAD_BASE);
    let label = '';
    let ble = '';
    if (payload.length > C.LINK_PAYLOAD_BASE) {
      let k = C.LINK_PAYLOAD_BASE;
      const la = payload[k++];
      if (la > C.LABEL_MAX || k + la + 1 > payload.length) throw bad('название');
      const lb = payload[k + la];
      if (lb > C.BLE_MAX || k + la + 1 + lb !== payload.length) throw bad('имя платы');
      label = utf8(payload.subarray(k, k + la));
      ble = utf8(payload.subarray(k + la + 1, k + la + 1 + lb));
      if (label === null || ble === null || /[\u0000-\u001f\u007f]/.test(label + ble)) throw bad('знаки');
    }
    const g = decodePass(guest);
    const r = decodePass(resident);
    if (g === null || !isGuestType(g.type) || g.holder[0] !== 0 || g.notAfter === 0) throw bad('пропуск гостя');
    if (r === null || (r.type !== C.TYPE_RESIDENT && r.type !== C.TYPE_GUARD)) throw bad('пропуск жильца');
    if (!equal(g.group, r.group) || singleGate(g.gates) < 0) throw bad('группа или ворота');
    const kid = (await sha256(subtle, r.holder)).slice(0, C.KID_LEN);
    if (!equal(kid, g.issuer)) throw bad('цепочка');
    const h = await sha256(subtle, secret);
    if (!equal(h, g.holder.subarray(1))) throw bad('секрет');
    return { guest, resident, secret, g, r, label, ble };
  }

  // ── Крипто (WebCrypto) ─────────────────────────────────────────────────
  /** @returns {Promise<Uint8Array>} */
  async function sha256(subtle, b) {
    return new Uint8Array(await subtle.digest('SHA-256', b));
  }

  /**
   * «ZMK1» ‖ вид ‖ содержимое — то, что подписывает телефон и хеширует плата.
   * @param {number} kind @param {Uint8Array} body
   */
  function sigMessage(kind, body) {
    return concat(new Uint8Array([0x5a, 0x4d, 0x4b, 0x31, kind]), body);
  }

  /**
   * Подпись r‖s (64 байта) неизвлекаемым ключом P-256. Плата принимает любое s.
   * @param {SubtleCrypto} subtle @param {CryptoKey} priv
   * @param {number} kind @param {Uint8Array} body
   * @returns {Promise<Uint8Array>}
   */
  async function sign(subtle, priv, kind, body) {
    const sig = new Uint8Array(
      await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, sigMessage(kind, body)),
    );
    if (sig.length !== C.SIG_LEN) throw new ZmkGuestError('crypto', 'подпись не 64 байта');
    return sig;
  }

  /**
   * Сжатый открытый ключ (33 байта) из несжатого (65).
   * @param {Uint8Array} raw
   */
  function compressPub(raw) {
    if (!(raw instanceof Uint8Array) || raw.length !== 65 || raw[0] !== 0x04) {
      throw new ZmkGuestError('crypto', 'ключ не P-256');
    }
    const out = new Uint8Array(C.PUB_LEN);
    out[0] = 0x02 | (raw[64] & 1);
    out.set(raw.subarray(1, 33), 1);
    return out;
  }

  /**
   * Новый ключ телефона гостя: закрытый — неизвлекаемый.
   * @param {SubtleCrypto} subtle
   * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey, pub: Uint8Array}>}
   */
  async function newKey(subtle) {
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const pub = compressPub(new Uint8Array(await subtle.exportKey('raw', pair.publicKey)));
    return { privateKey: pair.privateKey, publicKey: pair.publicKey, pub };
  }

  // ── Сообщения ───────────────────────────────────────────────────────────
  /** Подписываемое при первом открытии: группа ‖ ворота ‖ вызов ‖ SHA-256(гость) ‖ новый ключ. */
  function bindBody(group, gate, chal, passHash, key) {
    return concat(group, new Uint8Array([gate]), chal, passHash, key);
  }

  /** Подписываемое при открытии: группа ‖ ворота ‖ вызов ‖ команда ‖ SHA-256(гость) ‖ время 0. */
  function openBody(group, gate, chal, passHash) {
    return concat(group, new Uint8Array([gate]), chal, new Uint8Array([C.CMD_OPEN]), passHash, new Uint8Array(4));
  }

  /** Первое открытие: 0E 01 гость жилец секрет ключ подпись — 403 байта. */
  function bindMsg(guest, resident, secret, key, sig) {
    return concat(new Uint8Array([C.T_GUEST, C.G_BIND]), guest, resident, secret, key, sig);
  }

  /** Открытие привязанным ключом: 0E 02 гость жилец подпись — 354 байта. */
  function openMsg(guest, resident, sig) {
    return concat(new Uint8Array([C.T_GUEST, C.G_OPEN]), guest, resident, sig);
  }

  /**
   * Куски: [номер][всего][данные], номера с 0.
   * @param {Uint8Array} msg @param {number} payload Данных в куске.
   * @returns {Uint8Array[]}
   */
  function chunks(msg, payload) {
    const n = Math.ceil(msg.length / payload);
    if (n < 1 || n > 255) throw new ZmkGuestError('len', 'кусков ' + n);
    const out = [];
    for (let i = 0; i < n; i++) {
      out.push(concat(new Uint8Array([i, n]), msg.subarray(i * payload, Math.min(msg.length, (i + 1) * payload))));
    }
    return out;
  }

  /**
   * Ответ «привет» (37 байт).
   * @param {Uint8Array} b
   * @returns {{flags:number, group:Uint8Array, gate:number, admins:number, bulletin:number, time:number, chal:Uint8Array}|null}
   */
  function parseHello(b) {
    if (!(b instanceof Uint8Array) || b.length !== C.HELLO_REPLY_LEN || b[0] !== (C.REPLY | C.T_HELLO)) return null;
    return {
      ver: b[1],
      flags: b[2],
      group: b.slice(3, 11),
      gate: b[11],
      admins: b[12],
      bulletin: rd32(b, 13),
      time: rd32(b, 17),
      chal: b.slice(21, 37),
    };
  }

  /**
   * Ответ на «гость» (19 байт) или ответ канала [C0][причина].
   * @param {Uint8Array} b
   * @returns {{code:number, relay:number, channel:boolean}|null}
   */
  function parseGuestReply(b) {
    if (!(b instanceof Uint8Array)) return null;
    if (b.length === 2 && b[0] === C.R_CHANNEL) return { code: b[1], relay: RELAY.NONE, channel: true };
    if (b.length !== C.GUEST_REPLY_LEN || b[0] !== (C.REPLY | C.T_GUEST)) return null;
    return { code: b[1], relay: b[2], channel: false, bulletin: rd32(b, 15) };
  }

  // ── Время ворот ─────────────────────────────────────────────────────────
  const EPOCH_2000_MS = Date.UTC(2000, 0, 1);

  /**
   * Время пропуска (секунды от 2000 по местному времени ворот) → текст «11
   * ноября, 14:30». Пояс не пересчитывается: время ворот — местное.
   * @param {number} t
   */
  function gateTimeText(t) {
    const d = new Date(EPOCH_2000_MS + t * 1000);
    return new Intl.DateTimeFormat('ru-RU', {
      day: 'numeric',
      month: 'long',
      hour: '2-digit',
      minute: '2-digit',
      timeZone: 'UTC',
    }).format(d);
  }

  /** Местное время телефона в секундах от 2000 — примерно время ворот (тот же пояс). */
  function phoneGateNow(now = new Date()) {
    return Math.floor((now.getTime() - now.getTimezoneOffset() * 60000 - EPOCH_2000_MS) / 1000);
  }

  // ── Тексты человеку ─────────────────────────────────────────────────────
  /**
   * Что сказать курьеру по ответу платы.
   * @param {{code:number, relay:number}} r
   * @param {string} ble Имя ворот в эфире (подсказка).
   * @returns {{ok:boolean, text:string, retry:boolean}}
   */
  function replyText(r, ble) {
    const pick = ble ? '«' + ble + '»' : 'нужные ворота';
    if (r.code === R.OK) {
      if (r.relay === RELAY.OK) return { ok: true, text: 'Открыто. Проезжайте.', retry: false };
      if (r.relay === RELAY.BUSY) {
        return { ok: true, text: 'Ворота уже открыты или ещё закрываются. Подождите и нажмите снова.', retry: true };
      }
      return { ok: false, text: 'Пропуск принят, но ворота не открылись (код ' + r.relay + '). Попробуйте ещё раз.', retry: true };
    }
    switch (r.code) {
      case R.BOUND:
        return { ok: false, text: 'Эту ссылку уже открыли на другом телефоне. Пересланная ссылка не работает — попросите новую у того, кто её прислал.', retry: false };
      case R.NOT_YET:
        return { ok: false, text: 'Пропуск ещё не начал действовать по часам ворот.', retry: false };
      case R.EXPIRED:
        return { ok: false, text: 'Срок пропуска закончился. Попросите новый.', retry: false };
      case R.USES:
        return { ok: false, text: 'Открытия по этому пропуску закончились.', retry: false };
      case R.SCHEDULE:
        return { ok: false, text: 'Сейчас проезд по пропуску закрыт (расписание жильца).', retry: false };
      case R.REVOKED:
      case R.RETIRED:
      case R.CHAIN:
        return { ok: false, text: 'Пропуск отозван или недействителен. Попросите новый.', retry: false };
      case R.DELEGATION:
      case R.RIGHTS:
        return { ok: false, text: 'Жильцу не разрешено выдавать такой пропуск. Пусть он обратится к администратору.', retry: false };
      case R.DAYLIMIT:
        return { ok: false, text: 'У жильца закончился лимит пропусков на сутки.', retry: false };
      case R.FULL:
        return { ok: false, text: 'На воротах сейчас слишком много пропусков. Попросите жильца открыть вам.', retry: false };
      case R.GROUP:
      case R.GATE:
        return { ok: false, text: 'Это другие ворота. Нажмите «Открыть» снова и выберите ' + pick + '.', retry: true };
      case R.UNCLAIMED:
        return { ok: false, text: 'Ворота ещё не настроены администратором.', retry: false };
      case R.TYPE:
        return { ok: false, text: 'Ворота ещё не обновлены для пропусков гостей. Попросите жильца открыть вам.', retry: false };
      case R.BUSY:
      case R.RATE:
        return { ok: false, text: 'Ворота заняты. Подождите пару секунд и нажмите снова.', retry: true };
      case R.NOCHAL:
      case R.LATE:
      case R.CHUNK:
      case R.HOLDER:
        return { ok: false, text: 'Связь прервалась. Подойдите ближе и нажмите снова.', retry: true };
      case R.STORE:
      case R.NOSTORE:
        return { ok: false, text: 'Сбой памяти ворот. Нажмите снова; не выйдет — сообщите жильцу.', retry: true };
      default:
        return { ok: false, text: 'Ворота отказали (код 0x' + r.code.toString(16) + '). Сообщите жильцу.', retry: false };
    }
  }

  // ── Обмен с платой ──────────────────────────────────────────────────────
  /**
   * Канал пропусков поверх транспорта: write(кусок) → Promise; уведомления
   * подаются в onNotify(байты). Ждёт ответ на сообщение с тайм-аутом.
   */
  class Channel {
    /**
     * @param {{write: function(Uint8Array): Promise<void>}} transport
     * @param {{chunk?: number, timeoutMs?: number, sleep?: function(number): Promise<void>}} [opt]
     */
    constructor(transport, opt = {}) {
      this.t = transport;
      this.chunk = opt.chunk || C.CHUNK_BIG;
      this.timeoutMs = opt.timeoutMs || C.REPLY_TIMEOUT_MS;
      this.sleep = opt.sleep || ((ms) => new Promise((res) => setTimeout(res, ms)));
      this.waiter = null;
      this.lastHeavy = 0;
    }

    /** Уведомление платы (зовёт транспорт). @param {Uint8Array} b */
    onNotify(b) {
      const w = this.waiter;
      if (w === null) return; // ответ без вопроса — не наш, пропускаем
      this.waiter = null;
      w(b);
    }

    /**
     * Сообщение кусками и ответ. Длинная запись не прошла (старый Android) —
     * всё сообщение заново мелкими кусками: плата начинает сборку с куска 0.
     * @param {Uint8Array} msg
     * @returns {Promise<Uint8Array>}
     */
    async request(msg) {
      let timer = null;
      const reply = new Promise((resolve, reject) => {
        timer = setTimeout(() => {
          this.waiter = null;
          reject(new ZmkGuestError('timeout', 'плата не ответила'));
        }, this.timeoutMs);
        this.waiter = (b) => {
          clearTimeout(timer);
          resolve(b);
        };
      });
      try {
        try {
          await this.sendAll(msg, this.chunk);
        } catch (e) {
          if (this.chunk === C.CHUNK_SMALL) throw e;
          this.chunk = C.CHUNK_SMALL; // длинная запись не прошла — дальше только мелкие куски
          await this.sendAll(msg, this.chunk);
        }
      } catch (e) {
        // Не отправилось: ответа не будет — снять ожидание (обещание останется
        // висеть без отказа и уйдёт с мусором), ошибку — наверх.
        clearTimeout(timer);
        this.waiter = null;
        throw e;
      }
      return reply;
    }

    /** @private */
    async sendAll(msg, size) {
      for (const c of chunks(msg, size)) await this.t.write(c);
    }

    /** «Привет»: флаги, группа, ворота, свежий вызов. */
    async hello() {
      const h = parseHello(await this.request(new Uint8Array([C.T_HELLO])));
      if (h === null) throw new ZmkGuestError('reply', 'ответ «привет» не разобрался');
      return h;
    }

    /** Тяжёлое сообщение — не чаще раза в 1,6 с (плата иначе отвечает «слишком часто»). */
    async heavy(msg) {
      const wait = this.lastHeavy + C.HEAVY_GAP_MS - Date.now();
      if (this.lastHeavy !== 0 && wait > 0) await this.sleep(wait);
      this.lastHeavy = Date.now();
      return this.request(msg);
    }
  }

  /**
   * Весь обмен «открыть» по ссылке гостя: привет (свои ли это ворота, умеют
   * ли гостей), первое открытие ключом этого телефона. Первое открытие тем
   * же ключом, что уже привязан, плата принимает как обычное — поэтому
   * страница всегда шлёт «привязать и открыть»: потерянный ответ или
   * перезагрузка платы не запирают гостя.
   * @param {Channel} ch
   * @param {object} link Итог parseGuestPayload.
   * @param {{privateKey: CryptoKey, pub: Uint8Array}} key Ключ этого телефона.
   * @param {SubtleCrypto} subtle
   * @returns {Promise<{code:number, relay:number, channel:boolean}>}
   * @throws {ZmkGuestError} 'gate' — другие ворота, 'old' — плата без гостей,
   *         'unclaimed', 'reply', 'timeout'.
   */
  async function openWithLink(ch, link, key, subtle) {
    const h = await ch.hello();
    if ((h.flags & C.F_CLAIMED) === 0) throw new ZmkGuestError('unclaimed', 'плата не присвоена');
    if ((h.flags & C.F_GUESTS) === 0) throw new ZmkGuestError('old', 'плата без гостей (до r18d)');
    if (!equal(h.group, link.g.group) || h.gate !== singleGate(link.g.gates)) {
      throw new ZmkGuestError('gate', 'другие ворота');
    }
    const ph = await sha256(subtle, link.guest);
    const sig = await sign(subtle, key.privateKey, C.KIND_BIND, bindBody(h.group, h.gate, h.chal, ph, key.pub));
    const r = parseGuestReply(await ch.heavy(bindMsg(link.guest, link.resident, link.secret, key.pub, sig)));
    if (r === null) throw new ZmkGuestError('reply', 'ответ на «гость» не разобрался');
    return r;
  }

  return Object.freeze({
    C,
    R,
    RELAY,
    ZmkGuestError,
    concat,
    hex,
    unhex,
    equal,
    b64urlDecode,
    b64urlEncode,
    decodePass,
    singleGate,
    parseFragment,
    parseGuestPayload,
    sha256,
    sigMessage,
    sign,
    compressPub,
    newKey,
    bindBody,
    openBody,
    bindMsg,
    openMsg,
    chunks,
    parseHello,
    parseGuestReply,
    gateTimeText,
    phoneGateNow,
    replyText,
    Channel,
    openWithLink,
  });
});
