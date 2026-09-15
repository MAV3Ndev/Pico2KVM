import {
  E2ESession,
  fingerprintHex,
  fpShort,
  hexToBytes,
  randomNonceHex,
  verifyDeviceSig,
} from './e2e.js';

const $ = (id) => document.getElementById(id);
let ws = null;
let session = null; // E2ESession
let e2eReady = false;
let readyTimer = 0;
let pendingFp = null; // {fp, epub} awaiting user trust decision
let helloBusy = false;
let helloNonce = null; // nonce of the in-flight key-req
let closeReason = null; // shown instead of '切断' when we close on purpose

const setStatus = (t) => {
  $('status').textContent = t;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function setE2EReady(on) {
  e2eReady = on;
  $('control').classList.toggle('e2e-ready', on);
}

async function api(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'エラーが発生しました');
  return j;
}

// e.code -> HID usage (物理キー基準)
const KEY_USAGE = {
  Enter: 0x28, Escape: 0x29, Backspace: 0x2a, Tab: 0x2b, Space: 0x2c,
  Minus: 0x2d, Equal: 0x2e, BracketLeft: 0x2f, BracketRight: 0x30, Backslash: 0x31,
  Semicolon: 0x33, Quote: 0x34, Backquote: 0x35, Comma: 0x36, Period: 0x37, Slash: 0x38,
  CapsLock: 0x39,
  PrintScreen: 0x46, ScrollLock: 0x47, Pause: 0x48,
  Insert: 0x49, Home: 0x4a, PageUp: 0x4b, Delete: 0x4c, End: 0x4d, PageDown: 0x4e,
  ArrowRight: 0x4f, ArrowLeft: 0x50, ArrowDown: 0x51, ArrowUp: 0x52,
  NumLock: 0x53, NumpadDivide: 0x54, NumpadMultiply: 0x55, NumpadSubtract: 0x56,
  NumpadAdd: 0x57, NumpadEnter: 0x58, Numpad0: 0x62, NumpadDecimal: 0x63,
  IntlBackslash: 0x64, ContextMenu: 0x65, IntlRo: 0x87, KanaMode: 0x88,
  IntlYen: 0x89, Convert: 0x8a, NonConvert: 0x8b,
};
for (let i = 0; i < 26; i++) KEY_USAGE['Key' + String.fromCharCode(65 + i)] = 0x04 + i;
for (let i = 1; i <= 9; i++) KEY_USAGE['Digit' + i] = 0x1e + (i - 1);
KEY_USAGE.Digit0 = 0x27;
for (let i = 1; i <= 12; i++) KEY_USAGE['F' + i] = 0x3a + (i - 1);
for (let i = 1; i <= 9; i++) KEY_USAGE['Numpad' + i] = 0x59 + (i - 1);

const MOD_BITS = {
  ControlLeft: 0x01, ShiftLeft: 0x02, AltLeft: 0x04, MetaLeft: 0x08,
  ControlRight: 0x10, ShiftRight: 0x20, AltRight: 0x40, MetaRight: 0x80,
};

// 文字 -> [modifier, usage] (US配列)
const CHAR_KEY = {};
for (let i = 0; i < 26; i++) {
  CHAR_KEY[String.fromCharCode(97 + i)] = [0, 0x04 + i];
  CHAR_KEY[String.fromCharCode(65 + i)] = [0x02, 0x04 + i];
}
const DIGITS = '1234567890';
const DIGIT_SHIFT = '!@#$%^&*()';
for (let i = 0; i < 10; i++) {
  CHAR_KEY[DIGITS[i]] = [0, 0x1e + i];
  CHAR_KEY[DIGIT_SHIFT[i]] = [0x02, 0x1e + i];
}
Object.assign(CHAR_KEY, {
  ' ': [0, 0x2c], '\n': [0, 0x28], '\t': [0, 0x2b],
  '-': [0, 0x2d], '_': [0x02, 0x2d], '=': [0, 0x2e], '+': [0x02, 0x2e],
  '[': [0, 0x2f], '{': [0x02, 0x2f], ']': [0, 0x30], '}': [0x02, 0x30],
  '\\': [0, 0x31], '|': [0x02, 0x31], ';': [0, 0x33], ':': [0x02, 0x33],
  "'": [0, 0x34], '"': [0x02, 0x34], '`': [0, 0x35], '~': [0x02, 0x35],
  ',': [0, 0x36], '<': [0x02, 0x36], '.': [0, 0x37], '>': [0x02, 0x37],
  '/': [0, 0x38], '?': [0x02, 0x38],
});

let mods = 0;
const pressed = [];

function buildReport(mod, usages) {
  const b = new Uint8Array(8);
  b[0] = 0x01;
  b[1] = mod;
  for (let i = 0; i < 6 && i < usages.length; i++) b[2 + i] = usages[i];
  return b;
}

// Reports are encrypted and sent in order through a promise chain so that
// seq numbers and wire order always match.
let sendChain = Promise.resolve();
function queueSend(report) {
  sendChain = sendChain
    .then(async () => {
      if (!e2eReady || !session || !ws || ws.readyState !== WebSocket.OPEN)
        return;
      const frame = await session.encrypt(0, report); // dir 0 = browser->device
      if (frame && ws && ws.readyState === WebSocket.OPEN) ws.send(frame);
    })
    .catch(() => {});
}

function sendReport() {
  if (!e2eReady) return;
  queueSend(buildReport(mods, pressed));
}

function sendRaw(mod, usage) {
  if (!e2eReady) return;
  queueSend(buildReport(mod, usage ? [usage] : []));
}

function releaseAll() {
  if (!mods && !pressed.length) return;
  mods = 0;
  pressed.length = 0;
  sendReport();
}

// --- 画面遷移 ---

async function init() {
  try {
    const j = await (await fetch('/api/status')).json();
    if (j.configured) $('login').hidden = false;
    else $('setup').hidden = false;
  } catch {
    $('login').hidden = false;
  }
}
init();

$('setup-form').onsubmit = async (e) => {
  e.preventDefault();
  $('error').textContent = '';
  try {
    const r = await api('/api/setup', { password: $('setup-password').value });
    $('totp-secret').textContent = r.totpSecret;
    $('otpauth-url').textContent = r.otpauth;
    $('setup-form').hidden = true;
    $('setup-result').hidden = false;
  } catch (x) {
    $('error').textContent = x.message;
  }
};

$('to-login').onclick = () => {
  $('setup').hidden = true;
  $('login').hidden = false;
};

$('login-form').onsubmit = async (e) => {
  e.preventDefault();
  $('error').textContent = '';
  try {
    await api('/api/login', { password: $('password').value, otp: $('otp').value });
    $('login').hidden = true;
    $('control').hidden = false;
    $('password').value = '';
    $('otp').value = '';
  } catch (x) {
    $('error').textContent = x.message;
  }
};

$('logout').onclick = async () => {
  try {
    await fetch('/api/logout', { method: 'POST' });
  } catch {}
  ws?.close();
  ws = null;
  $('control').hidden = true;
  $('login').hidden = false;
};

// ペアリングコード(任意): デバイス側に PAIRING_CODE が設定されている
// 場合のみ入力。HKDF salt = SHA256(code) になり、不一致だと鍵が合わず
// ready が復号できない = E2E 確立失敗になる。
const pairingInput = $('pairing-code');
pairingInput.value = localStorage.getItem('pico2kvm-pairing') || '';
pairingInput.addEventListener('change', () => {
  localStorage.setItem('pico2kvm-pairing', pairingInput.value);
});

// --- WebSocket + E2E handshake ---

async function startE2E(devEpubHex) {
  setE2EReady(false);
  const s = await E2ESession.create();
  session = s;
  ws.send(JSON.stringify({ type: 'key', pub: s.publicKeyHex() }));
  await s.deriveSession(devEpubHex, $('pairing-code').value || undefined);
  clearTimeout(readyTimer);
  readyTimer = setTimeout(() => {
    if (!e2eReady) {
      closeReason = 'E2E 確立失敗(ペアリングコード確認)';
      ws?.close();
    }
  }, 5000);
}

function onE2EReady() {
  if (e2eReady) return;
  clearTimeout(readyTimer);
  setE2EReady(true);
  setStatus('E2E 接続済み');
}

async function handleHello(m) {
  if (helloBusy) return;
  const okPub = (h) => typeof h === 'string' && /^[0-9a-f]{130}$/.test(h);
  if (
    !okPub(m.spub) ||
    !okPub(m.epub) ||
    typeof m.sig !== 'string' ||
    !/^[0-9a-f]{128}$/.test(m.sig)
  ) {
    setStatus('ファームウェアが古い(要更新)');
    return;
  }
  if (!helloNonce) return; // unsolicited hello: no key-req in flight
  helloBusy = true;
  try {
    const fp = await fingerprintHex(hexToBytes(m.spub));
    const saved = localStorage.getItem('pico2kvm-fp-default');
    if (saved && saved !== fp) {
      closeReason = 'フィンガープリント不一致!(MITMの可能性)';
      ws?.close();
      return;
    }
    // Prove the peer holds the pinned static key before doing ECDH.
    const sigOk = await verifyDeviceSig(m.spub, helloNonce, m.epub, m.sig);
    if (!sigOk) {
      closeReason = '署名検証失敗(MITMの可能性)';
      ws?.close();
      return;
    }
    if (saved === fp) {
      await startE2E(m.epub);
    } else {
      pendingFp = { fp, epub: m.epub };
      $('fp-value').textContent = fpShort(fp);
      $('fp-confirm').hidden = false;
      setStatus('デバイス確認');
    }
  } finally {
    helloBusy = false;
  }
}

async function onWsMessage(ev) {
  if (typeof ev.data === 'string') {
    let m;
    try {
      m = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (m.type === 'peer') {
      setStatus(m.device ? 'デバイス オンライン' : 'リレー接続済み・デバイス待ち');
    } else if (m.type === 'hello') {
      void handleHello(m);
    }
    return;
  }
  // binary: E2E frame
  if (!session) return;
  const r = await session.decrypt(new Uint8Array(ev.data));
  if (!r) return;
  let j;
  try {
    j = JSON.parse(new TextDecoder().decode(r.plaintext));
  } catch {
    return;
  }
  if (j.type === 'ready') onE2EReady();
}

$('connect').onclick = () => {
  if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/device/default`);
  ws.binaryType = 'arraybuffer';
  session = null;
  pendingFp = null;
  helloNonce = null;
  setE2EReady(false);
  $('fp-confirm').hidden = true;
  setStatus('接続中');
  ws.onopen = () => {
    helloNonce = randomNonceHex();
    ws.send(JSON.stringify({ type: 'key-req', nonce: helloNonce }));
  };
  ws.onmessage = (ev) => {
    void onWsMessage(ev);
  };
  ws.onclose = () => {
    setE2EReady(false);
    releaseAll();
    session = null;
    pendingFp = null;
    helloNonce = null;
    clearTimeout(readyTimer);
    ws = null;
    $('fp-confirm').hidden = true;
    setStatus(closeReason || '切断');
    closeReason = null;
  };
  ws.onerror = () => setStatus('切断');
};

$('fp-trust').onclick = async () => {
  if (!pendingFp) return;
  localStorage.setItem('pico2kvm-fp-default', pendingFp.fp);
  const epub = pendingFp.epub;
  pendingFp = null;
  $('fp-confirm').hidden = true;
  setStatus('鍵交換中');
  await startE2E(epub);
};

$('fp-cancel').onclick = () => {
  pendingFp = null;
  $('fp-confirm').hidden = true;
  ws?.close();
};

// --- キーキャプチャ ---

const capture = $('capture');
capture.addEventListener('keydown', (e) => {
  e.preventDefault();
  if (e.repeat) return;
  const mb = MOD_BITS[e.code];
  if (mb !== undefined) {
    if (!(mods & mb)) {
      mods |= mb;
      sendReport();
    }
    return;
  }
  const u = KEY_USAGE[e.code];
  if (u !== undefined && !pressed.includes(u)) {
    pressed.push(u);
    sendReport();
  }
});
capture.addEventListener('keyup', (e) => {
  e.preventDefault();
  const mb = MOD_BITS[e.code];
  if (mb !== undefined) {
    if (mods & mb) {
      mods &= ~mb;
      sendReport();
    }
    return;
  }
  const u = KEY_USAGE[e.code];
  const i = u === undefined ? -1 : pressed.indexOf(u);
  if (i >= 0) {
    pressed.splice(i, 1);
    sendReport();
  }
});
capture.addEventListener('blur', releaseAll);

// --- ボタン ---

const BUTTON_KEYS = {
  enter: [0, 0x28],
  backspace: [0, 0x2a],
  tab: [0, 0x2b],
  escape: [0, 0x29],
  cad: [0x05, 0x4c],
  win: [0x08, 0],
};

document.querySelectorAll('[data-key]').forEach((b) => {
  b.onclick = async () => {
    const k = BUTTON_KEYS[b.dataset.key];
    if (!k) return;
    sendRaw(k[0], k[1]);
    await sleep(50);
    sendRaw(0, 0);
  };
});

// --- テキスト送信 ---

$('send-text').onclick = async () => {
  const text = $('text').value;
  if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
  $('send-text').disabled = true;
  try {
    for (const ch of text) {
      const k = CHAR_KEY[ch];
      if (!k) continue;
      sendRaw(k[0], k[1]);
      await sleep(20);
      sendRaw(0, 0);
      await sleep(20);
    }
  } finally {
    $('send-text').disabled = false;
  }
};
