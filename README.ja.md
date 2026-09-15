# Pico2KVM

[English](README.md) · [通信詳細仕様](Detailed-Spec.ja.md) ([English](Detailed-Spec.md))

**Raspberry Pi Pico 2 W** で作る最小構成リモート KVM(キーボードのみ)。

Web ページでタイプ → キー入力が TLS 経由で Cloudflare Worker(Durable
Object リレー)→ Pico 2 W に届き、USB HID キーボードとして対象
マシンに入力します。経路全体は **forward secrecy 付きのエンドツーエンド
暗号化(E2EE)** で守られており、リレーや経路上の誰から見ても暗号文しか
見えません。

```
┌──────────┐  WSS + E2EE   ┌───────────────────────┐  WSS + E2EE  ┌───────────┐   USB HID   ┌────────┐
│ ブラウザ │ ◄───────────► │ Cloudflare Worker (DO)│ ◄──────────► │ Pico 2 W  │ ──────────► │ 対象PC │
└──────────┘               └───────────────────────┘              └───────────┘             └────────┘
```

## 特徴

- **FS 付き E2EE**: セッションごとにエフェメラル同士の ECDH(P-256)→
  HKDF-SHA256 → AES-256-GCM。デバイスの長期鍵はハンドシェイクの署名専用で、
  後で漏れても過去の通信は復号できません。
- **MITM 検知**: ブラウザがデバイス鍵のフィンガープリントをピン留め
  (TOFU)。初回接続時に画面表示と `firmware/device_fingerprint.txt` を
  目視照合し、不一致なら接続を中止します。
- **リプレイ防止**: 方向ごとの単調増加シーケンス番号を AEAD フレームに
  内蔵。
- **認証付き Web UI**: パスワード(PBKDF2)+ TOTP(RFC 6238)、
  HMAC 署名セッション Cookie、ログイン試行のレートリミット。
- **デバイス側 TLS 証明書検証**: GTS Root R4 をピン留め(workers.dev
  の発行元ルート)。
- **キーキャプチャ**: 物理キー基準の `e.code` → HID usage 変換(JIS キー
  含む)、修飾キーコード追跡、Ctrl+Alt+Del/Win ボタン、ASCII テキスト送信。
- **自己回復ファーム**: 非同期 Wi-Fi 再接続、WebSocket keepalive +
  指数バックオフ、ウォッチドッグ、状態 LED(消灯=Wi-Fi 未接続、
  点滅=Wi-Fi 接続済み/リレー接続中、点灯=オンライン)。
- 映像キャプチャは対象外(必要なら MS2109 系 HDMI キャプチャを閲覧側 PC
  に挿す構成を)。

## 構成

```
firmware/   RP2350 ファームウェア (Pico SDK + TinyUSB + lwIP/altcp + mbedTLS)
  main.c              起動、Wi-Fi 管理、HID リング消費、LED、watchdog
  ws_client.c         WSS クライアント: DNS → TLS(SNI+CA検証) → WS upgrade
  e2e.c / e2e.h       ECDH/ECDSA/HKDF/GCM ハンドシェイク + フレーム暗号
  ws_frame.h          WebSocket フレームパーサ(ホストテストと共有)
  gen_device_key.mjs  device_key.h + device_fingerprint.txt を一度だけ生成
  gtsr4.pem           TLS 検証用の信頼 CA(workers.dev 発行元ルート)
  test/               ホスト側パーサテスト
worker/     Cloudflare Worker: 認証 API + Durable Object WS リレー + 静的配信
  src/index.ts        セッション/TOTP 認証、/device/:id ゲート、DeviceSession DO
  schema.sql          D1 アカウント/レートリミット用テーブル
  scripts/            totp.mjs, ws-test.mjs, e2e-sim.mjs, e2e-it.mjs
web/        依存ゼロの Web UI(ES modules + WebCrypto のみ)
  app.js, e2e.js, index.html, styles.css
```

## ワイヤープロトコル

完全な仕様は [Detailed-Spec.ja.md](Detailed-Spec.ja.md) を参照。

ハンドシェイク(平文 WS テキスト):

```
browser → {"type":"key-req","nonce":"<32 hex>"}
device  → {"type":"hello","fw":"pico2kvm","spub":"<130 hex>",
           "epub":"<130 hex>","sig":"<128 hex r||s>"}
             sig = ECDSA-SHA256(静的秘密鍵, SHA256(nonce || epub))
browser → {"type":"key","pub":"<130 hex ブラウザエフェメラル>"}
device  → 暗号化 {"type":"ready"}
```

データフレーム(WS バイナリ): `[0x02][seq u32 LE][ciphertext][GCM tag 16]`

- セッション鍵: `HKDF-SHA256(ECDH.X, salt=SHA256(pairing) or 32×0,
  info="pico2kvm-e2e-v1")`
- nonce(12B): `[dir][0×7][seq LE]`、dir 0 = browser→device、1 = 逆
- browser→device の平文: 8バイト HID レポート `[0x01][modifier][k1..k6]`
- 任意のペアリングコードを設定すると HKDF salt になり、セッション
  Cookie を盗まれた場合の多層防御になります

## デプロイ

### Worker

```sh
cd worker
npm install
wrangler d1 create pico2kvm            # database_id を wrangler.toml に設定
wrangler d1 execute pico2kvm --remote --file schema.sql
wrangler secret put DEVICE_TOKEN       # デバイス用のランダム bearer トークン
wrangler secret put SESSION_SECRET     # ランダム HMAC シークレット
wrangler deploy
```

`wrangler.toml`/`SERVER_HOST` のデプロイ名は `pico2kvm` です。初回
デプロイ前に変えても構いません。

### ファームウェア

必要なもの: Pico SDK 2.x(`PICO_SDK_PATH`)、CMake、Ninja、ARM GCC
ツールチェーン、Node.js(configure 時のデバイス鍵生成に使用)。

```sh
cmake -S firmware -B firmware/build -G Ninja \
  -DPICO_BOARD=pico2_w \
  -DWIFI_SSID=... -DWIFI_PASSWORD=... \
  -DDEVICE_TOKEN=<Worker と同じシークレット> \
  -DSERVER_HOST=<your-worker>.workers.dev \
  -DPAIRING_CODE=<任意>
cmake --build firmware/build
# BOOTSEL を押しながら USB 接続し、build/pico2kvm.uf2 を RP2350 ドライブへ
```

`device_key.h` と `device_fingerprint.txt` は `firmware/` に一度だけ生成
されます(両方 gitignore)。削除して再ビルドするとデバイス ID を更新
でき、ブラウザの `pico2kvm-fp-*` localStorage を消せば再ピン留めできます。

### 初回起動

`https://<your-worker>.workers.dev` を開き、パスワードを設定し、表示された
TOTP シークレットを認証アプリに登録、ログインして **接続** を押し、
フィンガープリントを `firmware/device_fingerprint.txt` と照合してから
タイプします。

## テスト

```sh
cd worker
npm run typecheck
node scripts/e2e-sim.mjs        # プロトコル暗号テスト(純 Node)
node scripts/ws-test.mjs http://localhost:8787 <device-token> <pw> <totp-secret>
node scripts/e2e-it.mjs         # wrangler dev に対するリレー+暗号の統合テスト
```

## セキュリティ上の注意・制限

- デバイス側 TLS は **GTS Root R4 ピン留めの VERIFY_REQUIRED**。
  Cloudflare が workers.dev の発行 CA を変えた場合は `gtsr4.pem` の
  差し替えと再書き込みが必要です。
- セッション Cookie の有効期間は 8 時間。`/api/login` は 10 分あたり
  10 回まで。
- デバッグ出力は UART(GP0/GP1、115200 baud)に出ます。

## License

MIT — [LICENSE](LICENSE) を参照。
