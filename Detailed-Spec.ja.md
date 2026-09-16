# Pico2KVM — 通信詳細仕様

[English](Detailed-Spec.md)

ブラウザ・Cloudflare Worker・RP2350 デバイス間でバイトがどう流れるかを、
認証・フレーミング・E2E ハンドシェイク・再送制御・全タイマー/定数まで
正確に解説するドキュメントです。

まず用語と通信の全体像を説明し、そのあと各層の詳細に入ります。

## 用語集

| 用語 | 意味 |
|---|---|
| USB HID | キーボードやマウスとして PC に認識されるための規格。OS標準ドライバで動くので、対象 PC 側にソフトのインストールは不要 |
| HID レポート | 「どのキーが押されているか」を表す 8 バイトのデータ(修飾キー + 最大6キー)。これを送ると PC は本物のキーボード入力として処理する |
| WebSocket / WSS | HTTP から始まる双方向の常時接続。WSS は TLS 暗号化付きの WebSocket |
| TLS | 通信路そのものを暗号化する仕組み(HTTPS の「S」)。サーバ証明書で相手を認証する |
| CA ピン留め | 「この認証局(CA)が発行した証明書しか信じない」とあらかじめ決めておくこと。間違った/偽の証明書を弾ける |
| Durable Object (DO) | Cloudflare の「状態を持つ Worker」。ID ごとに1個だけ存在し、今回は2本のソケットの中継役として使う |
| NAT | 家庭/社内ネットワークの内側から外には出られるが、外から内には直接入れない仕組み。デバイスが外向きに接続する理由 |
| E2E 暗号 | 通信の両端(ブラウザとデバイス)だけが読める暗号化。中継の Worker にも平文は見えない |
| 静的鍵 / エフェメラル鍵 | 静的 = 長期間使う「身分証明書」的な鍵。エフェメラル = 接続ごとに作り捨てる鍵 |
| ECDH | お互い公開鍵だけを交換して、通信の外にいる人には分からない共有秘密を導き出す方式 |
| ECDSA | 秘密鍵で署名し、公開鍵で検証する仕組み。「この鍵を本当に持っている」の証明に使う |
| HKDF | 共有秘密から「安全な暗号鍵」を作る関数。salt/info で鍵の用途を分離できる |
| AES-256-GCM | 暗号化と改ざん検知を同時に行う方式。同じ nonce を二度使うと破られるので連番で管理する |
| nonce | 「一度だけ使う数」。ここではハンドシェイクの使い回しを防ぐための乱数 |
| seq(シーケンス番号) | メッセージごとの連番。過去のメッセージの再送(リプレイ攻撃)を検知する |
| フィンガープリント | 公開鍵をハッシュして短くしたもの。人間が目視で照合できる |
| TOFU | Trust On First Use。初回に見たフィンガープリントを信頼して保存し、以後ずれたら警告する方式(SSH と同じ考え方) |
| Forward secrecy | 後から秘密鍵が漏れても、過去の通信内容は復号できない性質 |
| PBKDF2 | パスワードをわざと何万回もハッシュして、総当たりを遅くする方式 |
| TOTP | 30秒ごとに変わる6桁のコード(二要素認証アプリの数字)。パスワードの2要素目 |
| MITM | 中間者攻撃。通信路の途中に割り込んで盗聴・改ざんする攻撃 |

## 通信の流れ(Step by Step)

1 回の打鍵が対象 PC に届くまでの全手順です。

### A. デバイスの起動〜オンライン

1. Pico 2 W に電源が入る → Wi-Fi に接続(失敗したら10秒ごとにリトライ)。LED は消灯→点滅に変わる
2. DNS で `SERVER_HOST` を解決 → TCP 443 へ接続 → TLS ハンドシェイク。証明書は埋め込みの GTS Root R4 と照合し、違えばここで中止
3. `GET /device/default` に `Authorization: Bearer <DEVICE_TOKEN>` を付けて WS アップグレードを要求
4. Worker がトークンを照合 → Durable Object に接続 → 「デバイス役」ソケットとして登録。LED が点灯 = オンライン

### B. ブラウザのログイン〜E2E 確立

5. ブラウザで URL を開き、パスワード + TOTP でログイン → `session` Cookie を受け取る
6. 「接続」ボタン → `wss://…/device/default` へ WS 接続 → DO が「ブラウザ役」として登録し、デバイスが居るかを `peer` メッセージで通知
7. ブラウザが `key-req`(16 バイトの乱数 nonce)を送信
8. デバイスが使い捨てのエフェメラル鍵ペアを生成し、静的公開鍵・エフェメラル公開鍵・署名を `hello` で返す
9. ブラウザは静的公開鍵のフィンガープリントを照合(初回のみ目視確認)+ 署名を検証 → 自分のエフェメラル公開鍵を `key` で送信
10. 両側が ECDH で共有秘密を導出 → HKDF(ペアリングコードが salt)で同じ AES-256-GCM 鍵を得る
11. デバイスが暗号化した `ready` を送信 → ブラウザが復号できたら「E2E 接続済み」。復号できない = ペアリングコード間違いか偽物

### C. 打鍵(以降、繰り返し)

12. ユーザーがキーを押す → ブラウザが `KeyboardEvent.code` を HID usage に変換し、8 バイトのレポートを組み立てる
13. AES-256-GCM で暗号化して seq を付与 → WS バイナリフレーム → Worker/DO が**中身を見ずに**そのままデバイスへ転送
14. デバイスが seq を検査(古い番号は捨てる)→ 復号 → `tud_hid_keyboard_report()` → 対象 PC が普通の USB キーボード入力として受け取る

### D. 切断・再接続

15. WS が切れると、デバイスは「全キー離し」レポートをキューに積み(押しっぱなし防止)、E2E の状態を全て破棄してバックオフ後に手順 2 へ戻る
16. ブラウザは DO からデバイスの再参加を通知されると、古いセッションを捨てて手順 7 からハンドシェイクをやり直す

## 1. トポロジ

```
┌──────────┐   HTTPS/WSS    ┌────────────────────────┐   WSS(デバイス起点)   ┌─────────┐   USB HID   ┌────────┐
│ ブラウザ │ ◄────────────► │ Worker → DeviceSession │ ◄──────────────────► │ RP2350  │ ──────────► │ 対象PC │
└──────────┘                │ Durable Object (リレー)│                       │ ボード  │  キーボード │        │
                            └────────────────────────┘                       └─────────┘             └────────┘
```

- **デバイスは常に外向きに接続**する: Wi-Fi STA → DNS → TCP 443 → TLS →
  WS アップグレード。受信リスナーは存在せず、NAT/ファイアウォール越しでも
  動きます。
- **ブラウザ**も同じ Worker オリジンへ WSS で接続。
- `/device/:id` で名付けられた **Durable Object** は、最大1本のデバイス
  ソケットと最大1本のブラウザソケットの間の単純なバイト中継。
- **暗号は独立した2層**:
  1. 両 WebSocket 区間の TLS(デバイス↔Worker は GTS Root R4 ピン留め)
  2. WebSocket ペイロード**内部**の E2E 暗号 — リレーや経路上の観察者には
     常に暗号文しか見えない

## 2. HTTP レイヤ(Worker)

`worker/src/index.ts` のルーティング:

| ルート | メソッド | 認証 | 用途 |
|---|---|---|---|
| `GET /api/setup` | GET | なし | `{configured: bool}` |
| `POST /api/setup` | POST | 初回のみ・`SETUP_TOKEN` 設定時はそれも必要 | アカウント作成、TOTP シークレット+otpauth URI を返す。競合時は 409 |
| `POST /api/login` | POST | パスワード+TOTP | `session` Cookie を発行 |
| `POST /api/logout` | POST | — | Cookie 破棄 |
| `GET /api/status` | GET | なし | `{ok, configured}` |
| `/device/:id` | GET(Upgrade) | デバイス: `Authorization: Bearer <DEVICE_TOKEN>`、ブラウザ: `session` Cookie | DO へ転送 |
| その他 | GET | なし | 静的アセット(セキュリティヘッダ付与のため Worker 経由) |

### ログインまわり

- パスワードは `pbkdf2$<iters>$<salt_hex>$<hash_hex>` 形式で保存
  (PBKDF2-SHA-256、10万回 — Workers WebCrypto の上限 — 、16B salt、
  256bit 出力)。旧形式(無 salt SHA-256)の行は一度だけ検証され、
  次回のログイン成功時に PBKDF2 形式へ自動書き換え。
- レートリミット: クライアント IP(`cf-connecting-ip`)ごとに10分間の
  ローリングウィンドウで最大10回の失敗まで(`login_attempt`
  テーブル)。超過は 429。ログイン成功でその IP の行を消去。
- セッショントークン: `<exp_ms>.<HMAC-SHA256(exp)>` を `SESSION_SECRET`
  で署名。Cookie は `Secure; HttpOnly; SameSite=Strict`、有効期間 8時間。
  トークンはログイン時に D1 の `session` テーブルにも記録され検証時に
  照合されるため、`/api/logout`(または行の削除)で実際に失効する。
- 101 Upgrade 以外の全レスポンスにセキュリティヘッダ:
  `Strict-Transport-Security`、`Content-Security-Policy`、
  `X-Content-Type-Options`、`Referrer-Policy`、`X-Frame-Options`、
  `Permissions-Policy`。

## 3. WebSocket 区間: ブラウザ ↔ Worker ↔ デバイス

### 3.1 デバイス側接続(ファーム `ws_client.c`)

```
GET /device/<id> HTTP/1.1
Host: <server>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <b64 16B>
Sec-WebSocket-Version: 13
Authorization: Bearer <DEVICE_TOKEN>
User-Agent: pico2kvm
```

- 先に TLS: `altcp_tls` + mbedTLS、`VERIFY_REQUIRED`、SNI =
  `SERVER_HOST`、チェーンは埋め込み `gtsr4.pem`(GTS Root R4 —
  `*.workers.dev` の発行元 CA)にピン留め。証明書の有効期限は
  `BUILD_EPOCH + 起動からの経過時間` で検証(ボードに RTC が無いため)。
- HTTP 応答はステータス行(`HTTP/1.1 101`)と `Sec-WebSocket-Accept`
  (送信したキーから `base64(SHA1(key || "258EAFA5-E914-47DA-95CA-
  C5AB0DC85B11"))` を計算して照合)を検査。不一致なら拒否。
  `\r\n\r\n` までのヘッダは pending バッファ(最大2048B)で消費。
- クライアント→サーバのフレームは RFC 6455 通りマスク付き
  (xorshift32 PRNG でマスク生成)。
- サーバ→クライアントのフレームはファーム側でアンマスクしてから処理。

### 3.2 ブラウザ側接続

`new WebSocket("wss://<host>/device/default")` — session Cookie が自動で
載る。ブラウザの WS API は追加ヘッダを付けられないため、デバイス役は
`Authorization`、ブラウザ役は Cookie で認証する、という非対称設計。

### 3.3 Durable Object リレー(`DeviceSession`)

- 役割は Worker が付ける内部ヘッダ `X-Pico2KVM-Role` で伝達。
- 役割ごとにソケット1本。同じ役割の新規接続は**既存を置き換える**
  (旧ソケットは code 1000 "replaced" で close)。
- ブラウザ接続時に `{"type":"peer","device":<bool>}` を送信。
  デバイスソケットの接続/切断時には全ブラウザへ
  `{"type":"peer","device":true|false}` を通知。
- メッセージ転送: 片方のソケットのフレームを反対側へそのまま転送。
  `Blob`/`ArrayBufferView` は先に `ArrayBuffer` へ正規化(Cloudflare は
  バイナリを `Blob` で渡す; 生で送ると `"[object Blob]"` 文字列になる)。
- `MAX_FRAME = 16384` バイト超のフレームは送信側ソケットを 1009 で
  close。内容の検査は一切なし — DO は平文を見ない。

## 4. E2E ハンドシェイク

ハンドシェイクのメッセージはすべて平文の WS **テキスト**フレームで、
DO 経由でリレーされる。ブラウザ側の手順(`web/app.js`):

```
ブラウザ ──WS open──► {"type":"key-req","nonce":"<32 hex>"} を送信 (16B乱数)
デバイス ──text────►  {"type":"hello","fw":"pico2kvm",
                       "spub":"<130 hex>",      // 静的 P-256 公開鍵 0x04||X||Y
                       "epub":"<130 hex>",      // 毎回生成のエフェメラル公開鍵
                       "sig":"<128 hex>"}       // ECDSA r||s
                        sig = ECDSA-SHA256(静的秘密鍵, SHA256(nonce_bytes || epub_bytes))
ブラウザ: 1. fingerprint = SHA256(spub) → localStorage のピン留めと照合
          2. spub で sig を検証(静的鍵の保有証明)
          3. 初回のみ: フィンガープリントを画面表示しユーザー確認(TOFU)
          4. セッション鍵を導出してから
             ──text──► {"type":"key","pub":"<130 hex ブラウザエフェメラル>"}
デバイス:  ECDH(eph_d, browser_pub) → HKDF → AES-256-GCM 鍵
           ──binary──► {"type":"ready"} の E2E フレーム
ブラウザ:  ready を復号 → 「E2E 接続済み」(5秒でタイムアウト)

DO がデバイスの(再)参加を通知({"type":"peer","device":true})し、
key-req が処理中でなければ、ブラウザはセッション状態を捨てて新しい
key-req を送る — デバイスは再接続のたびに E2E 状態をリセットするため、
古いセッション鍵はもう存在しない。
```

要点:

- **静的鍵は認証専用**。署名に使い、暗号化には使わない。ファーム
  configure 時に一度だけ `device_key.h` へ生成される(gitignore 済み)。
- **Forward secrecy**: ECDH の共有秘密は両側エフェメラル鍵から導出。
  デバイスは `key-req` のたびにエフェメラル鍵ペアを再生成し、切断・
  再鍵交換時にゼロ化する。
- **nonce は必須**で、署名をこのハンドシェイクに紐付けるため、hello の
  リプレイは新しい `key-req` には使えない。有効な16B hex の nonce を
  持たない `key-req` は無視される。
- **TOFU ピン留め**: `SHA256(spub)` をユーザー確認後に
  `pico2kvm-fp-default` として localStorage に保存。以後の不一致は
  ECDH 前に中断。
- **ペアリングコード**(必須): ファームは `-DPAIRING_CODE` 必須で
  ビルドされる(未設定だと CMake が失敗し、`e2e_init` も実行時に
  fail-closed)。`e2e_salt = SHA256(UTF8(code))`、ブラウザは入力欄から
  同じ salt を導出。これが**ブラウザ側を認証する**仕組み: コードを
  知らない相手は別の鍵を導出するため、送ったフレームは全て GCM 認証に
  落ちる。これが無いと、盗まれたセッション Cookie だけでキー入力を
  注入できてしまう。高エントロピーのコードを選ぶこと。

### セッション鍵導出

```
shared = ECDH(エフェメラル同士) の X 座標   (32B)
key    = HKDF-SHA256(ikm=shared, salt=SHA256(ペアリングコード), info="pico2kvm-e2e-v1", 32)
cipher = AES-256-GCM
```

## 5. E2E データフレーム

WS **バイナリ**フレーム。ワイヤー形式:

```
[0x02][seq: u32 LE][ciphertext][GCM tag: 16B]
   0        1..4          5..        末尾16
```

- `seq` は方向ごとの単調増加カウンタで、ハンドシェイクごとに 0 に
  リセット(両側で `txSeq`/`rxSeqMax` を再初期化)。
- **nonce(12B)**: `[dir][ゼロ7B][seq u32 LE]`。
  `dir` 0 = ブラウザ→デバイス、1 = デバイス→ブラウザ。方向分離により
  両側で nonce が衝突しない。
- **リプレイ拒否**: `seq <= 認証済みの最大値` は復号前にドロップ
  (ウィンドウは有効な GCM タグの時だけ進む)。
  (厳密な単調増加。並び替え窓は無い — TCP が順序を保証するため)
- **ダウングレード防止**: デバイスは `0x02` で始まりちょうど
  `21+8` バイトのバイナリフレームしか受け付けない。仮に平文の `0x01`
  レポートが来ても黙って捨てる。
- 内部平文(ブラウザ→デバイス): 8バイト HID キーボードレポート
  `[0x01][修飾ビットマップ][key1..key6]`(boot protocol 形式)。
  デバイス→ブラウザ方向は予約(現状 `{"type":"ready"}` の JSON のみ)。

## 6. ファームの状態機械

### 6.1 Wi-Fi(`main.c`)

- リンクダウン中は `cyw43_arch_wifi_connect_async` を **10秒ごと**に
  再試行(1秒ごとにリンク確認)。
- ウォッチドッグ 8秒。メインループが毎回 feed。

### 6.2 WebSocket クライアント(`ws_client.c`)

```
WS_IDLE ──リンク確立──► WS_DNS ──► WS_CONNECTING ──► WS_HANDSHAKE ──101──► WS_OPEN
   ▲                                                                              │
   └───────────────── WS_BACKOFF ◄── あらゆるエラー/タイムアウト/close ◄────────────┘
```

タイマー一覧:

| 定数 | 値 | 意味 |
|---|---|---|
| `WS_PING_MS` | 20 000 | オープン中は20秒ごとにクライアント ping |
| `WS_RX_TIMEOUT_MS` | 60 000 | 受信が無いと再接続 |
| `WS_HS_TIMEOUT_MS` | 15 000 | アップグレードの完了期限 |
| `WS_BACKOFF_INIT_MS` | 2 000 | 初回リトライ待ち |
| `WS_BACKOFF_MAX_MS` | 30 000 | 倍増の上限 |

- `WS_BACKOFF` への遷移ごとに `e2e_reset()`(エフェメラル鍵破棄・
  シーケンスカウンタ消去 — 次のブラウザは再ハンドシェイク必須)と、
  全キー解放レポートをキューに積む(対象 PC でキーが押しっぱなしに
  ならないように)。
- 受信レポートは16エントリの SPSC リング(コールバック→メインループ)
  を経由。満杯なら最新のレポートを落とす。
- 巨大な受信 WS ペイロードはバッファせず `ws_skip_len` で読み飛ばす
  (pending バッファは 2KiB)。

### 6.3 USB HID(`main.c`)

- `tud_hid_ready()` の間、ポップしたレポートごとに
  `tud_hid_keyboard_report(0, modifier, keys)` を呼ぶ。
- LED: **消灯** = Wi-Fi リンク無し · **500ms 点滅** = Wi-Fi 接続済み・
  WS 未確立 · **点灯** = WS オープン。

## 7. ブラウザ送信経路(`web/app.js`)

- 物理位置マッピング: `KeyboardEvent.code` → HID usage(US 配列 +
  JIS の `IntlRo`/`IntlYen`/`Convert` 等)。修飾ビットは別途追跡し、
  状態変化ごとに完全なレポートを1通送る。
- 送信は promise チェーン(`queueSend`)で直列化し、`seq` 番号と
  ワイヤー上の順序が常に一致するようにする。
- `blur` / WS close → `releaseAll()`(空レポート)で押下キーを解除。
- テキスト送信は各 ASCII 文字を押下+解放として 20ms 間隔で打鍵。
- ボタン: Enter/Backspace/Tab/Esc/Ctrl+Alt+Del/Win を `sendRaw` で送信。

## 8. 主な失敗モード

| 症状 | 原因 |
|---|---|
| `E2E 確立失敗` | ペアリングコードの不一致/未入力、または 5秒以内に `ready` が復号できない |
| `フィンガープリント不一致!` | デバイス静的鍵の変更または MITM — 鍵交換の前に中断 |
| `ファームウェアが古い` | hello に `epub`/`sig` が無い(FS 前のファーム) |
| 対象 PC でキーが押しっぱなし | ファーム稼働中は原理的に起きない: WS 切断のたびに release-all をキュー投入。押下中のハードな電源断のみ起こり得る |
| 数年後に TLS 失敗 | 埋め込み `BUILD_EPOCH` が証明書の有効期間外 — 再ビルド&再書き込み |
| ログインで 429 | 10分で10回超の失敗 |
