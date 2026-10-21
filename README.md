# WEBランタン システム設計書

## 1. システム概要

本システム（WEBランタン）は、Webブラウザおよび外部APIを通じて複数台（#1〜#4）の「ランタン（照明デバイス）」の点灯・消灯ステータスおよび有効化状態をリアルタイムに一元管理・監視するWebアプリケーションです。

### 主要特徴

* **リアルタイムステータス監視・制御**: ブラウザ上での点灯/消灯切り替え、およびPicture-in-Picture (PiP) モードによる常時ミニウィンドウ表示。
* **多層的なアクセス制御**: 一般ユーザーおよび管理者ポータルによる二重構造の権限分離。
* **API連携機能**: 各ユーザーに割り当てられる共有APIキーを用いたcURL等の外部通信制御。
* **高度な死活監視システム**: クライアントごとのハートビート（生存確認）計測とタイムアウト時の通知アラート。

## 2. システム構成・ディレクトリ構造

```text
/ (ルートディレクトり)
├── CNF/
│   └── config.php          # 共通設定ファイル
├── DB/
│   └── WEBLAMP.db          # SQLite データベースファイル
├── HTML/
│   ├── index.html          # 一般ユーザー用メイン画面・PiP制御 [source: 19]
│   ├── admin_4.html        # 管理者専用ポータル画面 [source: 18]
│   ├── verify.php          # パスワード設定・再設定処理 [source: 17]
│   ├── api.php             # バックエンドAPI・認証・ビジネスロジック [source: 22]
│   ├── lanthan_on.svg      # ランタン点灯表示用アイコン [source: 21]
│   └── lanthan_off.svg     # ランタン消灯表示用アイコン [source: 20]
└── CRON/
    └── check_disconnect.php# クライアント死活監視用定期実行スクリプト [source: 23]
```

## 3. データベース設計 (SQLite3)

使用データベース: `WEBLAMP.db`

### 3.1 `users` テーブル（ユーザー管理）

ユーザーアカウント情報、権限、各ランタンのステータス・有効化状態を保持します。

| カラム名 | 型 | 制約 / 初期値 | 説明 |
| --- | --- | --- | --- |
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 一意の識別ID |
| `user_id` | TEXT | UNIQUE NOT NULL | ユーザーID（メールアドレス等） |
| `username` | TEXT | NOT NULL | ユーザー表示名 |
| `password_hash` | TEXT | - | ハッシュ化パスワード (`password_hash`) |
| `api_key` | TEXT | UNIQUE | 外部API用認証キー (`key_...` / `admin_key_...`) |
| `flag1`〜`flag4` | INTEGER | DEFAULT 0 | ランタン#1〜#4のステータス（`0`: 消灯, `1`: 点灯） |
| `enable1`〜`enable4` | INTEGER | DEFAULT 0 | ランタン#1〜#4の有効化状態（`0`: 無効, `1`: 有効） |
| `is_admin` | INTEGER | DEFAULT 0 | 管理者フラグ（`0`: 一般, `1`: 管理者） |
| `status` | TEXT | DEFAULT 'pending' | アカウント状態 (`pending`, `active`) |
| `verify_token` | TEXT | - | メール検証・パスワード再設定用トークン |
| `token_expires` | INTEGER | - | トークン有効期限 (UNIXタイムスタンプ) |
| `last_access` | INTEGER | - | 最終アクセス日時 (UNIXタイムスタンプ) |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 登録日時 |

### 3.2 `active_sessions` テーブル（接続クライアント死活監視）

クライアント単位（ブラウザ端末・タブなど）での接続生存確認データを保持します。

| カラム名 | 型 | 制約 / 初期値 | 説明 |
| --- | --- | --- | --- |
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 一意の識別ID |
| `user_id` | TEXT | NOT NULL | 紐付くユーザーID |
| `client_id` | TEXT | NOT NULL | クライアント個別識別ID |
| `ip_address` | TEXT | - | 接続元IPアドレス |
| `user_agent` | TEXT | - | 接続元User-Agent文字列 |
| `last_heartbeat` | INTEGER | NOT NULL | 最終ハートビート受信日時 (UNIXタイムスタンプ) |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 接続開始日時 |

* 複合一意制約: `UNIQUE(user_id, client_id)`

### 3.3 `status_logs` テーブル（変更履歴ログ）

ランタンのステータス変更履歴を記録します。

| カラム名 | 型 | 制約 / 初期値 | 説明 |
| --- | --- | --- | --- |
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 一意の識別ID |
| `user_id` | TEXT | NOT NULL | 操作を行ったユーザーID |
| `target` | INTEGER | NOT NULL | 操作対象ランタン番号 (1〜4) |
| `flag` | INTEGER | NOT NULL | 設定後のステータス（`0`: 消灯, `1`: 点灯） |
| `created_at` | TIMESTAMP | DEFAULT (localtime) | 変更日時 |

## 4. APIエンドポイント仕様 (`HTML/api.php`)

レスポンス形式はすべて **JSON**（ログダウンロード機能を除く）です。

### 4.1 認証・ユーザー管理 API

| アクション名 (`action`) | HTTPメソッド | 概要 | 主なパラメータ / 処理内容 |
| --- | --- | --- | --- |
| `register` | POST | 一般ユーザー仮登録 | **Body**: `username`, `email`<br>仮登録メール送信（トークン生成・24時間有効） |
| `reset_password_request` | POST | パスワード再設定依頼 | **Body**: `email`<br>再設定用メール送信 |
| `login` | POST | ユーザーログイン | **Body**: `user_id`, `password`<br>セッション開始・セッションID再生成 |
| `logout` | POST / GET | ログアウト | アクティブセッション破棄・クッキー削除 |

### 4.2 ステータス取得・外部API制御

| アクション名 (`action`) | HTTPメソッド | 概要 | 主なパラメータ / 処理内容 |
| --- | --- | --- | --- |
| `get_status` | GET | ステータス取得 & 生存通知 | **GET**: `client_id`<br>最新ステータス返却および`active_sessions`の更新 |
| `set_status_cmd` | GET | APIキーによる状態変更 | **GET**: `api_key`, `target` (1~4), `flag` (0/1), `client_id`<br>ステータス更新・ログ記録・生存通知更新 |
| `download_logs` | GET | CSVログ出力 | 過去500件の操作ログをUTF-8（BOM付き）CSVでダウンロード |

### 4.3 管理者専用 API

| アクション名 (`action`) | HTTPメソッド | 概要 | 主なパラメータ / 処理内容 |
| --- | --- | --- | --- |
| `admin_check` | GET | 管理者存在チェック | 管理者アカウントの登録有無を判定 |
| `admin_register` | POST | 管理者初期登録 | **Body**: `username`, `email`<br>初回管理者登録メールを送信 |
| `admin_get_users` | GET | 全ユーザー・接続監視取得 | 全ユーザー情報、各ランタン有効化フラグ、接続中のクライアント一覧を返却 |
| `admin_set_enable` | POST | ランタン有効/無効切り替え | **Body**: `id`, `target` (1~4), `enable` (0/1) |
| `admin_set_flag` | POST | ランタン点灯/消灯強制切替 | **Body**: `id`, `target` (1~4), `flag` (0/1) |
| `init_db` | GET/POST | DB初期化 | テーブル全削除および再作成（デバッグ・初期化用） |

## 5. バックエンド処理機能 (`HTML/verify.php`)

メール本文中のリンク（トークン付きURL）から遷移して実行されるアカウント本登録・パスワード設定処理です。

* **トークン検証 (GET)**: URLクエリの `token` をもとに `users` テーブルを検索し、有効期限（24時間以内）をチェック。

* **パスワード更新 (POST)**:
* パスワードバリデーション（8文字以上かつ確認用の一致）。
* `password_hash()` による暗号化保存。
* APIキーの発行（一般: `key_...`, 管理者: `admin_key_...`）。
* `status` を `'active'` に更新し、トークン情報を破棄 (`NULL`)。

## 6. フロントエンド機能構造

### 6.1 一般ユーザーポータル (`HTML/index.html`)

* **マルチ画面制御**: ログイン、仮登録、パスワード再設定、メイン制御カードを非同期（`fetch`）で表示切替。
* **ポーリング（自動同期）**: 3秒間隔で `get_status` を実行し、ランタンの最新状態（`flags` / `enabled_flags`）を同期。
* **Picture-in-Picture (PiP) モード**:
* Document Picture-in-Picture APIを利用し、ブラウザ外でも独立して浮遊表示されるミニウィンドウを生成。
* 管理者によって有効化（`enable=1`）されたランタンのみを表示・操作対象とする。
* ステータスが点灯に変わった際、ウィンドウ背景をフラッシュ点滅させて視覚的に通知。
* **API連携UI**: 割り当てられたAPIキーのコピー機能および cURL コマンド自動生成機能。

### 6.2 管理者ポータル (`HTML/admin_4.html`)

* **動的コンポーネント切り替え**:
* 管理者未存在時: 初期登録カードを表示。
* 管理者存在時: 管理者ログイン画面を表示。

* **リアルタイム監視・制御ポータル**:
* 全ユーザーのステータス、APIキー、各ランタン（#1〜#4）の有効化（`enable`）状態および点灯（`flag`）状態の切り替え。
* 各ユーザーに紐づく接続クライアント（`client_id`）の生存（`Online` / `Offline`）判定結果をバッジ表示。

## 7. 死活監視スクリプト (`CRON/check_disconnect.php`)

定期的なCRON実行により、無通信状態になったクライアントを監視・通知します。

* **判定ロジック**: `active_sessions` テーブルの `last_heartbeat` と現在時刻（`time()`）を比較。
* **閾値**: **60秒間** 以上ハートビート更新がないセッションを「通信断絶（オフライン）」と判定。
* **警告通知**: オフラインを検知した場合、該当ユーザー名、クライアントID、IPアドレス、最終アクセス日時を取りまとめ、管理者宛（`admin@example.com`）へメールを送信。
