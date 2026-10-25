<?php
/**
 * HTML/api.php - API・認証処理エンドポイント
 * ユーザー登録、ログイン、ステータス変更、複数セッションの死活監視（ハートビート）、ログ出力(CSV)などを制御します。
 */

// セキュリティ向上のためのセッション設定と開始
session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax'
]);

// CSRFトークンの生成（セッションに存在しない場合）
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// レスポンスヘッダーの設定（JSON固定）
header('Content-Type: application/json; charset=utf-8');

// パス・設定の定義
$baseDir = dirname(__DIR__);
$configPath = $baseDir . '/CNF/config.php';

if (file_exists($configPath)) {
    require_once $configPath;
}

if (!defined('BASE_DIR')) {
    define('BASE_DIR', $baseDir);
}
if (!defined('DB_PATH')) {
    define('DB_PATH', BASE_DIR . '/DB/WebLantern.db');
}

/**
 * DB接続および初期テーブル（users, status_logs, active_sessions）の自動生成
 */
function getDBConnection() {
    $dbPath = DB_PATH;
    $dbDir = dirname($dbPath);

    try {
        if (!file_exists($dbDir)) {
            @mkdir($dbDir, 0777, true);
        }

        // PDO接続オプションにタイムアウトを設定（5秒間待機）
        $pdo = new PDO('sqlite:' . $dbPath, null, null, [
            PDO::ATTR_TIMEOUT => 5,
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]);

        // WALモードとビジータイムアウトを有効化（同時読み書きの競合防止）
        $pdo->exec("PRAGMA journal_mode = WAL;");
        $pdo->exec("PRAGMA busy_timeout = 5000;");

        // ユーザー管理用テーブル
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                password_hash TEXT,
                api_key TEXT UNIQUE,
                parent_admin_id TEXT DEFAULT NULL,
                flag1 INTEGER DEFAULT 0,
                flag2 INTEGER DEFAULT 0,
                flag3 INTEGER DEFAULT 0,
                flag4 INTEGER DEFAULT 0,
                enable1 INTEGER DEFAULT 0,
                enable2 INTEGER DEFAULT 0,
                enable3 INTEGER DEFAULT 0,
                enable4 INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                verify_token TEXT,
                token_expires INTEGER,
                last_access INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ");

        // parent_admin_id カラムが存在しない場合に自動追加（既存DBの互換性確保）
        $cols = $pdo->query("PRAGMA table_info(users)")->fetchAll();
        $hasParentAdmin = false;
        foreach ($cols as $col) {
            if ($col['name'] === 'parent_admin_id') {
                $hasParentAdmin = true;
                break;
            }
        }
        if (!$hasParentAdmin) {
            $pdo->exec("ALTER TABLE users ADD COLUMN parent_admin_id TEXT DEFAULT NULL");
        }

        // クライアントごとのアクティブセッション管理テーブル（死活監視用）
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS active_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                last_heartbeat INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, client_id)
            )
        ");

        // ステータス変更ログ用テーブル
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS status_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                target INTEGER NOT NULL,
                flag INTEGER NOT NULL,
                source TEXT DEFAULT 'unknown',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ");

        return $pdo;
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'データベース接続エラー: ' . $e->getMessage()
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

/**
 * CSRFトークン検証関数
 */
function verifyCsrfToken() {
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (empty($token) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => '無効なCSRFトークンです。ページをリフレッシュして再試行してください。'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

/**
 * クライアント個別のハートビート（死活状態）を記録・更新する関数
 */
function updateClientHeartbeat($pdo, $userId, $clientId) {
    if (empty($userId) || empty($clientId) || strpos($clientId, 'session_') === 0) return;

    $now = time();

    // 10秒以内の頻繁な書き込み更新を抑止してDBロックを回避
    $sessionKey = 'last_hb_' . md5($clientId);
    if (isset($_SESSION[$sessionKey]) && ($now - $_SESSION[$sessionKey]) < 10) {
        return;
    }

    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);

    try {
        $stmt = $pdo->prepare("
            INSERT INTO active_sessions (user_id, client_id, ip_address, user_agent, last_heartbeat)
            VALUES (:user_id, :client_id, :ip, :ua, :now)
            ON CONFLICT(user_id, client_id) DO UPDATE SET
                ip_address = excluded.ip_address,
                user_agent = excluded.user_agent,
                last_heartbeat = excluded.last_heartbeat
        ");
        $stmt->execute([
            ':user_id' => $userId,
            ':client_id' => $clientId,
            ':ip' => $ip,
            ':ua' => $ua,
            ':now' => $now
        ]);

        $_SESSION[$sessionKey] = $now;
    } catch (PDOException $e) {
        // ロック等で失敗した場合も全体の処理を止めるためログ記録に留める
        error_log("Heartbeat update locked/failed: " . $e->getMessage());
    }
}

/**
 * フラグ・ステータス変更履歴を記録する共通関数
 */
function logStatusChange($pdo, $userId, $target, $flag, $source = 'unknown') {
    try {
        $stmt = $pdo->prepare("
            INSERT INTO status_logs (user_id, target, flag, source, created_at)
            VALUES (:user_id, :target, :flag, :source, datetime('now', 'localtime'))
        ");
        $stmt->execute([
            ':user_id' => $userId,
            ':target'  => $target,
            ':flag'    => $flag,
            ':source'  => $source
        ]);
    } catch (Exception $e) {
        error_log('ログ記録失敗: ' . $e->getMessage());
    }
}

/**
 * メール送信用ヘッダーおよび From アドレスを生成する共通関数
 */
function getMailHeaders() {
    $rawHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $host = preg_replace('/:\d+$/', '', $rawHost);
    
    if (filter_var($host, FILTER_VALIDATE_IP) || $host === 'localhost' || empty($host)) {
        $fromEmail = 'noreply@example.com';
    } else {
        $fromEmail = 'noreply@' . $host;
    }

    $headers = [];
    $headers[] = "From: " . $fromEmail;
    $headers[] = "Reply-To: " . $fromEmail;
    $headers[] = "Content-Type: text/plain; charset=UTF-8";
    $headers[] = "Content-Transfer-Encoding: 8bit";

    return implode("\n", $headers);
}

/**
 * 管理者権限の検証関数
 */
function requireAdminRole() {
    if (empty($_SESSION['user_id'])) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => '未ログインです']);
        exit;
    }
    if (empty($_SESSION['is_admin']) || (int)$_SESSION['is_admin'] !== 1) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => '管理者権限が必要です']);
        exit;
    }
}

// DB接続と入力パラメータの読み込み
$pdo = getDBConnection();
$action = $_REQUEST['action'] ?? ($_GET['action'] ?? '');
$input = json_decode(file_get_contents('php://input'), true) ?? [];

// CSRF検証の適用（点灯・消灯制御 set_status_cmd のみスキップし、有効・無効化処理 user_set_enable や admin_set_enable 等には適用）
$csrfExemptActions = ['set_status_cmd', 'get_csrf_token', 'admin_check', 'get_status', 'download_logs', 'admin_download_user_logs'];
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !in_array($action, $csrfExemptActions, true)) {
    verifyCsrfToken();
}

// ルーティング処理
switch ($action) {

    // CSRFトークン取得用アクション
    case 'get_csrf_token':
        echo json_encode([
            'success' => true,
            'csrf_token' => $_SESSION['csrf_token']
        ]);
        break;

    // ==================================================
    // 0. DB初期化機能
    // ==================================================
    case 'init_db':
        requireAdminRole();
        try {
            $pdo->exec("DROP TABLE IF EXISTS users");
            $pdo->exec("DROP TABLE IF EXISTS active_sessions");
            $pdo->exec("DROP TABLE IF EXISTS status_logs");
            getDBConnection(); // テーブル再生成

            echo json_encode([
                'success' => true,
                'message' => 'データベースを初期化しました（初期状態: 有効ランタン0個 / 全消灯状態）'
            ]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => '初期化エラー: ' . $e->getMessage()]);
        }
        break;

    // ==================================================
    // A. 管理者用API
    // ==================================================
    
    // 管理者アカウントが存在するか確認（常にtrueを返し、ログイン/仮登録を画面選択可能にする）
    case 'admin_check':
        $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM users WHERE is_admin = 1");
        $stmt->execute();
        $row = $stmt->fetch();
        
        echo json_encode(['exists' => true, 'admin_count' => (int)$row['count']]);
        break;

    // 管理者仮登録（複数管理者の作成を許可）
    case 'admin_register':
        $username = trim($input['username'] ?? '');
        $email = trim($input['email'] ?? '');

        if (empty($username) || empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => '有効な氏名とメールアドレスを入力してください']);
            exit;
        }

        $stmt = $pdo->prepare("SELECT status FROM users WHERE user_id = :email");
        $stmt->execute([':email' => $email]);
        $existing = $stmt->fetch();

        if ($existing) {
            if ($existing['status'] === 'active') {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'このメールアドレスは既に登録されています']);
                exit;
            } else {
                $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = :email AND status = 'pending'");
                $stmt->execute([':email' => $email]);
            }
        }

        $token = bin2hex(random_bytes(32));
        $apiKey = 'admin_key_' . bin2hex(random_bytes(16));
        $expires = time() + (24 * 60 * 60); // 24時間有効

        // 管理者は初期状態ですべて無効(enable=0)、消灯(flag=0)
        $stmt = $pdo->prepare("
            INSERT INTO users (user_id, username, api_key, verify_token, token_expires, status, is_admin, flag1, flag2, flag3, flag4, enable1, enable2, enable3, enable4)
            VALUES (:email, :username, :api_key, :token, :expires, 'pending', 1, 0, 0, 0, 0, 0, 0, 0, 0)
        ");
        $stmt->execute([
            ':email' => $email,
            ':username' => $username,
            ':api_key' => $apiKey,
            ':token' => $token,
            ':expires' => $expires
        ]);

        // メール本文の作成と送信（config.phpの設定値を反映）
        if (defined('BASE_URL')) {
            $verifyUrl = rtrim(BASE_URL, '/') . "/verify.php?token={$token}";
        } else {
            $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'];
            $path = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
            $verifyUrl = "{$scheme}://{$host}{$path}/verify.php?token={$token}";
        }

        $mailSubject = "【管理者登録】パスワード設定のご案内";
        $mailBody = "{$username} 様\n\n管理者アカウントの仮登録を受け付けました。\n以下のリンクからパスワードを設定し、本登録を完了してください。\n\n{$verifyUrl}\n\n※有効期限: 24時間";
        $mailHeaders = getMailHeaders();

        $mailSent = mb_send_mail($email, $mailSubject, $mailBody, $mailHeaders);
        if (!$mailSent) {
            error_log("【メール送信失敗】管理者仮登録メールの送信に失敗しました。 宛先: {$email}");
        }

        echo json_encode([
            'success' => true,
            'message' => '仮登録メールを送信しました。メール内のリンクから本登録を行ってください。',
            'dev_verify_url' => $verifyUrl,
            'mail_sent' => $mailSent
        ]);
        break;

    // 管理者用：ログイン中の管理者に紐づくユーザーの一覧・ステータス・各クライアント接続状態の取得
    case 'admin_get_users':
        requireAdminRole();

        $currentAdminUserId = $_SESSION['user_id'] ?? '';

        // ログイン中の管理者アカウント情報（ユニークID等）を取得
        $adminStmt = $pdo->prepare("SELECT user_id, username, api_key FROM users WHERE user_id = :admin_id");
        $adminStmt->execute([':admin_id' => $currentAdminUserId]);
        $adminInfo = $adminStmt->fetch();

        // ログイン中の管理者に紐づく一般ユーザー（parent_admin_id が一致するもの、または未指定のもの）を取得
        $stmt = $pdo->prepare("
            SELECT id, user_id, username, api_key, flag1, flag2, flag3, flag4, enable1, enable2, enable3, enable4, status, is_admin 
            FROM users 
            WHERE is_admin = 0 AND (parent_admin_id = :admin_id OR parent_admin_id IS NULL OR parent_admin_id = '')
            ORDER BY id ASC
        ");
        $stmt->execute([':admin_id' => $currentAdminUserId]);
        $users = $stmt->fetchAll();

        $now = time();
        $timeoutSeconds = 60; // 60秒以内のハートビートでアクティブ判定
        $currentSessionClientId = $_GET['client_id'] ?? ($_SERVER['HTTP_X_CLIENT_ID'] ?? '');

        $formattedUsers = array_map(function($u) use ($pdo, $now, $timeoutSeconds, $currentAdminUserId, $currentSessionClientId) {
            // 各ユーザーのアクティブセッションを取得
            $sStmt = $pdo->prepare("
                SELECT client_id, ip_address, user_agent, last_heartbeat 
                FROM active_sessions 
                WHERE user_id = :user_id 
                ORDER BY last_heartbeat DESC
            ");
            $sStmt->execute([':user_id' => $u['user_id']]);
            $sessions = $sStmt->fetchAll();

            $activeClients = [];
            foreach ($sessions as $s) {
                if (!empty($currentSessionClientId) && $s['client_id'] === $currentSessionClientId) {
                    continue;
                }

                $isAlive = ($now - (int)$s['last_heartbeat']) <= $timeoutSeconds;
                $activeClients[] = [
                    'client_id' => $s['client_id'],
                    'ip_address' => $s['ip_address'],
                    'user_agent' => $s['user_agent'],
                    'last_heartbeat' => $s['last_heartbeat'],
                    'is_alive' => $isAlive
                ];
            }

            return [
                'id' => $u['id'],
                'user_id' => $u['user_id'],
                'username' => $u['username'],
                'api_key' => $u['api_key'],
                'is_admin' => (int)($u['is_admin'] ?? 0),
                'flags' => [
                    (int)($u['flag1'] ?? 0),
                    (int)($u['flag2'] ?? 0),
                    (int)($u['flag3'] ?? 0),
                    (int)($u['flag4'] ?? 0)
                ],
                'enabled_flags' => [
                    (int)($u['enable1'] ?? 0),
                    (int)($u['enable2'] ?? 0),
                    (int)($u['enable3'] ?? 0),
                    (int)($u['enable4'] ?? 0)
                ],
                'status' => $u['status'],
                'clients' => $activeClients
            ];
        }, $users);

        echo json_encode([
            'success' => true,
            'admin_info' => [
                'user_id' => $adminInfo['user_id'] ?? $currentAdminUserId,
                'api_key' => $adminInfo['api_key'] ?? ''
            ],
            'users' => $formattedUsers,
            'csrf_token' => $_SESSION['csrf_token'] ?? ''
        ]);
        break;

    // 管理者用：指定したクライアント（タブ/端末）の強制切断
    case 'admin_kill_session':
        requireAdminRole();

        $userId = trim($input['user_id'] ?? '');
        $clientId = trim($input['client_id'] ?? '');

        if (empty($userId) || empty($clientId)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'パラメータ(user_id, client_id)が不足しています']);
            exit;
        }

        $stmt = $pdo->prepare("DELETE FROM active_sessions WHERE user_id = :user_id AND client_id = :client_id");
        $stmt->execute([
            ':user_id' => $userId,
            ':client_id' => $clientId
        ]);

        echo json_encode([
            'success' => true,
            'message' => '指定されたセッションを切断しました'
        ]);
        break;

    // 管理者用：個別のランタンの有効/無効化（無効化時は消灯ログも記録）
    case 'admin_set_enable':
        requireAdminRole();

        $id = (int)($input['id'] ?? 0);
        $target = (int)($input['target'] ?? 1);
        $enable = isset($input['enable']) ? (int)$input['enable'] : null;

        $allowedEnableColumns = [1 => 'enable1', 2 => 'enable2', 3 => 'enable3', 4 => 'enable4'];
        $allowedFlagColumns   = [1 => 'flag1',   2 => 'flag2',   3 => 'flag3',   4 => 'flag4'];

        if ($id <= 0 || !isset($allowedEnableColumns[$target]) || !in_array($enable, [0, 1], true)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'パラメータ(id, target, enable)が不正です']);
            exit;
        }

        $enableCol = $allowedEnableColumns[$target];
        $flagCol   = $allowedFlagColumns[$target];

        // 無効化された場合、フラグも強制的に消灯(0)にし、ログに記録する
        if ($enable === 0) {
            $stmt = $pdo->prepare("UPDATE users SET {$enableCol} = 0, {$flagCol} = 0 WHERE id = :id");
            $stmt->execute([':id' => $id]);

            $userStmt = $pdo->prepare("SELECT user_id FROM users WHERE id = :id");
            $userStmt->execute([':id' => $id]);
            $targetUser = $userStmt->fetch();
            if ($targetUser) {
                logStatusChange($pdo, $targetUser['user_id'], $target, 0, 'admin');
            }
        } else {
            $stmt = $pdo->prepare("UPDATE users SET {$enableCol} = :enable WHERE id = :id");
            $stmt->execute([':enable' => $enable, ':id' => $id]);
        }

        echo json_encode(['success' => true]);
        break;

    // 管理者用：個別のランタンの点灯/消灯制御
    case 'admin_set_flag':
        requireAdminRole();

        $id = (int)($input['id'] ?? 0);
        $target = (int)($input['target'] ?? 1);
        $flag = isset($input['flag']) ? (int)$input['flag'] : null;

        $allowedFlagColumns = [1 => 'flag1', 2 => 'flag2', 3 => 'flag3', 4 => 'flag4'];

        if ($id <= 0 || !isset($allowedFlagColumns[$target]) || !in_array($flag, [0, 1], true)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'パラメータ(id, target, flag)が不正です']);
            exit;
        }

        $userStmt = $pdo->prepare("SELECT user_id FROM users WHERE id = :id");
        $userStmt->execute([':id' => $id]);
        $targetUser = $userStmt->fetch();

        if ($targetUser) {
            $column = $allowedFlagColumns[$target];
            $stmt = $pdo->prepare("UPDATE users SET {$column} = :flag WHERE id = :id");
            $stmt->execute([':flag' => $flag, ':id' => $id]);

            // 変更ログを保存
            logStatusChange($pdo, $targetUser['user_id'], $target, $flag, 'admin');
        }

        echo json_encode(['success' => true]);
        break;

    // ==================================================
    // B. 一般ユーザー機能・認証・外部API操作
    // ==================================================
    
    // 一般ユーザー用：自身のランタンの点灯/消灯制御（画面操作用）
    case 'user_set_flag':
        if (empty($_SESSION['user_id'])) {
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => '未ログインです']);
            exit;
        }

        $target = (int)($input['target'] ?? 1);
        $flag = isset($input['flag']) ? (int)$input['flag'] : null;

        $allowedEnableColumns = [1 => 'enable1', 2 => 'enable2', 3 => 'enable3', 4 => 'enable4'];
        $allowedFlagColumns   = [1 => 'flag1',   2 => 'flag2',   3 => 'flag3',   4 => 'flag4'];

        if (!isset($allowedFlagColumns[$target]) || !in_array($flag, [0, 1], true)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'パラメータ(target, flag)が不正です']);
            exit;
        }

        // 無効化されているランタンの点灯要求をブロック
        $enableCol = $allowedEnableColumns[$target];
        $stmt = $pdo->prepare("SELECT {$enableCol} as is_enabled FROM users WHERE user_id = :user_id");
        $stmt->execute([':user_id' => $_SESSION['user_id']]);
        $userStatus = $stmt->fetch();

        if (!$userStatus || ((int)$userStatus['is_enabled'] === 0 && $flag === 1)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => "ランタン{$target}は現在無効化されているため点灯できません"]);
            exit;
        }

        $now = time();
        $column = $allowedFlagColumns[$target];
        $stmt = $pdo->prepare("UPDATE users SET {$column} = :flag, last_access = :now WHERE user_id = :user_id");
        $stmt->execute([':flag' => $flag, ':now' => $now, ':user_id' => $_SESSION['user_id']]);

        // 操作元を 'user'（一般ユーザー画面）としてログ保存
        logStatusChange($pdo, $_SESSION['user_id'], $target, $flag, 'user');

        echo json_encode(['success' => true]);
        break;

    // 一般ユーザー用：自身のランタン有効/無効化（無効化時は自動消灯＆ログ記録）
    case 'user_set_enable':
        if (empty($_SESSION['user_id'])) {
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => '未ログインです']);
            exit;
        }

        $target = (int)($input['target'] ?? 1);
        $enable = isset($input['enable']) ? (int)$input['enable'] : null;

        $allowedEnableColumns = [1 => 'enable1', 2 => 'enable2', 3 => 'enable3', 4 => 'enable4'];
        $allowedFlagColumns   = [1 => 'flag1',   2 => 'flag2',   3 => 'flag3',   4 => 'flag4'];

        if (!isset($allowedEnableColumns[$target]) || !in_array($enable, [0, 1], true)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'パラメータ(target, enable)が不正です']);
            exit;
        }

        $enableCol = $allowedEnableColumns[$target];
        $flagCol   = $allowedFlagColumns[$target];

        if ($enable === 0) {
            $stmt = $pdo->prepare("UPDATE users SET {$enableCol} = 0, {$flagCol} = 0 WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $_SESSION['user_id']]);

            logStatusChange($pdo, $_SESSION['user_id'], $target, 0, 'user');
        } else {
            $stmt = $pdo->prepare("UPDATE users SET {$enableCol} = :enable WHERE user_id = :user_id");
            $stmt->execute([':enable' => $enable, ':user_id' => $_SESSION['user_id']]);
        }

        echo json_encode(['success' => true]);
        break;

    // APIキー取得（IDとパスワードによる認証）
    case 'get_api_key':
        $userId   = trim($_REQUEST['user_id'] ?? ($input['user_id'] ?? ''));
        $password = $_REQUEST['password'] ?? ($input['password'] ?? '');

        if (empty($userId) || empty($password)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'ユーザーID/メールアドレスとパスワードを入力してください'
            ]);
            exit;
        }

        $stmt = $pdo->prepare("SELECT user_id, username, password_hash, api_key, status FROM users WHERE user_id = :user_id OR username = :username");
        $stmt->execute([':user_id' => $userId, ':username' => $userId]);
        $user = $stmt->fetch();

        if (!$user || $user['status'] !== 'active' || !password_verify($password, $user['password_hash'])) {
            http_response_code(401);
            echo json_encode([
                'success' => false,
                'message' => 'ユーザーIDまたはパスワードが正しくないか、本登録が完了していません'
            ]);
            exit;
        }

        echo json_encode([
            'success' => true,
            'user_id' => $user['user_id'],
            'username' => $user['username'],
            'api_key' => $user['api_key']
        ]);
        break;

    // 一般ユーザー仮登録（管理者IDの紐づけ対応）
    case 'register':
        $username = trim($input['username'] ?? '');
        $email = trim($input['email'] ?? '');
        $adminId = trim($input['admin_id'] ?? '');

        if (empty($username) || empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => '有効なユーザー名とメールアドレスを入力してください']);
            exit;
        }

        // 管理者IDが入力されている場合、実在する管理者アカウントか検証
        $parentAdminUserId = null;
        if (!empty($adminId)) {
            $adminCheck = $pdo->prepare("SELECT user_id FROM users WHERE (user_id = :admin_id OR api_key = :admin_id) AND is_admin = 1 AND status = 'active'");
            $adminCheck->execute([':admin_id' => $adminId]);
            $validAdmin = $adminCheck->fetch();
            if (!$validAdmin) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => '指定された管理者IDが存在しないか無効です']);
                exit;
            }
            $parentAdminUserId = $validAdmin['user_id'];
        }

        $stmt = $pdo->prepare("SELECT status FROM users WHERE user_id = :email");
        $stmt->execute([':email' => $email]);
        $existing = $stmt->fetch();

        if ($existing) {
            if ($existing['status'] === 'active') {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'このメールアドレスは既に登録されています']);
                exit;
            } else {
                // 仮登録のまま放置されている場合は一度削除して再発行を許可
                $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = :email AND status = 'pending'");
                $stmt->execute([':email' => $email]);
            }
        }

        $token = bin2hex(random_bytes(32));
        $apiKey = 'key_' . bin2hex(random_bytes(16));
        $expires = time() + (24 * 60 * 60);

        // 新規一般ユーザーも初期状態ですべて無効(enable=0)、消灯(flag=0)
        $stmt = $pdo->prepare("
            INSERT INTO users (user_id, username, api_key, verify_token, token_expires, status, parent_admin_id, flag1, flag2, flag3, flag4, enable1, enable2, enable3, enable4)
            VALUES (:email, :username, :api_key, :token, :expires, 'pending', :parent_admin_id, 0, 0, 0, 0, 0, 0, 0, 0)
        ");
        $stmt->execute([
            ':email' => $email,
            ':username' => $username,
            ':api_key' => $apiKey,
            ':token' => $token,
            ':expires' => $expires,
            ':parent_admin_id' => $parentAdminUserId
        ]);

        // メール本文の作成と送信（config.phpの設定値を反映）
        if (defined('BASE_URL')) {
            $verifyUrl = rtrim(BASE_URL, '/') . "/verify.php?token={$token}";
        } else {
            $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'];
            $path = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
            $verifyUrl = "{$scheme}://{$host}{$path}/verify.php?token={$token}";
        }

        $mailSubject = "【仮登録】本登録手続きのご案内";
        $mailBody = "{$username} 様\n\nご登録ありがとうございます。\n以下のリンクをクリックしてパスワードを設定し、本登録を完了してください。\n\n{$verifyUrl}\n\n※有効期限: 24時間";
        $mailHeaders = getMailHeaders();

        $mailSent = mb_send_mail($email, $mailSubject, $mailBody, $mailHeaders);
        if (!$mailSent) {
            error_log("【メール送信失敗】ユーザー仮登録メールの送信に失敗しました。 宛先: {$email}");
        }

        echo json_encode([
            'success' => true,
            'message' => '仮登録メールを送信しました。メール内のリンクから本登録を完了してください。',
            'dev_verify_url' => $verifyUrl,
            'mail_sent' => $mailSent
        ]);
        break;

    // パスワード再設定リクエスト
    case 'reset_password_request':
        $email = trim($input['email'] ?? '');

        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => '有効なメールアドレスを入力してください']);
            exit;
        }

        $stmt = $pdo->prepare("SELECT id, username FROM users WHERE user_id = :email AND status = 'active'");
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch();

        if (!$user) {
            // セキュリティのためメール未登録時も成功メッセージを返す
            echo json_encode([
                'success' => true,
                'message' => '入力されたメールアドレス宛に再設定手続きのご案内を送信しました。'
            ]);
            exit;
        }

        $token = bin2hex(random_bytes(32));
        $expires = time() + (24 * 60 * 60);

        $updateStmt = $pdo->prepare("
            UPDATE users 
            SET verify_token = :token, token_expires = :expires 
            WHERE id = :id
        ");
        $updateStmt->execute([
            ':token' => $token,
            ':expires' => $expires,
            ':id' => $user['id']
        ]);

        // メール本文の作成と送信（config.phpの設定値を反映）
        if (defined('BASE_URL')) {
            $resetUrl = rtrim(BASE_URL, '/') . "/verify.php?token={$token}";
        } else {
            $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'];
            $path = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
            $resetUrl = "{$scheme}://{$host}{$path}/verify.php?token={$token}";
        }

        $mailSubject = "【パスワード再設定】手続きのご案内";
        $mailBody = "{$user['username']} 様\n\nパスワードの再設定リクエストを受け付けました。\n以下のリンクをクリックして新しいパスワードを設定してください。\n\n{$resetUrl}\n\n※有効期限: 24時間";
        $mailHeaders = getMailHeaders();

        $mailSent = mb_send_mail($email, $mailSubject, $mailBody, $mailHeaders);
        if (!$mailSent) {
            error_log("【メール送信失敗】パスワード再設定メールの送信に失敗しました。 宛先: {$email}");
        }

        echo json_encode([
            'success' => true,
            'message' => '入力されたメールアドレス宛に再設定手続きのご案内を送信しました。',
            'dev_verify_url' => $resetUrl,
            'mail_sent' => $mailSent
        ]);
        break;

    // ログイン処理
    case 'login':
        $userId = trim($input['user_id'] ?? '');
        $password = trim($input['password'] ?? '');

        if (empty($userId) || empty($password)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'ユーザーID/メールアドレスとパスワードを入力してください']);
            exit;
        }

        $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = :user_id OR username = :username");
        $stmt->execute([':user_id' => $userId, ':username' => $userId]);
        $user = $stmt->fetch();

        if (!$user || $user['status'] !== 'active' || !password_verify($password, $user['password_hash'])) {
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => 'ユーザーIDまたはパスワードが正しくないか、本登録が完了していません']);
            exit;
        }

        session_regenerate_id(true);
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // ログイン成功時にトークン再生成
        $_SESSION['user_id'] = $user['user_id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['is_admin'] = (int)($user['is_admin'] ?? 0);

        $stmt = $pdo->prepare("UPDATE users SET last_access = :now WHERE id = :id");
        $stmt->execute([':now' => time(), ':id' => $user['id']]);

        // クライアントごとのアクティブセッション（死活監視）を更新
        $clientId = $input['client_id'] ?? ($_GET['client_id'] ?? ($_SERVER['HTTP_X_CLIENT_ID'] ?? ''));
        if (!empty($clientId)) {
            updateClientHeartbeat($pdo, $user['user_id'], $clientId);
        }

        echo json_encode([
            'success' => true,
            'user_id' => $user['user_id'],
            'username' => $user['username'],
            'is_admin' => $_SESSION['is_admin'],
            'api_key' => $user['api_key'],
            'csrf_token' => $_SESSION['csrf_token']
        ]);
        break;

    // 一般画面用：自身のステータス取得＆ポーリング時のセッション死活チェック
    case 'get_status':
        if (empty($_SESSION['user_id'])) {
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => '未ログイン状態です']);
            exit;
        }

        $clientId = $_GET['client_id'] ?? ($_SERVER['HTTP_X_CLIENT_ID'] ?? '');

        // 管理者によって active_sessions から切断（削除）されていないか検証
        if (!empty($clientId) && strpos($clientId, 'session_') !== 0) {
            $checkSessionStmt = $pdo->prepare("SELECT COUNT(*) as count FROM active_sessions WHERE user_id = :user_id AND client_id = :client_id");
            $checkSessionStmt->execute([
                ':user_id' => $_SESSION['user_id'],
                ':client_id' => $clientId
            ]);
            
            // active_sessions から消えている場合は強制ログアウト（401）を返す
            if ((int)$checkSessionStmt->fetch()['count'] === 0) {
                $_SESSION = [];
                session_destroy();
                http_response_code(401);
                echo json_encode(['success' => false, 'message' => '管理者によってセッションが切断されました']);
                exit;
            }
        }

        $stmt = $pdo->prepare("SELECT user_id, username, flag1, flag2, flag3, flag4, enable1, enable2, enable3, enable4, api_key FROM users WHERE user_id = :user_id");
        $stmt->execute([':user_id' => $_SESSION['user_id']]);
        $user = $stmt->fetch();

        if (!$user) {
            session_destroy();
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => 'ユーザーが存在しません']);
            exit;
        }

        // クライアントごとのハートビート更新
        if (!empty($clientId)) {
            updateClientHeartbeat($pdo, $user['user_id'], $clientId);
        }

        $now = time();
        $stmt = $pdo->prepare("UPDATE users SET last_access = :now WHERE user_id = :user_id");
        $stmt->execute([':now' => $now, ':user_id' => $_SESSION['user_id']]);

        echo json_encode([
            'success' => true,
            'user_id' => $user['user_id'],
            'username' => $user['username'],
            'flags' => [
                (int)($user['flag1'] ?? 0),
                (int)($user['flag2'] ?? 0),
                (int)($user['flag3'] ?? 0),
                (int)($user['flag4'] ?? 0)
            ],
            'enabled_flags' => [
                (int)($user['enable1'] ?? 0),
                (int)($user['enable2'] ?? 0),
                (int)($user['enable3'] ?? 0),
                (int)($user['enable4'] ?? 0)
            ],
            'api_key' => $user['api_key'] ?? '',
            'client_id' => $clientId,
            'csrf_token' => $_SESSION['csrf_token'] ?? ''
        ]);
        break;

    // 外部デバイス用：APIキーを指定してステータス（点灯/消灯）を切り替え（POST専用・ヘッダー認証対応）
    case 'set_status_cmd':
        // 1. HTTPメソッドの検証 (POSTのみ許可)
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['success' => false, 'message' => 'POSTリクエストのみ許可されています']);
            exit;
        }

        // 2. APIキーの取得（Authorization ヘッダー > X-API-Key > JSON Body > POST Form）
        $apiKey = '';
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        
        if (preg_match('/Bearer\s+(\S+)/i', $authHeader, $matches)) {
            $apiKey = $matches[1];
        } elseif (!empty($_SERVER['HTTP_X_API_KEY'])) {
            $apiKey = $_SERVER['HTTP_X_API_KEY'];
        }

        if (empty($apiKey)) {
            $apiKey = $input['api_key'] ?? ($_POST['api_key'] ?? '');
        }

        // 3. その他のパラメータ取得
        $target = (int)($input['target'] ?? ($_POST['target'] ?? 1));
        $flag = isset($input['flag']) ? (int)$input['flag'] : (isset($_POST['flag']) ? (int)$_POST['flag'] : null);
        $clientId = $_SERVER['HTTP_X_CLIENT_ID'] ?? ($input['client_id'] ?? ($_POST['client_id'] ?? 'api_' . substr(md5($apiKey), 0, 8)));

        $allowedEnableColumns = [1 => 'enable1', 2 => 'enable2', 3 => 'enable3', 4 => 'enable4'];
        $allowedFlagColumns   = [1 => 'flag1',   2 => 'flag2',   3 => 'flag3',   4 => 'flag4'];

        if (empty($apiKey) || !isset($allowedFlagColumns[$target]) || $flag === null || !in_array($flag, [0, 1], true)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'パラメータまたはAPIキーが不正です']);
            exit;
        }

        // 無効化されているランタンの点灯要求をブロック
        $enableCol = $allowedEnableColumns[$target];
        $stmt = $pdo->prepare("SELECT id, user_id, {$enableCol} as is_enabled FROM users WHERE api_key = :api_key AND status = 'active'");
        $stmt->execute([':api_key' => $apiKey]);
        $user = $stmt->fetch();

        if (!$user) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => '無効なAPIキーです']);
            exit;
        }

        if ((int)$user['is_enabled'] === 0 && $flag === 1) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => "ランタン{$target}は現在無効化されているため点灯できません"]);
            exit;
        }

        $now = time();
        $column = $allowedFlagColumns[$target];
        $stmt = $pdo->prepare("UPDATE users SET {$column} = :flag, last_access = :now WHERE id = :id");
        $stmt->execute([':flag' => $flag, ':now' => $now, ':id' => $user['id']]);

        // ハートビートおよび変更ログの記録
        // cURL操作（外部API操作）時はアクティブ端末テーブルへの追加を行わないため無効化
        // updateClientHeartbeat($pdo, $user['user_id'], $clientId);
        logStatusChange($pdo, $user['user_id'], $target, $flag, 'api');

        echo json_encode([
            'success' => true,
            'message' => "ランタン{$target}のステータスを更新しました",
            'target' => $target,
            'flag' => $flag
        ]);
        break;

    // ==================================================
    // C. ログダウンロード機能
    // ==================================================
    
    // 全体ログのダウンロード（管理者用）
    case 'download_logs':
        requireAdminRole();

        // 過去のログを取得（最新500件）
        $stmt = $pdo->prepare("
            SELECT 
                l.created_at,
                u.username,
                u.user_id,
                l.target,
                l.flag,
                l.source
            FROM status_logs l
            LEFT JOIN users u ON l.user_id = u.user_id
            ORDER BY l.id DESC
            LIMIT 500
        ");
        $stmt->execute();
        $logs = $stmt->fetchAll();

        // CSVヘッダー設定
        $filename = 'lantern_status_logs_' . date('Ymd_His') . '.csv';
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');

        // BOMの出力（Excelでの文字化け防止）
        $output = fopen('php://output', 'w');
        fwrite($output, "\xEF\xBB\xBF");

        // ヘッダー行
        fputcsv($output, ['日時', '氏名', 'メールアドレス (ユーザーID)', 'ランタン番号', 'ステータス', '操作元']);

        // データ行
        foreach ($logs as $log) {
            $statusText = ((int)$log['flag'] === 1) ? '点灯 (1)' : '消灯 (0)';
            $sourceLabel = match($log['source'] ?? 'unknown') {
                'admin' => '管理者画面',
                'user'  => '一般ユーザー画面',
                'api'   => '外部API (cURL/デバイス)',
                default => '不明'
            };

            fputcsv($output, [
                $log['created_at'],
                $log['username'] ?? '未登録/削除済み',
                $log['user_id'],
                '#' . $log['target'],
                $statusText,
                $sourceLabel
            ]);
        }

        fclose($output);
        exit;

    // 特定ユーザーに絞り込んだログのダウンロード（管理者用）
    case 'admin_download_user_logs':
        requireAdminRole();

        $targetUserId = trim($_GET['user_id'] ?? '');

        if (empty($targetUserId)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'ユーザーIDを指定してください']);
            exit;
        }

        // 指定されたユーザーのログのみを取得（最新500件）
        $stmt = $pdo->prepare("
            SELECT 
                l.created_at,
                u.username,
                l.user_id,
                l.target,
                l.flag,
                l.source
            FROM status_logs l
            LEFT JOIN users u ON l.user_id = u.user_id
            WHERE l.user_id = :user_id
            ORDER BY l.id DESC
            LIMIT 500
        ");
        $stmt->execute([':user_id' => $targetUserId]);
        $logs = $stmt->fetchAll();

        $safeUserId = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $targetUserId);
        $filename = 'lantern_logs_' . $safeUserId . '_' . date('Ymd_His') . '.csv';

        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');

        $output = fopen('php://output', 'w');
        fwrite($output, "\xEF\xBB\xBF");

        fputcsv($output, ['日時', '氏名', 'メールアドレス (ユーザーID)', 'ランタン番号', 'ステータス', '操作元']);

        foreach ($logs as $log) {
            $statusText = ((int)$log['flag'] === 1) ? '点灯 (1)' : '消灯 (0)';
            $sourceLabel = match($log['source'] ?? 'unknown') {
                'admin' => '管理者画面',
                'user'  => '一般ユーザー画面',
                'api'   => '外部API (cURL/デバイス)',
                default => '不明'
            };

            fputcsv($output, [
                $log['created_at'],
                $log['username'] ?? '未登録/削除済み',
                $log['user_id'],
                '#' . $log['target'],
                $statusText,
                $sourceLabel
            ]);
        }

        fclose($output);
        exit;

    // ログアウト処理（アクティブセッションからも削除）
    case 'logout':
        $userId = $_SESSION['user_id'] ?? '';
        $clientId = $_GET['client_id'] ?? ($_SERVER['HTTP_X_CLIENT_ID'] ?? $input['client_id'] ?? '');

        if (!empty($userId) && !empty($clientId)) {
            $stmt = $pdo->prepare("DELETE FROM active_sessions WHERE user_id = :user_id AND client_id = :client_id");
            $stmt->execute([
                ':user_id' => $userId,
                ':client_id' => $clientId
            ]);
        }

        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();
        echo json_encode(['success' => true, 'message' => 'ログアウトしました']);
        break;

    default:
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => '不正なアクションです']);
        break;
}