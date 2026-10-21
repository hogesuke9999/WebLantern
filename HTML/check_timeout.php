<?php
/**
 * CRON/監視スクリプト - check_disconnect.php
 * アクティブセッション（各接続クライアント）ごとの死活監視を行います。
 */

mb_language("Japanese");
mb_internal_encoding("UTF-8");

$baseDir = dirname(__DIR__);
$configPath = $baseDir . '/CNF/config.php';

if (file_exists($configPath)) {
    require_once $configPath;
}

if (!defined('BASE_DIR')) {
    define('BASE_DIR', $baseDir);
}
if (!defined('DB_PATH')) {
    define('DB_PATH', BASE_DIR . '/DB/WEBLAMP.db');
}

if (!file_exists(DB_PATH)) {
    exit("Database file not found.\n");
}

try {
    $pdo = new PDO('sqlite:' . DB_PATH);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    exit("DB connection failed: " . $e->getMessage() . "\n");
}

// タイムアウト閾値（60秒間アクセスがないセッションを断絶と判定）
$timeoutSeconds = 60;
$now = time();

// 各クライアントの最新ハートビートを検証
$stmt = $pdo->prepare("
    SELECT s.user_id, s.client_id, s.ip_address, s.last_heartbeat, u.username 
    FROM active_sessions s
    LEFT JOIN users u ON s.user_id = u.user_id
    WHERE (:now - s.last_heartbeat) > :timeout
");
$stmt->execute([
    ':now' => $now,
    ':timeout' => $timeoutSeconds
]);
$disconnectedSessions = $stmt->fetchAll(PDO::FETCH_ASSOC);

if (!empty($disconnectedSessions)) {
    $to = 'admin@example.com'; // 管理者の宛先メールアドレス
    $subject = '【警告】クライアント個別の通信断絶通知';

    $message = "以下のクライアント/セッションからの接続が {$timeoutSeconds} 秒以上確認できません。\n\n";
    foreach ($disconnectedSessions as $s) {
        $lastAccessTime = date('Y-m-d H:i:s', $s['last_heartbeat']);
        $userName = $s['username'] ?? '不明';
        $message .= "・ユーザー: {$userName} ({$s['user_id']})\n";
        $message .= "  クライアントID: {$s['client_id']}\n";
        $message .= "  IPアドレス: {$s['ip_address']}\n";
        $message .= "  最終通信: {$lastAccessTime}\n\n";
    }

    $headers = "From: system@example.com\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

    if (mb_send_mail($to, $subject, $message, $headers)) {
        echo date('Y-m-d H:i:s') . " - Alert mail sent for disconnected sessions.\n";
    } else {
        echo date('Y-m-d H:i:s') . " - Failed to send alert mail.\n";
    }
} else {
    echo date('Y-m-d H:i:s') . " - All connected clients are alive.\n";
}