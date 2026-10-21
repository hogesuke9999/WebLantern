<?php
/**
 * HTML/verify.php - パスワード設定・再設定処理
 * トークンの検証、パスワードの設定、APIキーの再発行を行います。
 */

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

function getDBConnection() {
    $dbPath = DB_PATH;
    $dbDir = dirname($dbPath);

    try {
        if (!file_exists($dbDir)) {
            @mkdir($dbDir, 0777, true);
        }

        $pdo = new PDO('sqlite:' . $dbPath);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        return $pdo;
    } catch (PDOException $e) {
        die("データベース接続エラーが発生しました");
    }
}

$pdo = getDBConnection();

$token = trim($_GET['token'] ?? '');
$errorMsg = '';
$successMsg = '';
$isValidToken = false;
$user = null;

if (!empty($token)) {
    $stmt = $pdo->prepare("
        SELECT * FROM users 
        WHERE verify_token = :token
    ");
    $stmt->execute([':token' => $token]);
    $user = $stmt->fetch();

    if ($user && isset($user['token_expires']) && (int)$user['token_expires'] > time()) {
        $isValidToken = true;
    } else {
        $errorMsg = '無効または有効期限切れのURLです。<br>再度手続きを行ってください。';
    }
} else {
    $errorMsg = '不正なアクセスです。トークンが指定されていません。';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $isValidToken) {
    $password = $_POST['password'] ?? '';
    $passwordConfirm = $_POST['password_confirm'] ?? '';

    if (mb_strlen($password) < 8) {
        $errorMsg = 'パスワードは8文字以上で入力してください。';
    } elseif ($password !== $passwordConfirm) {
        $errorMsg = 'パスワードが一致しません。';
    } else {
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        $prefix = ($user['user_id'] === 'admin') ? 'admin_key_' : 'key_';
        $newApiKey = $prefix . bin2hex(random_bytes(16));

        $updateStmt = $pdo->prepare("
            UPDATE users 
            SET password_hash = :hash, 
                api_key = :api_key,
                status = 'active', 
                verify_token = NULL, 
                token_expires = NULL 
            WHERE id = :id
        ");
        
        $updateStmt->execute([
            ':hash' => $passwordHash,
            ':api_key' => $newApiKey,
            ':id' => $user['id']
        ]);

        $successMsg = 'パスワードの設定とAPIキーの更新が完了しました！ログイン画面よりログインしてください。';
        $isValidToken = false;
    }
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>パスワード設定・再設定</title>
    <link rel="stylesheet" href="css/verify.css">
</head>
<body>

<div class="card">
    <h2>パスワード設定</h2>

    <?php if (!empty($errorMsg)): ?>
        <div class="msg-error"><?= $errorMsg ?></div>
    <?php endif; ?>

    <?php if (!empty($successMsg)): ?>
        <div class="msg-success"><?= htmlspecialchars($successMsg) ?></div>
        <a href="index.html" class="btn-link">ログイン画面へ行く</a>
    <?php endif; ?>

    <?php if ($isValidToken): ?>
        <form method="POST" action="verify.php?token=<?= htmlspecialchars($token) ?>">
            <div class="form-group">
                <label for="password">新しいパスワード（8文字以上）</label>
                <input type="password" id="password" name="password" required minlength="8">
            </div>
            <div class="form-group">
                <label for="password_confirm">新しいパスワード（確認用）</label>
                <input type="password" id="password_confirm" name="password_confirm" required minlength="8">
            </div>
            <button type="submit">パスワードを登録する</button>
        </form>
    <?php elseif (empty($successMsg)): ?>
        <a href="index.html" class="btn-link">ログイン画面に戻る</a>
    <?php endif; ?>
</div>

</body>
</html>