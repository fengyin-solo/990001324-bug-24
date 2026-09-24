<?php
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../config/database.php';

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (!empty($_SESSION['admin_id'])) {
    $adminId = $_SESSION['admin_id'];
    $sessionHash = hash('sha256', session_id());

    try {
        $db = getDB();
        ensureAdminSessionSchema($db);
        $stmt = $db->prepare("DELETE FROM active_admin_logins WHERE admin_id = ? AND session_id = ?");
        $stmt->execute([$adminId, $sessionHash]);
    } catch (Throwable $e) {
        // 即使清理登录记录表失败，也必须继续销毁当前会话。
    }
}

$_SESSION = [];

if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}

session_destroy();
header('Location: login.php?logged_out=1');
exit;
