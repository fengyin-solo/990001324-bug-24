<?php
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../config/database.php';

// 清除服务端会话凭证，使该账号在所有设备/标签页的会话同时失效
if (!empty($_SESSION['admin_id'])) {
    $db = getDB();
    ensureAdminSessionColumn($db);
    $db->prepare("UPDATE admins SET session_token = NULL WHERE id = ?")->execute([$_SESSION['admin_id']]);
}

// 清空会话数据并删除会话 Cookie
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
}
session_destroy();

sendNoCacheHeaders();
header('Location: login.php');
exit;
