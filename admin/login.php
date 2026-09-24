<?php
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../config/database.php';

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

$pageTitle = '后台登录 - 社区便民留言板';
$cssPath = '../assets/css/style.css';
$jsPath = '../assets/js/main.js';

// 已登录且会话仍有效则跳转；否则清除失效身份并显示登录页。
if (!empty($_SESSION['admin_id'])) {
    try {
        $currentAdmin = getAuthenticatedAdmin(getDB());
    } catch (Throwable $e) {
        $currentAdmin = null;
    }

    if ($currentAdmin) {
        header('Location: index.php');
        exit;
    }
    clearAdminIdentity();
}

$error = '';
$notice = '';
if (isset($_GET['logged_out'])) {
    $notice = '您已安全退出登录';
} elseif (isset($_GET['expired'])) {
    $notice = '登录状态已失效，请重新登录';
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_once __DIR__ . '/../config/database.php';
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($username) || empty($password)) {
        $error = '请输入用户名和密码';
    } else {
        $db = getDB();
        $stmt = $db->prepare("SELECT * FROM admins WHERE username = ?");
        $stmt->execute([$username]);
        $admin = $stmt->fetch();

        if ($admin && password_verify($password, $admin['password'])) {
            ensureAdminSessionSchema($db);

            // 登录成功后更换会话ID，并把该账号的有效登录绑定到新会话。
            session_regenerate_id(true);
            $sessionHash = hash('sha256', session_id());
            $stmt = $db->prepare("
                INSERT INTO active_admin_logins (admin_id, session_id, login_at)
                VALUES (?, ?, NOW())
                ON DUPLICATE KEY UPDATE
                    admin_id = VALUES(admin_id),
                    session_id = VALUES(session_id),
                    login_at = NOW(),
                    updated_at = NOW()
            ");
            $stmt->execute([$admin['id'], $sessionHash]);

            $_SESSION['admin_id'] = (int) $admin['id'];
            $_SESSION['admin_name'] = $admin['username'];
            header('Location: index.php');
            exit;
        } else {
            $error = '用户名或密码错误';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $pageTitle ?></title>
    <link rel="stylesheet" href="<?= $cssPath ?>">
</head>
<body class="login-body">
<div class="login-card">
    <h2>🔐 后台管理登录</h2>
    <p class="login-subtitle">社区便民留言板管理系统</p>
    <?php if ($error): ?>
    <div class="alert alert-error"><?= cleanInput($error) ?></div>
    <?php endif; ?>
    <?php if ($notice): ?>
    <div class="alert alert-success"><?= cleanInput($notice) ?></div>
    <?php endif; ?>
    <form method="POST" class="login-form" autocomplete="off">
        <div class="form-group">
            <label for="username">用户名</label>
            <input type="text" id="username" name="username" placeholder="请输入管理员账号" required autofocus>
        </div>
        <div class="form-group">
            <label for="password">密码</label>
            <input type="password" id="password" name="password" placeholder="请输入密码" required>
        </div>
        <button type="submit" class="btn btn-primary btn-lg btn-block">登 录</button>
    </form>
    <div class="login-footer">
        <a href="../index.php">← 返回首页</a>
    </div>
</div>
<script>
(function() {
    try {
        localStorage.removeItem('community-board.admin-session');
    } catch (e) {}
})();
</script>
</body>
</html>
