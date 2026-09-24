<?php
require_once __DIR__ . '/../includes/functions.php';

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

requireAdmin();

$adminIdentityJson = json_encode([
    'id' => (int) $_SESSION['admin_id'],
    'name' => $_SESSION['admin_name'],
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $pageTitle ?? '后台管理' ?></title>
    <link rel="stylesheet" href="<?= $cssPath ?? '../assets/css/style.css' ?>">
</head>
<body class="admin-body">
<script>
window.ADMIN_AUTH_IDENTITY = <?= $adminIdentityJson ?>;
</script>
<script src="../assets/js/admin-auth.js"></script>
