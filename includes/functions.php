<?php
function startAppSession() {
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') == 443)
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

startAppSession();

/**
 * 确保管理员单点登录记录表存在
 */
function ensureAdminSessionSchema(PDO $db = null) {
    static $checked = false;
    if ($checked) {
        return;
    }

    if ($db === null) {
        require_once __DIR__ . '/../config/database.php';
        $db = getDB();
    }

    $db->exec("CREATE TABLE IF NOT EXISTS `active_admin_logins` (
        `admin_id` INT UNSIGNED NOT NULL PRIMARY KEY,
        `session_id` VARCHAR(128) NOT NULL,
        `login_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY `uk_session_id` (`session_id`),
        CONSTRAINT `fk_active_admin` FOREIGN KEY (`admin_id`)
            REFERENCES `admins` (`id`) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='管理员当前有效登录'");

    $checked = true;
}

/**
 * 清除当前请求中的管理员登录状态
 */
function clearAdminIdentity() {
    unset($_SESSION['admin_id'], $_SESSION['admin_name']);
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
}

/**
 * 返回JSON响应
 */
function jsonResponse($code, $msg, $data = null) {
    header('Content-Type: application/json; charset=utf-8');
    $res = ['code' => $code, 'msg' => $msg];
    if ($data !== null) $res['data'] = $data;
    echo json_encode($res, JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * 获取留言类型文字
 */
function getTypeLabel($type) {
    $map = ['help' => '居民求助', 'suggest' => '意见建议', 'lost' => '失物招领'];
    return $map[$type] ?? '其他';
}

/**
 * 获取类型图标
 */
function getTypeIcon($type) {
    $map = ['help' => '🆘', 'suggest' => '💡', 'lost' => '🔍'];
    return $map[$type] ?? '📌';
}

/**
 * 获取状态文字
 */
function getStatusLabel($status) {
    $map = [0 => '待审核', 1 => '已通过', 2 => '已拒绝'];
    return $map[$status] ?? '未知';
}

/**
 * 获取状态样式类
 */
function getStatusClass($status) {
    $map = [0 => 'pending', 1 => 'approved', 2 => 'rejected'];
    return $map[$status] ?? '';
}

/**
 * 时间格式化
 */
function timeAgo($datetime) {
    $now = new DateTime();
    $ago = new DateTime($datetime);
    $diff = $now->diff($ago);

    if ($diff->y > 0) return $diff->y . '年前';
    if ($diff->m > 0) return $diff->m . '个月前';
    if ($diff->d > 0) return $diff->d . '天前';
    if ($diff->h > 0) return $diff->h . '小时前';
    if ($diff->i > 0) return $diff->i . '分钟前';
    return '刚刚';
}

/**
 * 检查管理员登录
 */
function requireAdmin() {
    if (empty($_SESSION['admin_id'])) {
        unauthorized();
    }

    require_once __DIR__ . '/../config/database.php';
    $db = getDB();
    $admin = getAuthenticatedAdmin($db);

    if (!$admin) {
        clearAdminIdentity();
        unauthorized();
    }

    // 每次受保护请求都以数据库中的当前账号为准，避免会话里残留旧名称。
    $_SESSION['admin_id'] = (int) $admin['id'];
    $_SESSION['admin_name'] = $admin['username'];
}

/**
 * 获取当前会话对应的有效管理员
 */
function getAuthenticatedAdmin(PDO $db) {
    if (empty($_SESSION['admin_id'])) {
        return null;
    }

    ensureAdminSessionSchema($db);

    $sessionHash = hash('sha256', session_id());
    $stmt = $db->prepare("
        SELECT a.id, a.username
        FROM active_admin_logins l
        INNER JOIN admins a ON a.id = l.admin_id
        WHERE l.admin_id = ? AND l.session_id = ?
    ");
    $stmt->execute([$_SESSION['admin_id'], $sessionHash]);
    return $stmt->fetch() ?: null;
}

/**
 * 未登录或登录已失效时的统一响应
 */
function unauthorized() {
    http_response_code(401);
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    $requestUri = $_SERVER['REQUEST_URI'] ?? '';
    $httpAccept = $_SERVER['HTTP_ACCEPT'] ?? '';
    $isApi = (
        strpos($requestUri, '/admin/api.php') !== false
        || strcasecmp($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '', 'XMLHttpRequest') === 0
        || strpos($httpAccept, 'application/json') !== false
    );

    if ($isApi) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'code' => 401,
            'msg' => '登录状态已失效，请重新登录',
            'data' => ['redirect' => 'login.php?expired=1'],
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    header('Location: login.php?expired=1');
    exit;
}

/**
 * 过滤输入
 */
function cleanInput($str) {
    return htmlspecialchars(trim($str), ENT_QUOTES, 'UTF-8');
}

/**
 * 获取访客唯一标识
 * 基于session和cookie实现匿名用户标识
 */
function getVisitorId() {
    if (empty($_SESSION['visitor_id'])) {
        if (!empty($_COOKIE['visitor_id'])) {
            $_SESSION['visitor_id'] = $_COOKIE['visitor_id'];
        } else {
            $visitorId = md5(uniqid('visitor_', true) . $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
            $_SESSION['visitor_id'] = $visitorId;
            setcookie('visitor_id', $visitorId, time() + 86400 * 365, '/');
        }
    }
    return $_SESSION['visitor_id'];
}

/**
 * 检查留言是否已收藏
 */
function isFavorited($messageId) {
    $visitorId = getVisitorId();
    $db = getDB();
    $stmt = $db->prepare("SELECT id FROM favorites WHERE visitor_id = ? AND message_id = ?");
    $stmt->execute([$visitorId, $messageId]);
    return $stmt->fetch() !== false;
}

/**
 * 获取当前访客收藏的所有留言ID
 */
function getFavoritedMessageIds() {
    $visitorId = getVisitorId();
    $db = getDB();
    $stmt = $db->prepare("SELECT message_id FROM favorites WHERE visitor_id = ?");
    $stmt->execute([$visitorId]);
    return array_column($stmt->fetchAll(), 'message_id');
}

/**
 * 切换收藏状态
 * 返回: ['favorited' => bool, 'action' => 'add'|'remove']
 */
function toggleFavorite($messageId) {
    $visitorId = getVisitorId();
    $db = getDB();

    $db->beginTransaction();
    try {
        $stmt = $db->prepare("SELECT id FROM favorites WHERE visitor_id = ? AND message_id = ? FOR UPDATE");
        $stmt->execute([$visitorId, $messageId]);
        $exists = $stmt->fetch();

        if ($exists) {
            $db->prepare("DELETE FROM favorites WHERE visitor_id = ? AND message_id = ?")
                ->execute([$visitorId, $messageId]);
            $result = ['favorited' => false, 'action' => 'remove'];
        } else {
            $db->prepare("INSERT INTO favorites (visitor_id, message_id) VALUES (?, ?)")
                ->execute([$visitorId, $messageId]);
            $result = ['favorited' => true, 'action' => 'add'];
        }

        $db->commit();
        return $result;
    } catch (Exception $e) {
        $db->rollBack();
        throw $e;
    }
}

/**
 * 获取举报类型文字
 */
function getReportTypeLabel($type) {
    $map = [
        'spam' => '垃圾信息',
        'abuse' => '辱骂攻击',
        'illegal' => '违法违规',
        'porn' => '色情低俗',
        'other' => '其他'
    ];
    return $map[$type] ?? '未知';
}

/**
 * 获取举报状态文字
 */
function getReportStatusLabel($status) {
    $map = [
        0 => '待处理',
        1 => '已处理-已删除',
        2 => '已处理-已忽略',
        3 => '已驳回'
    ];
    return $map[$status] ?? '未知';
}

/**
 * 获取举报状态样式类
 */
function getReportStatusClass($status) {
    $map = [
        0 => 'pending',
        1 => 'resolved-deleted',
        2 => 'resolved-ignored',
        3 => 'rejected'
    ];
    return $map[$status] ?? '';
}

/**
 * 检查当前访客是否已举报过某条留言
 */
function hasReported($messageId) {
    $visitorId = getVisitorId();
    $db = getDB();
    $stmt = $db->prepare("SELECT id FROM reports WHERE visitor_id = ? AND message_id = ?");
    $stmt->execute([$visitorId, $messageId]);
    return $stmt->fetch() !== false;
}

/**
 * 提交举报
 */
function submitReport($messageId, $reportType, $description = '') {
    $visitorId = getVisitorId();
    $db = getDB();

    $validTypes = ['spam', 'abuse', 'illegal', 'porn', 'other'];
    if (!in_array($reportType, $validTypes)) {
        throw new Exception('无效的举报类型');
    }

    $stmt = $db->prepare("SELECT id FROM messages WHERE id = ? AND status = 1");
    $stmt->execute([$messageId]);
    if (!$stmt->fetch()) {
        throw new Exception('留言不存在或未通过审核');
    }

    if (hasReported($messageId)) {
        throw new Exception('您已经举报过这条留言了');
    }

    $stmt = $db->prepare("INSERT INTO reports (message_id, visitor_id, report_type, description) VALUES (?, ?, ?, ?)");
    $stmt->execute([$messageId, $visitorId, $reportType, $description]);

    return $db->lastInsertId();
}

/**
 * 获取待处理举报数量
 */
function getPendingReportCount() {
    $db = getDB();
    return $db->query("SELECT COUNT(*) FROM reports WHERE status = 0")->fetchColumn();
}
