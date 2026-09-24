-- 管理员会话凭证迁移脚本
-- 执行此 SQL 为 admins 表添加 session_token 字段
-- 用于服务端校验登录状态：退出登录或在其他设备登录后，旧会话立即失效

USE `community_board`;

ALTER TABLE `admins`
    ADD COLUMN `session_token` VARCHAR(64) DEFAULT NULL COMMENT '当前登录会话凭证' AFTER `password`;

-- 执行完成后，可以通过以下命令验证：
-- DESCRIBE admins;
