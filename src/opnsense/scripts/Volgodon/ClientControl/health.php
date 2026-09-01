#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

require_once('config.inc');

use Volgodon\ClientControl\AuditLog;
use Volgodon\ClientControl\ClientControl;
use Volgodon\ClientControl\Compiler;

function clientControlAccountUid($name)
{
    if (function_exists('posix_getpwnam')) {
        $account = posix_getpwnam($name);
        return $account === false ? null : (int)$account['uid'];
    }
    foreach (@file('/etc/passwd', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $fields = explode(':', $line);
        if (count($fields) > 2 && hash_equals($name, $fields[0]) && ctype_digit($fields[2])) {
            return (int)$fields[2];
        }
    }
    return null;
}

function assertAuditLogPermissions()
{
    $serviceUid = clientControlAccountUid('wwwonly');
    if ($serviceUid === null) {
        $serviceUid = clientControlAccountUid('www');
    }
    if ($serviceUid === null) {
        throw new RuntimeException('Unable to resolve the Client Control audit service account.');
    }
    $paths = [AuditLog::PATH];
    foreach (glob(AuditLog::PATH . '.*') ?: [] as $path) {
        if (preg_match('/\.[0-9]+$/D', $path) === 1 && is_file($path)) {
            $paths[] = $path;
        }
    }
    foreach ($paths as $path) {
        $stat = @stat($path);
        if (is_link($path) || $stat === false ||
            (int)$stat['uid'] !== $serviceUid || ((int)$stat['mode'] & 0777) !== 0640) {
            throw new RuntimeException('The Client Control audit log ownership or permissions are invalid.');
        }
    }
}

try {
    $model = new ClientControl();
    $messages = $model->performValidation();
    if (count($messages) > 0) {
        foreach ($messages as $message) {
            fwrite(STDERR, sprintf("%s: %s\n", $message->getField(), $message->getMessage()));
        }
        exit(1);
    }
    $desired = (new Compiler())->compile($model);
    $counts = [];
    foreach (['categories', 'aliases', 'filter_rules', 'pipes', 'queues', 'shaper_rules'] as $kind) {
        $counts[$kind] = count($desired[$kind] ?? []);
    }
    $auditLog = ['status' => 'ok', 'message' => ''];
    try {
        (new AuditLog())->probe();
        assertAuditLogPermissions();
    } catch (Throwable $error) {
        $auditLog = ['status' => 'degraded', 'message' => $error->getMessage()];
    }
    $status = $auditLog['status'] === 'ok' ? 'ok' : 'degraded';
    echo json_encode([
        'status' => $status,
        'objects' => $counts,
        'audit_log' => $auditLog,
    ], JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit($status === 'ok' ? 0 : 1);
} catch (Throwable $error) {
    fwrite(STDERR, $error->getMessage() . PHP_EOL);
    exit(1);
}
