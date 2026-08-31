#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

require_once('config.inc');

use Volgodon\ClientControl\ClientControl;
use Volgodon\ClientControl\Compiler;

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
    echo json_encode(['status' => 'ok', 'objects' => $counts], JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR, $error->getMessage() . PHP_EOL);
    exit(1);
}
