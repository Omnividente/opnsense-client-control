#!/usr/local/bin/php
<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

require_once('config.inc');

use OPNsense\Core\Config;
use Volgodon\ClientControl\Canonical;
use Volgodon\ClientControl\ClientControl;
use Volgodon\ClientControl\RuntimeSchedule;

try {
    $runtime = new RuntimeSchedule();
    $previous = $runtime->load();
    $current = $runtime->current(new ClientControl());
    if (Canonical::encode($previous) === Canonical::encode($current)) {
        if (!file_exists(RuntimeSchedule::STATE_FILE)) {
            $runtime->save($current);
        }
        echo json_encode(['status' => 'ok', 'changed' => false], JSON_UNESCAPED_SLASHES) . PHP_EOL;
        exit(0);
    }

    $reloadStatus = mwexecf('/usr/local/etc/rc.filter_configure %s', ['skip_alias']);
    if ($reloadStatus !== 0) {
        throw new RuntimeException('Scheduled Client Control firewall reload failed.');
    }

    $killed = [];
    $config = Config::getInstance()->object();
    if (!isset($config->system->schedule_states)) {
        foreach ($runtime->labelsToKill($previous, $current) as $label) {
            if (mwexecf('/sbin/pfctl -k label -k %s', [$label]) !== 0) {
                throw new RuntimeException('Unable to clear states for an expired Client Control schedule.');
            }
            $killed[] = $label;
        }
    }
    $runtime->save($current);
    echo json_encode([
        'status' => 'ok',
        'changed' => true,
        'scheduled_rules' => count($current),
        'states_cleared' => count($killed),
    ], JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR, $error->getMessage() . PHP_EOL);
    exit(1);
}
