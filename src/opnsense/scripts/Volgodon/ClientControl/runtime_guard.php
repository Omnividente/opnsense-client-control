#!/usr/local/bin/php
<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

require_once('config.inc');

use Volgodon\ClientControl\ClientControl;
use Volgodon\ClientControl\Compiler;
use Volgodon\ClientControl\FirewallHook;
use Volgodon\ClientControl\Platform;
use Volgodon\ClientControl\ScheduleEvaluator;

try {
    $model = new ClientControl();
    $desired = (new Compiler())->compile($model);
    $hook = new FirewallHook();
    $scheduleEvaluator = new ScheduleEvaluator();
    $expectedLabels = [];
    foreach ($desired['filter_rules'] as $rule) {
        $packetRate = 0;
        $packetRateSeconds = 0;
        $scheduleActive = true;
        if ($rule['owner_type'] === 'group') {
            $group = $model->getNodeByReference('groups.group.' . $rule['owner_uuid']);
            if ($group !== null) {
                $packetRate = ((int) (string) $group->packet_rate);
                $packetRateSeconds = ((int) (string) $group->packet_rate_seconds);
                $scheduleActive = $scheduleEvaluator->isActive((string)$group->schedule);
            }
        }
        if ($packetRate > 0 && !Platform::supportsPacketRate()) {
            throw new RuntimeException('Packet-rate limiting is not supported by the installed firewall runtime.');
        }
        $config = $hook->ruleConfig(
            $rule['fields'],
            $rule['core_name'],
            $packetRate,
            $packetRateSeconds,
            $scheduleActive
        );
        if (empty($config['disabled'])) {
            $expectedLabels[$config['label']] = $packetRate > 0;
        }
    }
    ksort($expectedLabels, SORT_STRING);

    $rulesDebug = @file_get_contents('/tmp/rules.debug');
    $rulesDebug = is_string($rulesDebug) ? $rulesDebug : '';
    preg_match_all('/^(?!\s*#).*\blabel\s+"(clientcontrol_[0-9a-f]{32})"/m', $rulesDebug, $matches);
    $actualLabels = array_values(array_unique($matches[1] ?? []));
    sort($actualLabels, SORT_STRING);
    $missingLabels = array_values(array_diff(array_keys($expectedLabels), $actualLabels));
    $orphanLabels = array_values(array_diff($actualLabels, array_keys($expectedLabels)));
    $missingPacketRate = [];
    foreach ($expectedLabels as $label => $requiresPacketRate) {
        if ($requiresPacketRate && !preg_match(
            '/^(?!\s*#).*\bmax-pkt-rate\b.*\blabel\s+"' . preg_quote($label, '/') . '"/m',
            $rulesDebug
        )) {
            $missingPacketRate[] = $label;
        }
    }

    $ipfwRules = @file_get_contents('/usr/local/etc/ipfw.rules');
    $ipfwRules = is_string($ipfwRules) ? $ipfwRules : '';
    $missingPipes = [];
    $missingShaperRules = [];
    foreach ($model->managed_objects->object->iterateItems() as $record) {
        $coreType = (string)$record->core_type;
        if ($coreType !== 'pipe' && $coreType !== 'shaper_rule') {
            continue;
        }
        $state = json_decode((string)$record->applied_state, true);
        $allocation = is_array($state) && is_array($state['allocation'] ?? null) ? $state['allocation'] : [];
        if ($coreType === 'pipe') {
            $number = (int)($allocation['number'] ?? 0);
            if ($number > 0 && !preg_match('/^\s*pipe\s+' . $number . '\s+config\b/m', $ipfwRules)) {
                $missingPipes[] = (string)$record->logical_id;
            }
        } else {
            $sequence = (int)($allocation['sequence'] ?? 0);
            $runtimeSequence = Platform::usesLegacyShaperRuntime() ? 60000 + $sequence : $sequence;
            if ($sequence > 0 && !preg_match('/^\s*add\s+' . $runtimeSequence . '\s+\S+/m', $ipfwRules)) {
                $missingShaperRules[] = (string)$record->logical_id;
            }
        }
    }
    sort($missingPipes, SORT_STRING);
    sort($missingShaperRules, SORT_STRING);

    $errors = [];
    if (!empty($missingLabels)) {
        $errors[] = 'missing runtime firewall labels';
    }
    if (!empty($orphanLabels)) {
        $errors[] = 'orphan runtime firewall labels';
    }
    if (!empty($missingPacketRate)) {
        $errors[] = 'missing packet-rate guards';
    }
    if (!empty($missingPipes)) {
        $errors[] = 'missing IPFW pipes';
    }
    if (!empty($missingShaperRules)) {
        $errors[] = 'missing IPFW shaper rules';
    }
    echo json_encode([
        'status' => empty($errors) ? 'ok' : 'error',
        'runtime_guard' => empty($errors) ? 'verified' : 'failed',
        'errors' => $errors,
        'expected_filter_rules' => count($expectedLabels),
        'actual_filter_rules' => count($actualLabels),
        'missing_filter_labels' => $missingLabels,
        'orphan_filter_labels' => $orphanLabels,
        'missing_packet_rate_labels' => $missingPacketRate,
        'missing_pipes' => $missingPipes,
        'missing_shaper_rules' => $missingShaperRules,
    ], JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit(empty($errors) ? 0 : 1);
} catch (Throwable $error) {
    fwrite(STDERR, $error->getMessage() . PHP_EOL);
    exit(1);
}
