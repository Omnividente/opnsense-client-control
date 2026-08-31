<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

final class RuntimeSchedule
{
    public const STATE_FILE = '/var/run/clientcontrol-schedule.json';

    public function current($model, $now = null)
    {
        $state = [];
        if (!((string) $model->general->enabled === (string) '1') ||
            !((string) $model->general->enforcement_mode === (string) 'enforce')) {
            return $state;
        }
        $desired = (new Compiler())->compile($model);
        $evaluator = new ScheduleEvaluator();
        $hook = new FirewallHook();
        foreach ($desired['filter_rules'] as $rule) {
            if ($rule['owner_type'] !== 'group') {
                continue;
            }
            $group = $model->getNodeByReference('groups.group.' . $rule['owner_uuid']);
            if ($group === null || trim((string)$group->schedule) === '') {
                continue;
            }
            $packetRate = ((int) (string) $group->packet_rate);
            $packetRateSeconds = ((int) (string) $group->packet_rate_seconds);
            $active = $evaluator->isActive((string)$group->schedule, $now);
            $config = $hook->ruleConfig(
                $rule['fields'],
                $rule['core_name'],
                $packetRate,
                $packetRateSeconds,
                $active
            );
            $state[$config['label']] = $active;
        }
        ksort($state, SORT_STRING);
        return $state;
    }

    public function load()
    {
        $data = @file_get_contents(self::STATE_FILE);
        $state = is_string($data) ? json_decode($data, true) : null;
        if (!is_array($state)) {
            return [];
        }
        $result = [];
        foreach ($state as $label => $active) {
            if (preg_match('/^clientcontrol_[0-9a-f]{32}$/', (string)$label)) {
                $result[$label] = (bool)$active;
            }
        }
        ksort($result, SORT_STRING);
        return $result;
    }

    public function save(array $state)
    {
        ksort($state, SORT_STRING);
        $directory = dirname(self::STATE_FILE);
        $temporary = tempnam($directory, '.clientcontrol-schedule.');
        if ($temporary === false) {
            throw new \RuntimeException('Unable to create the Client Control schedule state file.');
        }
        try {
            if (file_put_contents($temporary, Canonical::encode($state) . "\n", LOCK_EX) === false ||
                !chmod($temporary, 0600) || !rename($temporary, self::STATE_FILE)) {
                throw new \RuntimeException('Unable to persist the Client Control schedule state.');
            }
        } finally {
            if (file_exists($temporary)) {
                @unlink($temporary);
            }
        }
    }

    public function labelsToKill(array $previous, array $current)
    {
        $result = [];
        foreach ($previous as $label => $active) {
            if ($active && empty($current[$label])) {
                $result[] = $label;
            }
        }
        sort($result, SORT_STRING);
        return $result;
    }
}
