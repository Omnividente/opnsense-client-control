<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

final class PlanFingerprint
{
    public static function intent($revision, $mode, $strategy, array $desired, array $managed, array $raw)
    {
        $managedState = [];
        foreach ($managed as $identity => $record) {
            $managedState[(string)$identity] = [
                'identity' => (string)($record['identity'] ?? $identity),
                'owner_type' => (string)($record['owner_type'] ?? ''),
                'owner_uuid' => (string)($record['owner_uuid'] ?? ''),
                'core_type' => (string)($record['core_type'] ?? ''),
                'core_uuid' => (string)($record['core_uuid'] ?? ''),
                'core_name' => (string)($record['core_name'] ?? ''),
                'desired_fingerprint' => (string)($record['desired_fingerprint'] ?? ''),
                'applied_state' => self::stableAppliedState($record),
            ];
        }
        ksort($managedState, SORT_STRING);

        $actualState = [];
        foreach ($raw as $record) {
            $actualState[] = [
                'core_type' => (string)($record['core_type'] ?? ''),
                'core_uuid' => (string)($record['core_uuid'] ?? ''),
                'core_name' => (string)($record['core_name'] ?? ''),
                'owned' => !empty($record['owned']),
                'ownership_intact' => !empty($record['ownership_intact']),
                'fields' => self::stableFields($record['core_type'] ?? '', $record['raw_fields'] ?? []),
            ];
        }
        usort($actualState, function ($left, $right) {
            return [
                $left['core_type'],
                $left['core_uuid'],
                $left['core_name'],
            ] <=> [
                $right['core_type'],
                $right['core_uuid'],
                $right['core_name'],
            ];
        });

        $platform = Platform::featureMatrix();
        return Canonical::fingerprint([
            'revision' => (int)$revision,
            'mode' => (string)$mode,
            'strategy' => (string)$strategy,
            // Compiler::fingerprint intentionally excludes resolved MAC IPs.
            'desired_fingerprint' => (string)($desired['fingerprint'] ?? ''),
            'warnings' => array_values(array_filter($desired['warnings'] ?? [], 'is_array')),
            'notices' => array_values(array_filter($desired['notices'] ?? [], 'is_array')),
            'managed' => $managedState,
            'actual' => $actualState,
            'platform' => [
                'filter_backend' => $platform['filter_backend'],
                'requirements' => $platform['requirements'],
                'legacy_shaper_runtime' => $platform['legacy_shaper_runtime'],
                'packet_rate' => $platform['packet_rate'],
            ],
        ]);
    }

    public static function runtime($intentFingerprint, array $desired, array $plan)
    {
        return Canonical::fingerprint([
            'intent_fingerprint' => (string)$intentFingerprint,
            'runtime_fingerprint' => (string)($desired['runtime_fingerprint'] ?? ''),
            'operations' => $plan['operations'] ?? [],
            'conflicts' => $plan['conflicts'] ?? [],
        ]);
    }

    private static function stableAppliedState(array $record)
    {
        $state = json_decode((string)($record['applied_state'] ?? ''), true);
        if (!is_array($state)) {
            return [];
        }
        return [
            'fields' => self::stableFields($record['core_type'] ?? '', $state['fields'] ?? []),
            'allocation' => is_array($state['allocation'] ?? null) ? $state['allocation'] : [],
        ];
    }

    private static function stableFields($coreType, $fields)
    {
        $fields = is_array($fields) ? $fields : [];
        if ((string)$coreType === 'shaper_rule') {
            // Shaper matches contain addresses resolved from ARP/NDP. Explicit
            // client/group configuration remains covered by desired_fingerprint.
            unset($fields['source'], $fields['destination']);
        }
        ksort($fields, SORT_STRING);
        return $fields;
    }
}
