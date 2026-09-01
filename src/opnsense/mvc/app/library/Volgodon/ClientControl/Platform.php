<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

final class Platform
{
    public static function featureMatrix($appliedFilterBackend = '')
    {
        $requirements = [
            'persistent_filter_model' => class_exists('OPNsense\\Firewall\\Filter'),
            'schedule_field' => class_exists('OPNsense\\Firewall\\FieldTypes\\ScheduleField'),
        ];
        $filterBackend = !in_array(false, $requirements, true)
            ? 'persistent_model' : 'runtime_registry';
        $appliedFilterBackend = trim((string)$appliedFilterBackend);
        $transitionPending = $appliedFilterBackend !== '' && $appliedFilterBackend !== $filterBackend;
        $warning = '';
        if ($transitionPending) {
            $warning = sprintf(
                gettext('Firewall backend capability changed from %s to %s. Review and apply the current plan before relying on the new backend.'),
                $appliedFilterBackend,
                $filterBackend
            );
        } elseif ($filterBackend === 'runtime_registry') {
            $warning = gettext('Compatibility firewall backend is active because the persistent filter model lacks a required capability.');
        }
        return [
            'filter_backend' => $filterBackend,
            'applied_filter_backend' => $appliedFilterBackend,
            'transition_pending' => $transitionPending,
            'requirements' => $requirements,
            'legacy_shaper_runtime' => $filterBackend === 'runtime_registry',
            'packet_rate' => $filterBackend === 'persistent_model',
            'warning' => $warning,
        ];
    }

    public static function usesRuntimeFilterRegistry()
    {
        return self::featureMatrix()['filter_backend'] === 'runtime_registry';
    }

    public static function usesLegacyShaperRuntime()
    {
        return self::featureMatrix()['legacy_shaper_runtime'];
    }

    public static function supportsPacketRate()
    {
        return self::featureMatrix()['packet_rate'];
    }

    public static function listValues($field)
    {
        return array_values(array_filter(
            array_map('trim', explode(',', (string)$field)),
            'strlen'
        ));
    }
}
