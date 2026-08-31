<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

final class Platform
{
    public static function usesRuntimeFilterRegistry()
    {
        return !class_exists('OPNsense\\Firewall\\FieldTypes\\ScheduleField');
    }

    public static function usesLegacyShaperRuntime()
    {
        return self::usesRuntimeFilterRegistry();
    }

    public static function supportsPacketRate()
    {
        return !self::usesRuntimeFilterRegistry();
    }

    public static function listValues($field)
    {
        return array_values(array_filter(
            array_map('trim', explode(',', (string)$field)),
            'strlen'
        ));
    }
}
