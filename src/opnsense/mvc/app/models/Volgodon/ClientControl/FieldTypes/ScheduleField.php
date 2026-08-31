<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\FieldTypes;

use OPNsense\Base\FieldTypes\BaseListField;
use OPNsense\Core\Config;

final class ScheduleField extends BaseListField
{
    protected function actionPostLoadingEvent()
    {
        $options = [];
        $config = Config::getInstance()->object();
        if (isset($config->schedules->schedule)) {
            foreach ($config->schedules->schedule as $schedule) {
                $name = trim((string)$schedule->name);
                if ($name !== '') {
                    $options[$name] = $name;
                }
            }
        }
        ksort($options, SORT_NATURAL | SORT_FLAG_CASE);
        $this->internalOptionList = $options;
        return parent::actionPostLoadingEvent();
    }
}
