<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\FieldTypes;

use OPNsense\Base\FieldTypes\BaseListField;
use OPNsense\Firewall\Alias;

final class DestinationAliasField extends BaseListField
{
    protected function actionPostLoadingEvent()
    {
        $options = [];
        $aliasModel = new Alias();
        foreach ($aliasModel->aliases->alias->iterateItems() as $alias) {
            $type = (string)$alias->type;
            $name = trim((string)$alias->name);
            if ($name !== '' && !in_array($type, ['port', 'urltable_ports'], true) &&
                !str_starts_with($name, 'CC_')) {
                $options[$name] = $name;
            }
        }
        $current = trim((string)$this);
        if ($current !== '' && !isset($options[$current])) {
            $options[$current] = sprintf(gettext('Missing alias: %s'), $current);
        }
        ksort($options, SORT_NATURAL | SORT_FLAG_CASE);
        $this->internalOptionList = $options;
        return parent::actionPostLoadingEvent();
    }
}
