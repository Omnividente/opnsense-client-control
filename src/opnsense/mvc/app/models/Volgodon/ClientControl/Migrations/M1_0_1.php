<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\Migrations;

use OPNsense\Base\BaseModelMigration;
use Volgodon\ClientControl\ClientControl;

class M1_0_1 extends BaseModelMigration
{
    private const RECOVERY_GROUP_NAME = 'Recovered orphaned clients';
    private const RECOVERY_MARKER = 'Recovered during Client Control 1.0.1 upgrade: the original group was missing.';

    public function run($model)
    {
        if (!($model instanceof ClientControl)) {
            return;
        }

        $groups = [];
        $groupNames = [];
        foreach ($model->groups->group->iterateItems() as $uuid => $group) {
            $groups[(string)$uuid] = true;
            $groupNames[strtolower((string)$group->name)] = true;
        }

        $orphaned = [];
        foreach ($model->clients->client->iterateItems() as $client) {
            if (!isset($groups[(string)$client->group])) {
                $orphaned[] = $client;
            }
        }
        if ($orphaned === []) {
            parent::run($model);
            return;
        }

        $name = self::RECOVERY_GROUP_NAME;
        for ($suffix = 2; isset($groupNames[strtolower($name)]); $suffix++) {
            $name = self::RECOVERY_GROUP_NAME . ' ' . $suffix;
        }
        $recovery = $model->groups->group->Add();
        $recovery->enabled = '0';
        $recovery->name = $name;
        $recovery->description = 'Disabled recovery group created for clients whose group reference was missing.';
        $recovery->access = 'block';
        $recovery->shaping_mode = 'unlimited';
        $recovery->download = '0';
        $recovery->upload = '0';
        $recovery->metric = 'Mbit';
        $recoveryUuid = $recovery->getAttribute('uuid');

        foreach ($orphaned as $client) {
            $client->enabled = '0';
            $client->group = $recoveryUuid;
            $comment = trim((string)$client->comment);
            if (strpos($comment, self::RECOVERY_MARKER) === false) {
                $client->comment = substr(trim($comment . ' ' . self::RECOVERY_MARKER), 0, 255);
            }
        }
        parent::run($model);
    }
}
