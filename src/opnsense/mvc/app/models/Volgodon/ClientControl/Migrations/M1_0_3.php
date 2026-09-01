<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\Migrations;

use OPNsense\Base\BaseModelMigration;
use Volgodon\ClientControl\AuditLog;
use Volgodon\ClientControl\ClientControl;

class M1_0_3 extends BaseModelMigration
{
    public function run($model)
    {
        if (!($model instanceof ClientControl)) {
            return;
        }

        $records = [];
        $uuids = [];
        foreach ($model->audit->entry->iterateItems() as $uuid => $entry) {
            $uuids[] = $uuid;
            $summary = (string)$entry->summary;
            $records[] = [
                'uuid' => (string)$uuid,
                'timestamp' => (string)$entry->timestamp,
                'username' => (string)$entry->username,
                'operation' => (string)$entry->operation,
                'summary' => $summary,
                'result' => (string)$entry->result,
            ];
            $entry->summary = AuditLog::compactSummary($summary);
        }

        // Persist first. If this fails, the migration aborts before config.xml
        // is pruned; a retry is idempotent because UUIDs are de-duplicated.
        if ($records !== []) {
            (new AuditLog())->append($records, true);
        }
        while (count($uuids) > AuditLog::CONFIG_LIMIT) {
            $model->audit->entry->del(array_shift($uuids));
        }
        parent::run($model);
    }
}
