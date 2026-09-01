<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\Api;

class SettingsController extends ClientControlControllerBase
{
    protected static $internalModelName = 'general';

    private const EDITABLE_FIELDS = [
        'enabled',
        'protected_interfaces',
        'wan_interfaces',
        'enforcement_mode',
        'destination_scope',
        'destination_alias',
    ];

    public function getAction()
    {
        if (!$this->request->isGet()) {
            return [];
        }
        $model = $this->getModel();
        return [
            'general' => array_merge($model->general->getNodes(), [
                'revision' => ((int) (string) $model->general->revision),
            ]),
            'revision' => ((int) (string) $model->general->revision),
            'sync_state' => $model->getSyncState(),
        ];
    }

    public function setAction()
    {
        $this->requirePost();
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $payload = $this->getRequiredArray('general');
            foreach (['protected_interfaces', 'wan_interfaces'] as $field) {
                if (isset($payload[$field]) && is_array($payload[$field])) {
                    $payload[$field] = implode(',', array_values(array_unique(array_map('strval', $payload[$field]))));
                }
            }
            $model->general->setNodes(array_intersect_key($payload, array_flip(self::EDITABLE_FIELDS)));
            return $this->finishMutation(
                $model,
                'settings.set',
                'updated module settings',
                [],
                $model->general,
                'general'
            );
        } finally {
            $this->unlockModel();
        }
    }
}
