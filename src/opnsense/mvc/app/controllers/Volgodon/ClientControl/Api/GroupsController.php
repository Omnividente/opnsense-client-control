<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\Api;

use OPNsense\Base\UserException;

class GroupsController extends ClientControlControllerBase
{
    protected static $internalModelName = 'group';

    private const GROUP_FIELDS = [
        'enabled',
        'name',
        'description',
        'access',
        'shaping_mode',
        'download',
        'upload',
        'metric',
        'schedule',
        'max_states',
        'max_tcp_connections',
        'connection_rate',
        'connection_rate_seconds',
        'packet_rate',
        'packet_rate_seconds',
    ];
    private const INTEGER_LIMITS = [
        'download' => 1000000,
        'upload' => 1000000,
        'max_states' => 2147483647,
        'max_tcp_connections' => 2147483647,
        'connection_rate' => 4294967,
        'connection_rate_seconds' => 2147483647,
        'packet_rate' => 4294967,
        'packet_rate_seconds' => 2147483647,
    ];


    public function searchGroupAction()
    {
        $model = $this->getModel();
        $memberCounts = [];
        foreach ($model->clients->client->iterateItems() as $client) {
            $groupUuid = (string)$client->group;
            $memberCounts[$groupUuid] = ($memberCounts[$groupUuid] ?? 0) + 1;
        }
        $records = [];
        foreach ($model->groups->group->iterateItems() as $uuid => $group) {
            $records[] = [
                'uuid' => $uuid,
                'enabled' => ((string) $group->enabled === (string) '1') ? 1 : 0,
                'name' => (string)$group->name,
                'description' => (string)$group->description,
                'members' => $memberCounts[$uuid] ?? 0,
                'access' => (string)$group->access,
                'shaping_mode' => (string)$group->shaping_mode,
                'download' => ((int) (string) $group->download),
                'upload' => ((int) (string) $group->upload),
                'metric' => (string)$group->metric,
                'schedule' => (string)$group->schedule,
                'max_states' => ((int) (string) $group->max_states),
                'max_tcp_connections' => ((int) (string) $group->max_tcp_connections),
                'connection_rate' => ((int) (string) $group->connection_rate),
                'connection_rate_seconds' => ((int) (string) $group->connection_rate_seconds),
                'packet_rate' => ((int) (string) $group->packet_rate),
                'packet_rate_seconds' => ((int) (string) $group->packet_rate_seconds),
                'sync_state' => $model->getSyncState(),
            ];
        }
        $accessFilter = $this->request->getPost('access');
        $modeFilter = $this->request->getPost('shaping_mode');
        $filter = function ($record) use ($accessFilter, $modeFilter) {
            if ($accessFilter !== null && $accessFilter !== '' &&
                !in_array($record['access'], array_map('strval', (array)$accessFilter), true)) {
                return false;
            }
            if ($modeFilter !== null && $modeFilter !== '' &&
                !in_array($record['shaping_mode'], array_map('strval', (array)$modeFilter), true)) {
                return false;
            }
            return true;
        };
        $result = $this->searchRecordsetBase(
            $records,
            ['name', 'description', 'access', 'shaping_mode', 'schedule'],
            'name',
            $filter
        );
        $result['revision'] = ((int) (string) $model->general->revision);
        return $result;
    }

    public function getGroupAction($uuid = null)
    {
        $model = $this->getModel();
        if ($uuid === null) {
            $node = $model->groups->group->Add();
        } elseif (!$this->isValidUUID($uuid) ||
            ($node = $model->getNodeByReference('groups.group.' . $uuid)) === null) {
            return [];
        }
        $result = [
            'group' => $node->getNodes(),
            'revision' => ((int) (string) $model->general->revision),
        ];
        if ($uuid !== null) {
            $result['group']['uuid'] = $uuid;
            $result['members'] = $model->getGroupMemberCount($uuid);
        }
        return $result;
    }

    public function addGroupAction()
    {
        $this->requirePost();
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $group = $model->groups->group->Add();
            $group->setNodes($this->groupFields($this->getRequiredArray('group')));
            $uuid = $group->getAttribute('uuid');
            return $this->finishMutation(
                $model,
                'group.add',
                sprintf('added group %s {%s}', (string)$group->name, $uuid),
                ['uuid' => $uuid]
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function setGroupAction($uuid)
    {
        $this->requirePost();
        if (!$this->isValidUUID($uuid)) {
            return ['result' => 'failed'];
        }
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $group = $model->getNodeByReference('groups.group.' . $uuid);
            if ($group === null) {
                throw new UserException(gettext('The group no longer exists.'), gettext('Client Control'));
            }
            $group->setNodes($this->groupFields($this->getRequiredArray('group')));
            return $this->finishMutation(
                $model,
                'group.set',
                sprintf('updated group %s {%s}', (string)$group->name, $uuid)
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function delGroupAction($uuid)
    {
        $this->requirePost();
        if (!$this->isValidUUID($uuid)) {
            return ['result' => 'failed'];
        }
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $group = $model->getNodeByReference('groups.group.' . $uuid);
            if ($group === null) {
                throw new UserException(gettext('The group no longer exists.'), gettext('Client Control'));
            }
            $targetUuid = trim((string)$this->request->getPost('target_group_uuid'));
            $members = [];
            foreach ($model->clients->client->iterateItems() as $clientUuid => $client) {
                if (((string) $client->group === (string) $uuid)) {
                    $members[$clientUuid] = $client;
                }
            }
            if (!empty($members)) {
                if (!$this->isValidUUID($targetUuid) || $targetUuid === $uuid ||
                    $model->getNodeByReference('groups.group.' . $targetUuid) === null) {
                    throw new UserException(
                        gettext('Select another existing group for all current members before deletion.'),
                        gettext('Client Control')
                    );
                }
                foreach ($members as $client) {
                    $client->group = $targetUuid;
                }
            }
            $name = (string)$group->name;
            $model->groups->group->del($uuid);
            return $this->finishMutation(
                $model,
                'group.delete',
                sprintf('deleted group %s {%s} and moved %d client(s)', $name, $uuid, count($members)),
                ['moved' => count($members)]
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function toggleGroupAction($uuid, $enabled = null)
    {
        $this->requirePost();
        if (!$this->isValidUUID($uuid)) {
            return ['result' => 'failed'];
        }
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $group = $model->getNodeByReference('groups.group.' . $uuid);
            if ($group === null) {
                throw new UserException(gettext('The group no longer exists.'), gettext('Client Control'));
            }
            $next = $enabled === null || $enabled === '' ?
                (((string) $group->enabled === (string) '1') ? '0' : '1') : (string)$enabled;
            if (!in_array($next, ['0', '1'], true)) {
                throw new UserException(gettext('Enabled must be 0 or 1.'), gettext('Client Control'));
            }
            $group->enabled = $next;
            return $this->finishMutation(
                $model,
                'group.toggle',
                sprintf('%s group %s {%s}', $next === '1' ? 'enabled' : 'disabled', (string)$group->name, $uuid)
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function copyGroupAction($uuid)
    {
        $this->requirePost();
        if (!$this->isValidUUID($uuid)) {
            return ['result' => 'failed'];
        }
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $source = $model->getNodeByReference('groups.group.' . $uuid);
            if ($source === null) {
                throw new UserException(gettext('The group no longer exists.'), gettext('Client Control'));
            }
            $copy = $model->groups->group->Add();
            foreach (self::GROUP_FIELDS as $field) {
                $copy->$field = (string)$source->$field;
            }
            $copy->enabled = '0';
            $copy->name = trim((string)$this->request->getPost('name')) ?: (string)$source->name . ' copy';
            $copyUuid = $copy->getAttribute('uuid');
            return $this->finishMutation(
                $model,
                'group.copy',
                sprintf('copied group %s {%s} to {%s}', (string)$source->name, $uuid, $copyUuid),
                ['uuid' => $copyUuid]
            );
        } finally {
            $this->unlockModel();
        }
    }

    private function groupFields($payload)
    {
        $fields = array_intersect_key($payload, array_flip(self::GROUP_FIELDS));
        foreach (self::INTEGER_LIMITS as $field => $maximum) {
            if (!array_key_exists($field, $fields)) {
                continue;
            }
            $value = $fields[$field];
            if ((!is_string($value) && !is_int($value)) ||
                !preg_match('/^(?:0|[1-9][0-9]*)$/D', (string)$value) ||
                (int)$value > $maximum) {
                throw new UserException(
                    sprintf(gettext('%s must be a whole number from 0 through %d.'), $field, $maximum),
                    gettext('Client Control')
                );
            }
            $fields[$field] = (string)$value;
        }
        return $fields;
    }
}
