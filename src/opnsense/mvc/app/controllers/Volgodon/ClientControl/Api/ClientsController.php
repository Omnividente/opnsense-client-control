<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\Api;

use OPNsense\Base\UserException;
use OPNsense\Core\Backend;

class ClientsController extends ClientControlControllerBase
{
    protected static $internalModelName = 'client';

    private const CLIENT_FIELDS = [
        'enabled',
        'name',
        'group',
        'comment',
        'access_override',
        'shaping_override',
        'download_override',
        'upload_override',
        'metric_override',
    ];

    public function searchClientAction()
    {
        $records = [];
        $model = $this->getModel();
        $runtime = $this->runtimeClientStats($model);
        foreach ($model->clients->client->iterateItems() as $uuid => $client) {
            $records[] = $this->clientRecord($model, $uuid, $client, $runtime[$uuid] ?? []);
        }

        $groupFilter = $this->request->getPost('group_uuid');
        $accessFilter = $this->request->getPost('access');
        $syncFilter = $this->request->getPost('sync_state');
        $enabledFilter = $this->request->getPost('enabled');
        $filter = function ($record) use ($groupFilter, $accessFilter, $syncFilter, $enabledFilter) {
            if (!$this->matchesFilter($record['group_uuid'], $groupFilter)) {
                return false;
            }
            if (!$this->matchesFilter($record['access'], $accessFilter)) {
                return false;
            }
            if (!$this->matchesFilter($record['sync_state'], $syncFilter)) {
                return false;
            }
            if ($enabledFilter !== null && $enabledFilter !== '' &&
                !$this->matchesFilter((string)$record['enabled'], $enabledFilter)) {
                return false;
            }
            return true;
        };
        $result = $this->searchRecordsetBase(
            $records,
            ['name', 'endpoints_text', 'group_name', 'comment', 'access', 'sync_state'],
            'name',
            $filter
        );
        $result['revision'] = ((int) (string) $model->general->revision);
        return $result;
    }

    public function getClientAction($uuid = null)
    {
        $model = $this->getModel();
        if ($uuid === null) {
            $node = $model->clients->client->Add();
        } elseif (!$this->isValidUUID($uuid) ||
            ($node = $model->getNodeByReference('clients.client.' . $uuid)) === null) {
            return [];
        }
        $clientData = $node->getNodes();
        $groupOptions = [];
        $currentGroup = (string)$node->group;
        foreach ($model->groups->group->iterateItems() as $groupUuid => $group) {
            $groupOptions[$groupUuid] = [
                'value' => (string)$group->name,
                'selected' => $groupUuid === $currentGroup ? 1 : 0,
            ];
        }
        $clientData['group'] = $groupOptions;
        $result = [
            'client' => $clientData,
            'endpoints' => $uuid === null ? [] : $model->getClientEndpoints($uuid),
            'revision' => ((int) (string) $model->general->revision),
        ];
        if ($uuid !== null) {
            $result['client']['uuid'] = $uuid;
            $result['effective_policy'] = $model->getEffectivePolicy($uuid);
        }
        return $result;

    }

    public function addClientAction()
    {
        $this->requirePost();
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $payload = $this->getRequiredArray('client');
            $endpoints = $this->extractEndpoints($payload, false);
            $client = $model->clients->client->Add();
            $client->setNodes($this->clientFields($payload));
            $uuid = $client->getAttribute('uuid');
            if ($endpoints !== null) {
                $this->syncEndpoints($model, $uuid, $endpoints, false);
            }
            return $this->finishMutation(
                $model,
                'client.add',
                sprintf('added client %s {%s}', (string)$client->name, $uuid),
                ['uuid' => $uuid]
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function setClientAction($uuid)
    {
        $this->requirePost();
        if (!$this->isValidUUID($uuid)) {
            return ['result' => 'failed'];
        }
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $client = $model->getNodeByReference('clients.client.' . $uuid);
            if ($client === null) {
                throw new UserException(gettext('The client no longer exists.'), gettext('Client Control'));
            }
            $payload = $this->getRequiredArray('client');
            $endpoints = $this->extractEndpoints($payload, false);
            $client->setNodes($this->clientFields($payload));
            if ($endpoints !== null) {
                $this->syncEndpoints($model, $uuid, $endpoints, true);
            }
            return $this->finishMutation(
                $model,
                'client.set',
                sprintf('updated client %s {%s}', (string)$client->name, $uuid)
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function delClientAction($uuids = null)
    {
        $this->requirePost();
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $selected = $this->requestedClientUuids($uuids);
            $deleted = 0;
            foreach ($selected as $uuid) {
                $client = $model->getNodeByReference('clients.client.' . $uuid);
                if ($client === null) {
                    throw new UserException(gettext('A selected client no longer exists.'), gettext('Client Control'));
                }
                $this->deleteClientEndpoints($model, $uuid);
                if ($model->clients->client->del($uuid)) {
                    $deleted++;
                }
            }
            return $this->finishMutation(
                $model,
                'client.delete',
                sprintf('deleted %d client(s)', $deleted),
                ['deleted' => $deleted]
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function toggleClientAction($uuid, $enabled = null)
    {
        $this->requirePost();
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            if (!$this->isValidUUID($uuid) ||
                ($client = $model->getNodeByReference('clients.client.' . $uuid)) === null) {
                throw new UserException(gettext('The client no longer exists.'), gettext('Client Control'));
            }
            $next = $enabled === null || $enabled === '' ?
                (((string) $client->enabled === (string) '1') ? '0' : '1') : (string)$enabled;
            if (!in_array($next, ['0', '1'], true)) {
                throw new UserException(gettext('Enabled must be 0 or 1.'), gettext('Client Control'));
            }
            $client->enabled = $next;
            return $this->finishMutation(
                $model,
                'client.toggle',
                sprintf('%s client %s {%s}', $next === '1' ? 'enabled' : 'disabled', (string)$client->name, $uuid)
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function bulkMoveAction()
    {
        $this->requirePost();
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $groupUuid = (string)$this->request->getPost('group_uuid');
            if (!$this->isValidUUID($groupUuid) ||
                $model->getNodeByReference('groups.group.' . $groupUuid) === null) {
                throw new UserException(gettext('The target group does not exist.'), gettext('Client Control'));
            }
            $selected = $this->requestedClientUuids();
            $changed = 0;
            foreach ($selected as $uuid) {
                $client = $model->getNodeByReference('clients.client.' . $uuid);
                if ($client === null) {
                    throw new UserException(gettext('A selected client no longer exists.'), gettext('Client Control'));
                }
                if (!((string) $client->group === (string) $groupUuid)) {
                    $client->group = $groupUuid;
                    $changed++;
                }
            }
            return $this->finishMutation(
                $model,
                'client.bulk_move',
                sprintf('moved %d client(s) to group {%s}', $changed, $groupUuid),
                ['changed' => $changed]
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function bulkToggleAction()
    {
        $this->requirePost();
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $enabled = (string)$this->request->getPost('enabled');
            if (!in_array($enabled, ['0', '1'], true)) {
                throw new UserException(gettext('Enabled must be 0 or 1.'), gettext('Client Control'));
            }
            $changed = 0;
            foreach ($this->requestedClientUuids() as $uuid) {
                $client = $model->getNodeByReference('clients.client.' . $uuid);
                if ($client === null) {
                    throw new UserException(gettext('A selected client no longer exists.'), gettext('Client Control'));
                }
                if (!((string) $client->enabled === (string) $enabled)) {
                    $client->enabled = $enabled;
                    $changed++;
                }
            }
            return $this->finishMutation(
                $model,
                'client.bulk_toggle',
                sprintf('%s %d client(s)', $enabled === '1' ? 'enabled' : 'disabled', $changed),
                ['changed' => $changed]
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function copyClientAction($uuid)
    {
        $this->requirePost();
        if (!$this->isValidUUID($uuid)) {
            return ['result' => 'failed'];
        }
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $source = $model->getNodeByReference('clients.client.' . $uuid);
            if ($source === null) {
                throw new UserException(gettext('The client no longer exists.'), gettext('Client Control'));
            }
            $copy = $model->clients->client->Add();
            foreach (self::CLIENT_FIELDS as $field) {
                $copy->$field = (string)$source->$field;
            }
            $copy->enabled = '0';
            $copy->name = trim((string)$this->request->getPost('name')) ?: (string)$source->name . ' copy';
            $copyUuid = $copy->getAttribute('uuid');
            return $this->finishMutation(
                $model,
                'client.copy',
                sprintf('copied client %s {%s} to disabled client {%s} without endpoints', (string)$source->name, $uuid, $copyUuid),
                ['uuid' => $copyUuid]
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function addEndpointAction($clientUuid = null)
    {
        $this->requirePost();
        $payload = $this->getRequiredArray('endpoint');
        if ($clientUuid === null) {
            $clientUuid = (string)($payload['client'] ?? '');
        }
        if (!$this->isValidUUID($clientUuid)) {
            return ['result' => 'failed'];
        }
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            if ($model->getNodeByReference('clients.client.' . $clientUuid) === null) {
                throw new UserException(gettext('The client no longer exists.'), gettext('Client Control'));
            }
            $endpoint = $this->addEndpointNode($model, $clientUuid, $payload);
            $uuid = $endpoint->getAttribute('uuid');
            return $this->finishMutation(
                $model,
                'endpoint.add',
                sprintf('added endpoint {%s} to client {%s}', $uuid, $clientUuid),
                ['uuid' => $uuid]
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function setEndpointAction($uuid)
    {
        $this->requirePost();
        if (!$this->isValidUUID($uuid)) {
            return ['result' => 'failed'];
        }
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $endpoint = $model->getNodeByReference('endpoints.endpoint.' . $uuid);
            if ($endpoint === null) {
                throw new UserException(gettext('The endpoint no longer exists.'), gettext('Client Control'));
            }
            $payload = $this->getRequiredArray('endpoint');
            if (isset($payload['client'])) {
                $clientUuid = (string)$payload['client'];
                if (!$this->isValidUUID($clientUuid) ||
                    $model->getNodeByReference('clients.client.' . $clientUuid) === null) {
                    throw new UserException(gettext('The selected client no longer exists.'), gettext('Client Control'));
                }
                $endpoint->client = $clientUuid;
            }
            $endpoint->setNodes(array_intersect_key($payload, array_flip(['kind', 'value', 'label'])));
            return $this->finishMutation(
                $model,
                'endpoint.set',
                sprintf('updated endpoint {%s}', $uuid)
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function delEndpointAction($uuid)
    {
        $this->requirePost();
        if (!$this->isValidUUID($uuid)) {
            return ['result' => 'failed'];
        }
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            if (!$model->endpoints->endpoint->del($uuid)) {
                throw new UserException(gettext('The endpoint no longer exists.'), gettext('Client Control'));
            }
            return $this->finishMutation(
                $model,
                'endpoint.delete',
                sprintf('deleted endpoint {%s}', $uuid)
            );
        } finally {
            $this->unlockModel();
        }
    }

    public function searchEndpointsAction()
    {
        $records = [];
        $model = $this->getModel();
        foreach ($model->endpoints->endpoint->iterateItems() as $uuid => $endpoint) {
            $clientUuid = (string)$endpoint->client;
            $client = $model->getNodeByReference('clients.client.' . $clientUuid);
            $records[] = [
                'uuid' => $uuid,
                'client' => $client === null ? '' : (string)$client->name,
                'client_uuid' => $clientUuid,
                'client_name' => $client === null ? '' : (string)$client->name,
                'kind' => (string)$endpoint->kind,
                'value' => (string)$endpoint->value,
                'label' => (string)$endpoint->label,
            ];
        }
        $result = $this->searchRecordsetBase(
            $records,
            ['client_name', 'kind', 'value', 'label'],
            'client_name'
        );
        $result['revision'] = ((int) (string) $model->general->revision);
        return $result;
    }

    public function getEndpointAction($uuid = null)
    {
        $model = $this->getModel();
        if ($uuid === null) {
            $node = $model->endpoints->endpoint->Add();
        } elseif (!$this->isValidUUID($uuid) ||
            ($node = $model->getNodeByReference('endpoints.endpoint.' . $uuid)) === null) {
            return [];
        }
        $endpointData = $node->getNodes();
        $clientOptions = [];
        $currentClient = (string)$node->client;
        foreach ($model->clients->client->iterateItems() as $clientUuid => $client) {
            $clientOptions[$clientUuid] = [
                'value' => (string)$client->name,
                'selected' => $clientUuid === $currentClient ? 1 : 0,
            ];
        }
        $endpointData['client'] = $clientOptions;
        $result = [
            'endpoint' => $endpointData,
            'revision' => ((int) (string) $model->general->revision),
        ];
        if ($uuid !== null) {
            $result['endpoint']['uuid'] = $uuid;
        }
        return $result;
    }
    private function clientRecord($model, $uuid, $client, $runtime = [])
    {
        $policy = $model->getEffectivePolicy($uuid) ?? [];
        $endpoints = $model->getClientEndpoints($uuid);
        return [
            'uuid' => $uuid,
            'enabled' => ((string) $client->enabled === (string) '1') ? 1 : 0,
            'name' => (string)$client->name,
            'endpoints' => $endpoints,
            'endpoints_text' => implode(', ', array_column($endpoints, 'value')),
            'group_uuid' => (string)$client->group,
            'group_name' => $policy['group_name'] ?? '',
            'group' => $policy['group_name'] ?? '',
            'comment' => (string)$client->comment,
            'access' => $policy['access'] ?? '',
            'shaping_mode' => $policy['shaping_mode'] ?? '',
            'access_override' => (string)$client->access_override,
            'shaping_override' => (string)$client->shaping_override,
            'download_override' => ((int) (string) $client->download_override),
            'upload_override' => ((int) (string) $client->upload_override),
            'metric_override' => (string)$client->metric_override,
            'download' => $policy['download'] ?? 0,
            'upload' => $policy['upload'] ?? 0,
            'metric' => $policy['metric'] ?? '',
            'max_states' => $policy['max_states'] ?? 0,
            'state_count' => (int)($runtime['state_count'] ?? 0),
            'online' => !empty($runtime['online']),
            'sync_state' => $policy['sync_state'] ?? $model->getSyncState(),
            'effective_policy' => $policy,
        ];
    }

    private function runtimeClientStats($model)
    {
        $result = [];
        $clientIps = [];
        foreach ($model->clients->client->iterateItems() as $clientUuid => $client) {
            $result[$clientUuid] = ['online' => false, 'state_count' => 0];
            $clientIps[$clientUuid] = [];
        }
        try {
            $backend = new Backend();
            $neighbors = [];
            $macIps = [];
            foreach (['arp', 'ndp'] as $kind) {
                $rows = json_decode($backend->configdRun('interface list ' . $kind . ' json'), true);
                foreach (is_array($rows) ? $rows : [] as $row) {
                    if (!is_array($row)) {
                        continue;
                    }
                    $ip = $this->normalizeAddress((string)($row['ip'] ?? ''));
                    $mac = strtolower((string)($row['mac'] ?? ''));
                    if ($ip !== '') {
                        $neighbors[$ip] = true;
                    }
                    if ($ip !== '' && $mac !== '') {
                        $macIps[$mac][$ip] = true;
                    }
                }
            }

            foreach ($model->endpoints->endpoint->iterateItems() as $endpoint) {
                $clientUuid = (string)$endpoint->client;
                if (!isset($clientIps[$clientUuid])) {
                    continue;
                }
                if (((string) $endpoint->kind === (string) 'mac')) {
                    $resolved = $macIps[strtolower((string)$endpoint->value)] ?? [];
                    foreach (array_keys($resolved) as $ip) {
                        $clientIps[$clientUuid][$ip] = true;
                    }
                    if ($resolved !== []) {
                        $result[$clientUuid]['online'] = true;
                    }
                } else {
                    $ip = $this->normalizeAddress((string)$endpoint->value);
                    if ($ip !== '') {
                        $clientIps[$clientUuid][$ip] = true;
                        if (isset($neighbors[$ip])) {
                            $result[$clientUuid]['online'] = true;
                        }
                    }
                }
            }

            $clientsByIp = [];
            foreach ($clientIps as $clientUuid => $ips) {
                foreach (array_keys($ips) as $ip) {
                    $clientsByIp[$ip][$clientUuid] = true;
                }
            }
            $states = json_decode($backend->configdpRun('filter list states', ['', '10000', '0', '', '']), true);
            foreach (($states['details'] ?? []) as $state) {
                $matched = [];
                foreach (['src_addr', 'dst_addr', 'nat_addr'] as $field) {
                    $ip = $this->normalizeAddress((string)($state[$field] ?? ''));
                    foreach (array_keys($clientsByIp[$ip] ?? []) as $clientUuid) {
                        $matched[$clientUuid] = true;
                    }
                }
                foreach (array_keys($matched) as $clientUuid) {
                    $result[$clientUuid]['online'] = true;
                    ++$result[$clientUuid]['state_count'];
                }
            }
        } catch (\Throwable $error) {
            return $result;
        }
        return $result;
    }

    private function normalizeAddress($value)
    {
        $value = trim($value, "[] \t\n\r\0\x0B");
        $zone = strpos($value, '%');
        if ($zone !== false) {
            $value = substr($value, 0, $zone);
        }
        return filter_var($value, FILTER_VALIDATE_IP) === false ? '' : $value;
    }

    private function matchesFilter($actual, $filter)
    {
        if ($filter === null || $filter === '' || $filter === []) {
            return true;
        }
        return in_array((string)$actual, array_map('strval', (array)$filter), true);
    }

    private function clientFields($payload)
    {
        return array_intersect_key($payload, array_flip(self::CLIENT_FIELDS));
    }

    private function extractEndpoints(&$payload, $required = true)
    {
        $endpoints = $payload['endpoints'] ?? $this->request->getPost('endpoints');
        unset($payload['endpoints']);
        if ($endpoints === null && !$required) {
            return null;
        }
        if (!is_array($endpoints)) {
            throw new UserException(gettext('Endpoints must be a list.'), gettext('Client Control'));
        }
        return $endpoints;
    }

    private function requestedClientUuids($pathUuids = null)
    {
        $items = $pathUuids !== null ? explode(',', (string)$pathUuids) : $this->request->getPost('client_uuids');
        if (!is_array($items) || empty($items)) {
            throw new UserException(gettext('Select at least one client.'), gettext('Client Control'));
        }
        $result = [];
        foreach (array_unique($items) as $uuid) {
            if (!is_string($uuid) || !$this->isValidUUID($uuid)) {
                throw new UserException(gettext('Invalid client identifier.'), gettext('Client Control'));
            }
            $result[] = $uuid;
        }
        return $result;
    }

    private function syncEndpoints($model, $clientUuid, $records, $replace)
    {
        $existing = [];
        foreach ($model->endpoints->endpoint->iterateItems() as $uuid => $endpoint) {
            if (((string) $endpoint->client === (string) $clientUuid)) {
                $existing[$uuid] = $endpoint;
            }
        }
        $seen = [];
        foreach ($records as $record) {
            if (!is_array($record)) {
                throw new UserException(gettext('Every endpoint must be an object.'), gettext('Client Control'));
            }
            $uuid = $record['uuid'] ?? null;
            if ($uuid !== null && $uuid !== '') {
                if (!is_string($uuid) || !$this->isValidUUID($uuid) || !isset($existing[$uuid])) {
                    throw new UserException(gettext('An endpoint changed or belongs to another client.'), gettext('Client Control'));
                }
                $endpoint = $existing[$uuid];
                $endpoint->setNodes(array_intersect_key($record, array_flip(['kind', 'value', 'label'])));
                $seen[$uuid] = true;
            } else {
                $endpoint = $this->addEndpointNode($model, $clientUuid, $record);
                $seen[$endpoint->getAttribute('uuid')] = true;
            }
        }
        if ($replace) {
            foreach (array_keys($existing) as $uuid) {
                if (!isset($seen[$uuid])) {
                    $model->endpoints->endpoint->del($uuid);
                }
            }
        }
    }

    private function addEndpointNode($model, $clientUuid, $record)
    {
        $endpoint = $model->endpoints->endpoint->Add();
        $endpoint->client = $clientUuid;
        $endpoint->setNodes(array_intersect_key($record, array_flip(['kind', 'value', 'label'])));
        return $endpoint;
    }

    private function deleteClientEndpoints($model, $clientUuid)
    {
        $delete = [];
        foreach ($model->endpoints->endpoint->iterateItems() as $uuid => $endpoint) {
            if (((string) $endpoint->client === (string) $clientUuid)) {
                $delete[] = $uuid;
            }
        }
        foreach ($delete as $uuid) {
            $model->endpoints->endpoint->del($uuid);
        }
    }
}
