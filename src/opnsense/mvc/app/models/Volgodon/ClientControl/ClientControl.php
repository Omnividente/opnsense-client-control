<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class ClientControl extends BaseModel
{
    public function getClientEndpoints($clientUuid)
    {
        $result = [];
        foreach ($this->endpoints->endpoint->iterateItems() as $endpoint) {
            if (!((string) $endpoint->client === (string) $clientUuid)) {
                continue;
            }
            $result[] = [
                'uuid' => $endpoint->getAttribute('uuid'),
                'kind' => (string)$endpoint->kind,
                'value' => (string)$endpoint->value,
                'label' => (string)$endpoint->label,
            ];
        }
        usort($result, function ($left, $right) {
            return strnatcasecmp(
                $left['kind'] . "\n" . $left['value'] . "\n" . $left['uuid'],
                $right['kind'] . "\n" . $right['value'] . "\n" . $right['uuid']
            );
        });
        return $result;
    }

    public function getGroupMemberCount($groupUuid)
    {
        $count = 0;
        foreach ($this->clients->client->iterateItems() as $client) {
            if (((string) $client->group === (string) $groupUuid)) {
                $count++;
            }
        }
        return $count;
    }

    public function getEffectivePolicy($clientUuid)
    {
        $client = $this->getNodeByReference('clients.client.' . $clientUuid);
        if ($client === null) {
            return null;
        }
        $groupUuid = (string)$client->group;
        $group = $this->getNodeByReference('groups.group.' . $groupUuid);
        if ($group === null) {
            return null;
        }

        $enabled = ((string) $client->enabled === (string) '1') && ((string) $group->enabled === (string) '1');
        $access = ((string) $client->access_override === (string) 'inherit') ?
            (string)$group->access : (string)$client->access_override;
        $shapingMode = (string)$group->shaping_mode;
        $download = ((int) (string) $group->download);
        $upload = ((int) (string) $group->upload);
        $metric = (string)$group->metric;

        if (((string) $client->shaping_override === (string) 'unlimited')) {
            $shapingMode = 'unlimited';
            $download = 0;
            $upload = 0;
        } elseif (((string) $client->shaping_override === (string) 'limited')) {
            $shapingMode = 'per_client';
            $download = ((int) (string) $client->download_override);
            $upload = ((int) (string) $client->upload_override);
            $metric = (string)$client->metric_override;
        }

        return [
            'enabled' => $enabled,
            'group_uuid' => $groupUuid,
            'group_name' => (string)$group->name,
            'access' => $access,
            'shaping_mode' => $shapingMode,
            'download' => $download,
            'upload' => $upload,
            'metric' => $metric,
            'schedule' => (string)$group->schedule,
            'max_states' => ((int) (string) $group->max_states),
            'max_tcp_connections' => ((int) (string) $group->max_tcp_connections),
            'connection_rate' => ((int) (string) $group->connection_rate),
            'connection_rate_seconds' => ((int) (string) $group->connection_rate_seconds),
            'packet_rate' => ((int) (string) $group->packet_rate),
            'packet_rate_seconds' => ((int) (string) $group->packet_rate_seconds),
            'sync_state' => $this->getSyncState(),
        ];
    }

    public function getSyncState()
    {
        $lastStatus = (string)$this->general->last_apply_status;
        if (in_array($lastStatus, ['conflict', 'error'], true)) {
            return $lastStatus;
        }
        if (!((string) $this->general->revision === (string) (string)$this->general->last_applied_revision)) {
            return 'pending';
        }
        return $lastStatus === 'ok' ? 'in_sync' : 'never';
    }

    public function appendAudit($username, $operation, $summary, $result = 'ok')
    {
        $entry = $this->audit->entry->Add();
        $entry->timestamp = gmdate('c');
        $entry->username = (string)$username;
        $entry->operation = (string)$operation;
        $entry->summary = (string)$summary;
        $entry->result = $result === 'error' ? 'error' : 'ok';

        $uuids = [];
        foreach ($this->audit->entry->iterateItems() as $uuid => $unused) {
            $uuids[] = $uuid;
        }
        while (count($uuids) > 100) {
            $this->audit->entry->del(array_shift($uuids));
        }
    }

    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        if (((string) $this->general->destination_scope === (string) 'custom') && ((string) $this->general->destination_alias === '')) {
            $messages->appendMessage(new Message(
                gettext('A destination alias is required for custom destination scope.'),
                $this->general->destination_alias->__reference
            ));
        }

        $protectedInterfaces = Platform::listValues($this->general->protected_interfaces);
        $wanInterfaces = Platform::listValues($this->general->wan_interfaces);
        if (((string) $this->general->enabled === (string) '1') && empty($protectedInterfaces)) {
            $messages->appendMessage(new Message(
                gettext('Select at least one protected client interface.'),
                $this->general->protected_interfaces->__reference
            ));
        }
        if (count($wanInterfaces) > 2) {
            $messages->appendMessage(new Message(
                gettext('Traffic Shaper rules support at most two WAN interfaces.'),
                $this->general->wan_interfaces->__reference
            ));
        }

        $shapingEnabled = false;
        foreach ($this->groups->group->iterateItems() as $group) {
            if (((string) $group->enabled === (string) '1') && !((string) $group->shaping_mode === (string) 'unlimited')) {
                $shapingEnabled = true;
                break;
            }
        }
        if (!$shapingEnabled) {
            foreach ($this->clients->client->iterateItems() as $client) {
                if (((string) $client->enabled === (string) '1') && ((string) $client->shaping_override === (string) 'limited')) {
                    $shapingEnabled = true;
                    break;
                }
            }
        }
        if (((string) $this->general->enabled === (string) '1') &&
            ((string) $this->general->enforcement_mode === (string) 'enforce') &&
            $shapingEnabled && empty($wanInterfaces)) {
            $messages->appendMessage(new Message(
                gettext('Select at least one WAN interface when shaping is enabled.'),
                $this->general->wan_interfaces->__reference
            ));
        }

        foreach ($this->groups->group->iterateItems() as $group) {
            if (!((string) $group->shaping_mode === (string) 'unlimited') &&
                (((int) (string) $group->download) === 0 || ((int) (string) $group->upload) === 0)) {
                $message = gettext('Limited groups require non-zero download and upload rates.');
                $messages->appendMessage(new Message($message, $group->download->__reference));
                $messages->appendMessage(new Message($message, $group->upload->__reference));
            }
            if ((((int) (string) $group->connection_rate) === 0) !== (((int) (string) $group->connection_rate_seconds) === 0)) {
                $message = gettext('Connection rate and interval must be configured together.');
                $messages->appendMessage(new Message($message, $group->connection_rate->__reference));
                $messages->appendMessage(new Message($message, $group->connection_rate_seconds->__reference));
            }
            if ((((int) (string) $group->packet_rate) === 0) !== (((int) (string) $group->packet_rate_seconds) === 0)) {
                $message = gettext('Packet rate and interval must be configured together.');
                $messages->appendMessage(new Message($message, $group->packet_rate->__reference));
                $messages->appendMessage(new Message($message, $group->packet_rate_seconds->__reference));
            }
            if (((int) (string) $group->packet_rate) > 0 && !Platform::supportsPacketRate()) {
                $messages->appendMessage(new Message(
                    gettext('Packet-rate limiting is not supported by this firewall runtime.'),
                    $group->packet_rate->__reference
                ));
            }
        }

        $clients = [];
        $endpointCounts = [];
        foreach ($this->clients->client->iterateItems() as $uuid => $client) {
            $clients[$uuid] = $client;
            $endpointCounts[$uuid] = 0;
            $groupUuid = (string)$client->group;
            $group = $groupUuid === '' ? null : $this->getNodeByReference('groups.group.' . $groupUuid);
            if (($groupUuid !== '' && $group === null) ||
                (((string) $client->enabled === (string) '1') && $group === null)) {
                $messages->appendMessage(new Message(
                    gettext('The group must exist, and an enabled client requires one.'),
                    $client->group->__reference
                ));
            }
            if (((string) $client->shaping_override === (string) 'limited') &&
                (((int) (string) $client->download_override) === 0 || ((int) (string) $client->upload_override) === 0)) {
                $message = gettext('A limited client override requires non-zero download and upload rates.');
                $messages->appendMessage(new Message($message, $client->download_override->__reference));
                $messages->appendMessage(new Message($message, $client->upload_override->__reference));
            }
        }

        $endpointOwners = [];
        foreach ($this->endpoints->endpoint->iterateItems() as $endpoint) {
            $clientUuid = (string)$endpoint->client;
            if (!isset($clients[$clientUuid])) {
                $messages->appendMessage(new Message(
                    gettext('The endpoint owner client does not exist.'),
                    $endpoint->client->__reference
                ));
                continue;
            }
            $endpointCounts[$clientUuid]++;
            $key = (string)$endpoint->kind . ':' . strtolower((string)$endpoint->value);
            if (isset($endpointOwners[$key])) {
                $messages->appendMessage(new Message(
                    gettext('This endpoint is already assigned to another client.'),
                    $endpoint->value->__reference
                ));
                $messages->appendMessage(new Message(
                    gettext('This endpoint is already assigned to another client.'),
                    $endpointOwners[$key]
                ));
            } else {
                $endpointOwners[$key] = $endpoint->value->__reference;
            }
        }

        foreach ($clients as $uuid => $client) {
            if (((string) $client->enabled === (string) '1') && $endpointCounts[$uuid] === 0) {
                $messages->appendMessage(new Message(
                    gettext('An enabled client requires at least one endpoint.'),
                    $client->name->__reference
                ));
            }
        }

        return $messages;
    }
}
