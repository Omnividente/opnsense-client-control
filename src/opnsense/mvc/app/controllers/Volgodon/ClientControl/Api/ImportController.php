<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\Api;

use OPNsense\Base\UserException;
use OPNsense\Firewall\Alias;
use Volgodon\ClientControl\Canonical;

class ImportController extends ClientControlControllerBase
{
    protected static $internalModelName = 'import';

    public function scanAction()
    {
        $aliases = $this->aliasMap();
        $records = [];
        foreach ($aliases as $alias) {
            if (!in_array($alias['type'], ['host', 'network', 'mac', 'networkgroup'], true)) {
                continue;
            }
            $importable = $alias['type'] !== 'network';
            $records[] = [
                'uuid' => $alias['uuid'],
                'name' => $alias['name'],
                'type' => $alias['type'],
                'proto' => $alias['proto'],
                'description' => $alias['description'],
                'items' => $alias['items'],
                'item_count' => count($alias['items']),
                'candidate' => $alias['type'] === 'networkgroup' ? 'group' :
                    ($importable ? 'client' : 'unsupported'),
                'importable' => $importable,
                'reason' => $importable ? '' :
                    gettext('Network aliases contain subnets, but client endpoints require individual IP addresses.'),
                'recommended' => false,
            ];
        }
        return $this->searchRecordsetBase(
            $records,
            ['name', 'type', 'proto', 'description', 'items', 'reason'],
            'name'
        );
    }

    public function previewAction()
    {
        $aliases = $this->aliasMap();
        $selected = $this->selectedAliasNames($aliases);
        return $this->buildPreview(
            $aliases,
            $selected,
            $this->getModel(),
            $this->requestedReuseExistingGroups()
        );
    }

    public function applyAction()
    {
        $this->requirePost();
        $model = $this->lockModel();
        try {
            $this->assertRevision($model);
            $aliases = $this->aliasMap();
            $selected = $this->selectedAliasNames($aliases);
            $reuseExistingGroups = $this->requestedReuseExistingGroups();
            $preview = $this->buildPreview($aliases, $selected, $model, $reuseExistingGroups);
            $offeredHash = (string)$this->request->getPost('preview_hash');
            if ($offeredHash === '' || !hash_equals($preview['preview_hash'], $offeredHash)) {
                throw new UserException(
                    gettext('The aliases or import selection changed. Review the current preview.'),
                    gettext('Client Control')
                );
            }
            if (empty($preview['can_apply'])) {
                throw new UserException(
                    implode("\n", $preview['errors'] ?: [gettext('No valid aliases remain to import.')]),
                    gettext('Alias import')
                );
            }

            $groupMapping = [];
            $groupsAdded = 0;
            foreach ($preview['groups'] as $proposal) {
                if (!empty($proposal['existing_uuid'])) {
                    $groupMapping[$proposal['source_alias']] = $proposal['existing_uuid'];
                    continue;
                }
                $group = $model->groups->group->Add();
                $group->enabled = '0';
                $group->name = $proposal['name'];
                $group->description = $proposal['description'];
                $group->access = 'allow';
                $group->shaping_mode = 'unlimited';
                $groupMapping[$proposal['source_alias']] = $group->getAttribute('uuid');
                $groupsAdded++;
            }

            $clientsAdded = 0;
            $endpointsAdded = 0;
            foreach ($preview['clients'] as $proposal) {
                $groupUuid = $groupMapping[$proposal['group_source_alias']] ?? '';
                if ($groupUuid === '') {
                    throw new UserException(gettext('Unable to resolve an imported client group.'), gettext('Alias import'));
                }
                $client = $model->clients->client->Add();
                $client->enabled = '0';
                $client->name = $proposal['name'];
                $client->group = $groupUuid;
                $client->comment = $proposal['comment'];
                $clientUuid = $client->getAttribute('uuid');
                foreach ($proposal['endpoints'] as $endpointProposal) {
                    $endpoint = $model->endpoints->endpoint->Add();
                    $endpoint->client = $clientUuid;
                    $endpoint->kind = $endpointProposal['kind'];
                    $endpoint->value = $endpointProposal['value'];
                    $endpoint->label = $endpointProposal['label'];
                    $endpointsAdded++;
                }
                $clientsAdded++;
            }

            return $this->finishMutation(
                $model,
                'import.apply',
                sprintf(
                    'imported aliases without modifying source objects: groups=%d clients=%d endpoints=%d',
                    $groupsAdded,
                    $clientsAdded,
                    $endpointsAdded
                ),
                [
                    'groups_added' => $groupsAdded,
                    'clients_added' => $clientsAdded,
                    'endpoints_added' => $endpointsAdded,
                ]
            );
        } finally {
            $this->unlockModel();
        }
    }

    private function aliasMap()
    {
        $result = [];
        $model = new Alias();
        foreach ($model->aliases->alias->iterateItems() as $uuid => $alias) {
            $name = (string)$alias->name;
            if ($name === '' || str_starts_with($name, 'CC_') ||
                str_starts_with((string)$alias->description, 'ClientControl ')) {
                continue;
            }
            $items = array_values(array_filter(
                array_map('trim', explode("\n", (string)$alias->content)),
                'strlen'
            ));
            $result[$name] = [
                'uuid' => $uuid,
                'name' => $name,
                'type' => (string)$alias->type,
                'proto' => (string)$alias->proto,
                'description' => (string)$alias->description,
                'items' => $items,
            ];
        }
        ksort($result, SORT_NATURAL | SORT_FLAG_CASE);
        return $result;
    }

    private function selectedAliasNames($aliases)
    {
        $selected = $this->request->getPost('alias_names');
        if (!is_array($selected) || empty($selected)) {
            throw new UserException(gettext('Select at least one importable alias.'), gettext('Alias import'));
        }
        $result = [];
        foreach (array_unique($selected) as $name) {
            if (!is_string($name) || !isset($aliases[$name])) {
                throw new UserException(
                    sprintf(gettext('Alias %s does not exist or is not importable.'), (string)$name),
                    gettext('Alias import')
                );
            }
            if ($aliases[$name]['type'] === 'network') {
                throw new UserException(
                    sprintf(gettext('Network alias %s cannot be imported as a client endpoint.'), $name),
                    gettext('Alias import')
                );
            }
            $result[] = $name;
        }
        sort($result, SORT_NATURAL | SORT_FLAG_CASE);
        return $result;
    }

    private function requestedReuseExistingGroups()
    {
        return (string)$this->request->getPost('reuse_existing_groups') === '1';
    }

    private function buildPreview($aliases, $selected, $module, $reuseExistingGroups = false)
    {
        $warnings = [];
        $errors = [];
        $groupProposals = [];
        $clientGroup = [];
        $selectedLeaves = [];

        foreach ($selected as $name) {
            $alias = $aliases[$name];
            if ($alias['type'] !== 'networkgroup') {
                $selectedLeaves[$name] = true;
                continue;
            }
            $groupWarnings = [];
            $groupErrors = [];
            $members = $this->resolveGroupMembers(
                $name,
                $aliases,
                [],
                $groupWarnings,
                $groupErrors
            );
            $warnings = array_merge($warnings, $groupWarnings);
            if ($groupErrors !== []) {
                $errors = array_merge($errors, $groupErrors);
                continue;
            }
            $conflict = false;
            foreach ($members as $member) {
                if (isset($clientGroup[$member]) && $clientGroup[$member] !== $name) {
                    $errors[] = sprintf(
                        gettext('Alias %s belongs to more than one selected policy group (%s, %s).'),
                        $member,
                        $clientGroup[$member],
                        $name
                    );
                    $conflict = true;
                }
            }
            if ($conflict) {
                continue;
            }
            foreach ($members as $member) {
                $clientGroup[$member] = $name;
                $selectedLeaves[$member] = true;
            }
            $groupProposals[$name] = [
                'source_alias' => $name,
                'source_uuid' => $alias['uuid'],
                'name' => $name,
                'description' => $alias['description'] !== '' ?
                    $alias['description'] : sprintf(gettext('Imported from alias %s'), $name),
                'members' => $members,
                'existing_uuid' => '',
                'reuse_existing' => false,
            ];
        }

        $ungrouped = array_values(array_diff(array_keys($selectedLeaves), array_keys($clientGroup)));
        if ($ungrouped !== []) {
            $groupName = 'Imported';
            $proposalNames = array_map(
                fn($proposal) => strtolower($proposal['name']),
                array_values($groupProposals)
            );
            if (in_array(strtolower($groupName), $proposalNames, true)) {
                $groupName = 'Imported standalone';
            }
            $groupProposals['__standalone__'] = [
                'source_alias' => '__standalone__',
                'source_uuid' => '',
                'name' => $groupName,
                'description' => gettext('Imported standalone aliases'),
                'members' => $ungrouped,
                'existing_uuid' => '',
                'reuse_existing' => false,
            ];
            foreach ($ungrouped as $member) {
                $clientGroup[$member] = '__standalone__';
            }
        }

        $existingGroups = [];
        foreach ($module->groups->group->iterateItems() as $uuid => $group) {
            $existingGroups[strtolower((string)$group->name)] = $uuid;
        }
        $blockedGroups = [];
        foreach ($groupProposals as $key => &$group) {
            $existingUuid = $existingGroups[strtolower($group['name'])] ?? '';
            if ($existingUuid === '') {
                continue;
            }
            if (!$reuseExistingGroups) {
                $blockedGroups[$key] = true;
                $errors[] = sprintf(
                    gettext('Group %s already exists; explicitly allow reuse or rename it before import.'),
                    $group['name']
                );
                continue;
            }
            $group['existing_uuid'] = $existingUuid;
            $group['reuse_existing'] = true;
            $warnings[] = sprintf(
                gettext('Existing group %s will be reused without changing its policy.'),
                $group['name']
            );
        }
        unset($group);

        $existingClients = [];
        foreach ($module->clients->client->iterateItems() as $client) {
            $existingClients[strtolower((string)$client->name)] = true;
        }
        $clients = [];
        $endpointOwners = [];
        foreach ($module->endpoints->endpoint->iterateItems() as $endpoint) {
            $clientUuid = (string)$endpoint->client;
            $client = $module->getNodeByReference('clients.client.' . $clientUuid);
            $owner = $client === null ? $clientUuid : (string)$client->name;
            $key = (string)$endpoint->kind . ':' . strtolower((string)$endpoint->value);
            $endpointOwners[$key] = $owner;
        }
        foreach (array_keys($selectedLeaves) as $name) {
            $groupSource = $clientGroup[$name] ?? '';
            if ($groupSource === '' || isset($blockedGroups[$groupSource])) {
                $errors[] = sprintf(gettext('Client %s was skipped because its target group is unavailable.'), $name);
                continue;
            }
            if (isset($existingClients[strtolower($name)])) {
                $errors[] = sprintf(gettext('Client %s already exists in Client Control.'), $name);
                continue;
            }
            $clientWarnings = [];
            $clientErrors = [];
            $endpoints = $this->resolveEndpoints(
                $name,
                $aliases,
                [],
                $clientWarnings,
                $clientErrors
            );
            if ($endpoints === []) {
                $clientErrors[] = sprintf(gettext('Alias %s contains no importable IP or MAC endpoints.'), $name);
            }
            foreach ($endpoints as $endpoint) {
                $key = $endpoint['kind'] . ':' . strtolower($endpoint['value']);
                if (isset($endpointOwners[$key]) && $endpointOwners[$key] !== $name) {
                    $clientErrors[] = sprintf(
                        gettext('Endpoint %s occurs in both %s and %s.'),
                        $endpoint['value'],
                        $endpointOwners[$key],
                        $name
                    );
                }
            }
            $warnings = array_merge($warnings, $clientWarnings);
            if ($clientErrors !== []) {
                $errors = array_merge($errors, $clientErrors);
                continue;
            }
            foreach ($endpoints as $endpoint) {
                $key = $endpoint['kind'] . ':' . strtolower($endpoint['value']);
                $endpointOwners[$key] = $name;
            }
            $source = $aliases[$name];
            $clients[] = [
                'source_alias' => $name,
                'source_uuid' => $source['uuid'],
                'name' => $name,
                'comment' => $source['description'] !== '' ?
                    $source['description'] : sprintf(gettext('Imported from alias %s'), $name),
                'group_source_alias' => $groupSource,
                'endpoints' => $endpoints,
                'enabled' => false,
            ];
        }

        $usedGroups = array_fill_keys(array_column($clients, 'group_source_alias'), true);
        $groupProposals = array_filter(
            $groupProposals,
            fn($proposal) => isset($usedGroups[$proposal['source_alias']])
        );
        ksort($groupProposals, SORT_NATURAL | SORT_FLAG_CASE);
        usort($clients, fn($left, $right) => strnatcasecmp($left['name'], $right['name']));
        $preview = [
            'selected_aliases' => array_values($selected),
            'reuse_existing_groups' => $reuseExistingGroups,
            'groups' => array_values($groupProposals),
            'clients' => $clients,
            'warnings' => array_values(array_unique($warnings)),
            'errors' => array_values(array_unique($errors)),
            'can_apply' => $clients !== [],
            'partial' => $clients !== [] && $errors !== [],
        ];
        $preview['preview_hash'] = Canonical::fingerprint($preview);
        $preview['revision'] = (int)(string)$module->general->revision;
        return $preview;
    }

    private function resolveGroupMembers($name, $aliases, $stack, &$warnings, &$errors)
    {
        if (isset($stack[$name])) {
            $errors[] = sprintf(gettext('Alias cycle detected at %s.'), $name);
            return [];
        }
        $stack[$name] = true;
        $result = [];
        foreach ($aliases[$name]['items'] as $item) {
            $item = ltrim($item, '!');
            if (!isset($aliases[$item])) {
                $warnings[] = sprintf(gettext('Group alias %s references unsupported item %s.'), $name, $item);
                continue;
            }
            if ($aliases[$item]['type'] === 'networkgroup') {
                $result = array_merge(
                    $result,
                    $this->resolveGroupMembers($item, $aliases, $stack, $warnings, $errors)
                );
            } else {
                $result[] = $item;
            }
        }
        $result = array_values(array_unique($result));
        sort($result, SORT_NATURAL | SORT_FLAG_CASE);
        return $result;
    }

    private function resolveEndpoints($name, $aliases, $stack, &$warnings, &$errors)
    {
        if (isset($stack[$name])) {
            $errors[] = sprintf(gettext('Alias cycle detected at %s.'), $name);
            return [];
        }
        $stack[$name] = true;
        $alias = $aliases[$name];
        $result = [];
        foreach ($alias['items'] as $item) {
            $item = trim($item);
            if (isset($aliases[$item]) && $aliases[$item]['type'] !== 'networkgroup') {
                $result = array_merge(
                    $result,
                    $this->resolveEndpoints($item, $aliases, $stack, $warnings, $errors)
                );
                continue;
            }
            $mac = strtolower(str_replace('-', ':', $item));
            if ($alias['type'] === 'mac' && filter_var($mac, FILTER_VALIDATE_MAC) !== false) {
                $result[] = ['kind' => 'mac', 'value' => $mac, 'label' => $name];
            } elseif (filter_var($item, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                $result[] = ['kind' => 'ipv4', 'value' => $item, 'label' => $name];
            } elseif (filter_var($item, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                $result[] = ['kind' => 'ipv6', 'value' => strtolower($item), 'label' => $name];
            } else {
                $warnings[] = sprintf(
                    gettext('Alias %s item %s is not an IP or MAC endpoint and will be skipped.'),
                    $name,
                    $item
                );
            }
        }
        $unique = [];
        foreach ($result as $endpoint) {
            $unique[$endpoint['kind'] . ':' . strtolower($endpoint['value'])] = $endpoint;
        }
        ksort($unique, SORT_STRING);
        return array_values($unique);
    }
}
