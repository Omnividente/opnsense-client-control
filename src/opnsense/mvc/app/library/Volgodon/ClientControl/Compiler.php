<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

use InvalidArgumentException;

class Compiler
{
    public const ORIGIN = 'ClientControl';
    public const CATEGORY = 'ClientControl';
    private const SHAPER_RULE_WARNING_THRESHOLD = 64;

    public function compile($model, array $resolvedMacs = [])
    {
        return $this->compileState($this->modelState($model, $resolvedMacs));
    }

    public function compileState(array $state)
    {
        $warnings = $this->validateStateShape($state);
        $warnings = array_merge($warnings, $this->unsupportedPlatformWarnings($state));
        $configurationState = $state;
        $notices = $this->degradeUnavailableSchedules($state);
        $desired = [
            'categories' => [],
            'aliases' => [],
            'filter_rules' => [],
            'preview_filter_rules' => [],
            'pipes' => [],
            'shaper_rules' => [],
            'warnings' => $warnings,
            'notices' => $notices,
        ];
        $clients = $state['clients'];
        $groups = $state['groups'];
        $general = $state['general'];

        $desired['categories']['system:category'] = $this->desiredObject(
            'system',
            'category',
            'category',
            self::CATEGORY,
            ['name' => self::CATEGORY, 'auto' => '0', 'color' => '4a90e2']
        );

        $endpointAliases = [];
        $clientShaperAddresses = [];
        foreach ($clients as $clientUuid => $client) {
            $byKind = ['ipv4' => [], 'ipv6' => [], 'mac' => []];
            foreach ($client['endpoints'] as $endpoint) {
                $byKind[$endpoint['kind']][] = $endpoint['value'];
                if ($endpoint['kind'] === 'mac') {
                    foreach ($endpoint['resolved_ips'] ?? [] as $address) {
                        if (filter_var($address, FILTER_VALIDATE_IP) !== false) {
                            $clientShaperAddresses[$clientUuid][] = $address;
                        }
                    }
                } else {
                    $clientShaperAddresses[$clientUuid][] = $endpoint['value'];
                }
            }
            foreach ($byKind as &$values) {
                $values = array_values(array_unique($values));
                natcasesort($values);
                $values = array_values($values);
            }
            unset($values);
            $clientShaperAddresses[$clientUuid] = $this->sortedUnique($clientShaperAddresses[$clientUuid] ?? []);

            if (!empty($byKind['ipv4']) || !empty($byKind['ipv6'])) {
                $name = 'CC_C_' . $this->token($clientUuid) . '_IP';
                $proto = [];
                if (!empty($byKind['ipv4'])) {
                    $proto[] = 'IPv4';
                }
                if (!empty($byKind['ipv6'])) {
                    $proto[] = 'IPv6';
                }
                $desired['aliases']['client:' . $clientUuid . ':ip'] = $this->desiredObject(
                    'client',
                    $clientUuid,
                    'alias',
                    $name,
                    [
                        'enabled' => '1',
                        'name' => $name,
                        'type' => 'host',
                        'proto' => implode(',', $proto),
                        'content' => implode("\n", array_merge($byKind['ipv4'], $byKind['ipv6'])),
                        'categories' => self::CATEGORY,
                        'description' => sprintf('ClientControl client=%s endpoints=ip', $clientUuid),
                    ]
                );
                $endpointAliases[$clientUuid]['ip'] = $name;
            }
            if (!empty($byKind['mac'])) {
                $name = 'CC_C_' . $this->token($clientUuid) . '_MAC';
                $desired['aliases']['client:' . $clientUuid . ':mac'] = $this->desiredObject(
                    'client',
                    $clientUuid,
                    'alias',
                    $name,
                    [
                        'enabled' => '1',
                        'name' => $name,
                        'type' => 'mac',
                        'proto' => '',
                        'content' => implode("\n", $byKind['mac']),
                        'categories' => self::CATEGORY,
                        'description' => sprintf('ClientControl client=%s endpoints=mac', $clientUuid),
                    ]
                );
                $endpointAliases[$clientUuid]['mac'] = $name;
            }
        }

        $groupAccessAliases = [];
        $groupShaperAddresses = [];
        foreach ($groups as $groupUuid => $group) {
            $accessMembers = [];
            $shaperAddresses = [];
            foreach ($clients as $clientUuid => $client) {
                if ($client['group'] !== $groupUuid || !$this->effectiveEnabled($client, $group)) {
                    continue;
                }
                $effectiveAccess = $client['access_override'] === 'inherit' ?
                    $group['access'] : $client['access_override'];
                if ($effectiveAccess !== 'allow') {
                    continue;
                }
                foreach ($endpointAliases[$clientUuid] ?? [] as $aliasName) {
                    $accessMembers[] = $aliasName;
                }
                if ($client['shaping_override'] === 'inherit') {
                    foreach ($clientShaperAddresses[$clientUuid] ?? [] as $address) {
                        $shaperAddresses[] = $address;
                    }
                }
            }
            $accessMembers = $this->sortedUnique($accessMembers);
            $groupShaperAddresses[$groupUuid] = $this->sortedUnique($shaperAddresses);

            $groupName = 'CC_G_' . $this->token($groupUuid);
            $desired['aliases']['group:' . $groupUuid . ':access'] = $this->desiredObject(
                'group',
                $groupUuid,
                'alias',
                $groupName,
                [
                    'enabled' => '1',
                    'name' => $groupName,
                    'type' => 'networkgroup',
                    'proto' => '',
                    'content' => implode("\n", $accessMembers),
                    'categories' => self::CATEGORY,
                    'description' => sprintf('ClientControl group=%s purpose=access', $groupUuid),
                ]
            );
            $groupAccessAliases[$groupUuid] = $groupName;

        }

        $allowedGroups = [];
        foreach ($groupAccessAliases as $groupUuid => $aliasName) {
            $content = $desired['aliases']['group:' . $groupUuid . ':access']['fields']['content'];
            if ($content !== '') {
                $allowedGroups[] = $aliasName;
            }
        }
        $desired['aliases']['system:allowed'] = $this->desiredObject(
            'system',
            'allowed',
            'alias',
            'CC_ALLOWED',
            [
                'enabled' => '1',
                'name' => 'CC_ALLOWED',
                'type' => 'networkgroup',
                'proto' => '',
                'content' => implode("\n", $this->sortedUnique($allowedGroups)),
                'categories' => self::CATEGORY,
                'description' => 'ClientControl system=allowed',
            ]
        );

        if ($general['destination_scope'] === 'wan') {
            $desired['aliases']['system:private'] = $this->desiredObject(
                'system',
                'private',
                'alias',
                'CC_PRIVATE',
                [
                    'enabled' => '1',
                    'name' => 'CC_PRIVATE',
                    'type' => 'network',
                    'proto' => 'IPv4,IPv6',
                    'content' => implode("\n", [
                        '0.0.0.0/8',
                        '10.0.0.0/8',
                        '100.64.0.0/10',
                        '127.0.0.0/8',
                        '169.254.0.0/16',
                        '172.16.0.0/12',
                        '192.168.0.0/16',
                        '224.0.0.0/4',
                        '255.255.255.255/32',
                        '::1/128',
                        'fc00::/7',
                        'fe80::/10',
                        'ff00::/8',
                    ]),
                    'categories' => self::CATEGORY,
                    'description' => 'ClientControl system=private-destinations',
                ]
            );
        }

        $previewRules = $this->compileFilterRules($general, $groups, $groupAccessAliases);
        $desired['preview_filter_rules'] = $previewRules;
        if ($general['enabled'] && $general['enforcement_mode'] === 'enforce') {
            $desired['filter_rules'] = $previewRules;
        }

        if ($general['enabled'] && $general['enforcement_mode'] === 'enforce') {
            $this->compileShaper(
                $desired,
                $general,
                $groups,
                $clients,
                $groupShaperAddresses,
                $clientShaperAddresses
            );
        }

        foreach (['categories', 'aliases', 'filter_rules', 'preview_filter_rules', 'pipes', 'shaper_rules'] as $section) {
            ksort($desired[$section], SORT_STRING);
        }
        foreach ($configurationState['groups'] as &$group) {
            unset($group['schedule_exists']);
        }
        unset($group);
        foreach ($configurationState['clients'] as &$client) {
            foreach ($client['endpoints'] as &$endpoint) {
                unset($endpoint['resolved_ips']);
            }
            unset($endpoint);
        }
        unset($client);
        $desired['fingerprint'] = Canonical::fingerprint($configurationState);
        $desired['runtime_fingerprint'] = Canonical::fingerprint([
            'categories' => $desired['categories'],
            'aliases' => $desired['aliases'],
            'filter_rules' => $desired['filter_rules'],
            'pipes' => $desired['pipes'],
            'shaper_rules' => $desired['shaper_rules'],
        ]);
        $desired['forecast'] = [
            'filter_rules' => count($desired['filter_rules']),
            'shaper_rules' => count($desired['shaper_rules']),
            'managed_objects' => count($desired['categories']) + count($desired['aliases']) +
                count($desired['filter_rules']) + count($desired['pipes']) + count($desired['shaper_rules']),
        ];
        if ($desired['forecast']['shaper_rules'] > self::SHAPER_RULE_WARNING_THRESHOLD) {
            $desired['notices'][] = [
                'reason' => 'high_shaper_rule_count',
                'message' => sprintf(
                    gettext('This plan creates %d Traffic Shaper rules; review interface and policy combinations.'),
                    $desired['forecast']['shaper_rules']
                ),
            ];
        }
        return $desired;
    }

    public function modelState($model, array $resolvedMacs = [])
    {
        $state = [
            'general' => [
                'enabled' => ((string) $model->general->enabled === (string) '1'),
                'protected_interfaces' => Platform::listValues($model->general->protected_interfaces),
                'wan_interfaces' => Platform::listValues($model->general->wan_interfaces),
                'enforcement_mode' => (string)$model->general->enforcement_mode,
                'destination_scope' => (string)$model->general->destination_scope,
                'destination_alias' => (string)$model->general->destination_alias,
            ],
            'groups' => [],
            'clients' => [],
        ];
        $scheduleEvaluator = new ScheduleEvaluator();
        foreach ($model->groups->group->iterateItems() as $uuid => $group) {
            $state['groups'][$uuid] = [
                'enabled' => ((string) $group->enabled === (string) '1'),
                'name' => (string)$group->name,
                'access' => (string)$group->access,
                'shaping_mode' => (string)$group->shaping_mode,
                'download' => ((int) (string) $group->download),
                'upload' => ((int) (string) $group->upload),
                'metric' => (string)$group->metric,
                'schedule' => (string)$group->schedule,
                'schedule_exists' => $scheduleEvaluator->exists((string)$group->schedule),
                'max_states' => ((int) (string) $group->max_states),
                'max_tcp_connections' => ((int) (string) $group->max_tcp_connections),
                'connection_rate' => ((int) (string) $group->connection_rate),
                'connection_rate_seconds' => ((int) (string) $group->connection_rate_seconds),
                'packet_rate' => ((int) (string) $group->packet_rate),
                'packet_rate_seconds' => ((int) (string) $group->packet_rate_seconds),
            ];
        }
        foreach ($model->clients->client->iterateItems() as $uuid => $client) {
            $endpoints = $model->getClientEndpoints($uuid);
            foreach ($endpoints as &$endpoint) {
                $endpoint['resolved_ips'] = $endpoint['kind'] === 'mac' ?
                    array_values($resolvedMacs[strtolower($endpoint['value'])] ?? []) : [];
            }
            unset($endpoint);
            $state['clients'][$uuid] = [
                'enabled' => ((string) $client->enabled === (string) '1'),
                'name' => (string)$client->name,
                'group' => (string)$client->group,
                'access_override' => (string)$client->access_override,
                'shaping_override' => (string)$client->shaping_override,
                'download_override' => ((int) (string) $client->download_override),
                'upload_override' => ((int) (string) $client->upload_override),
                'metric_override' => (string)$client->metric_override,
                'endpoints' => $endpoints,
            ];
        }
        return $state;
    }

    private function compileFilterRules($general, $groups, $groupAliases)
    {
        $rules = [];
        $destination = $this->destination($general);
        $interfaces = implode(',', $this->sortedUnique($general['protected_interfaces']));
        $base = [
            'enabled' => '1',
            'statetype' => 'keep',
            'action' => 'pass',
            'quick' => '1',
            'interface' => $interfaces,
            'direction' => 'in',
            'ipprotocol' => 'inet46',
            'protocol' => 'any',
            'source_net' => 'any',
            'source_not' => '0',
            'destination_net' => $destination['net'],
            'destination_not' => $destination['not'],
            'log' => '0',
            'categories' => self::CATEGORY,
        ];

        $fields = $base;
        $fields['destination_net'] = '(self)';
        $fields['destination_not'] = '0';
        $fields['description'] = 'ClientControl system=self-pass';
        $rules['system:self-pass'] = $this->desiredObject(
            'system',
            'self-pass',
            'filter_rule',
            'CC_SELF_PASS',
            $fields,
            10
        );

        $fields = $base;
        $fields['ipprotocol'] = 'inet';
        $fields['protocol'] = 'UDP';
        $fields['source_port'] = '68';
        $fields['destination_net'] = 'any';
        $fields['destination_not'] = '0';
        $fields['destination_port'] = '67';
        $fields['description'] = 'ClientControl system=dhcp4-pass';
        $rules['system:dhcp4-pass'] = $this->desiredObject(
            'system',
            'dhcp4-pass',
            'filter_rule',
            'CC_DHCP4_PASS',
            $fields,
            20
        );

        $fields = $base;
        $fields['ipprotocol'] = 'inet6';
        $fields['protocol'] = 'UDP';
        $fields['source_port'] = '546';
        $fields['destination_net'] = 'any';
        $fields['destination_not'] = '0';
        $fields['destination_port'] = '547';
        $fields['description'] = 'ClientControl system=dhcp6-pass';
        $rules['system:dhcp6-pass'] = $this->desiredObject(
            'system',
            'dhcp6-pass',
            'filter_rule',
            'CC_DHCP6_PASS',
            $fields,
            21
        );

        $fields = $base;
        $fields['ipprotocol'] = 'inet6';
        $fields['protocol'] = 'IPV6-ICMP';
        $fields['icmp6type'] = '1,2,3,4,130,131,132,133,134,135,136,137';
        $fields['destination_net'] = 'any';
        $fields['destination_not'] = '0';
        $fields['description'] = 'ClientControl system=ipv6-control-pass';
        $rules['system:ipv6-control-pass'] = $this->desiredObject(
            'system',
            'ipv6-control-pass',
            'filter_rule',
            'CC_IPV6_CONTROL_PASS',
            $fields,
            22
        );

        $order = 100;
        foreach ($groups as $groupUuid => $group) {
            if (!$group['enabled']) {
                continue;
            }
            $fields = $base;
            $fields['source_net'] = $groupAliases[$groupUuid];
            $fields['sched'] = $group['schedule'];
            if ($group['packet_rate'] > 0 && Platform::supportsPacketRate()) {
                $fields['max-pkt-rate-number'] = $this->optionalInt($group['packet_rate']);
                $fields['max-pkt-rate-seconds'] = $this->optionalInt($group['packet_rate_seconds']);
            }
            $fields['max-src-states'] = $this->optionalInt($group['max_states']);
            $packetRate = $group['packet_rate'] > 0 ?
                sprintf(' packet_rate=%d/%d', $group['packet_rate'], $group['packet_rate_seconds']) : '';
            $fields['description'] = sprintf('ClientControl group=%s access=allow%s', $groupUuid, $packetRate);

            if ($group['max_tcp_connections'] > 0 || $group['connection_rate'] > 0) {
                $tcp = $fields;
                $tcp['protocol'] = 'TCP';
                $tcp['max-src-conn'] = $this->optionalInt($group['max_tcp_connections']);
                $tcp['max-src-conn-rate'] = $this->optionalInt($group['connection_rate']);
                $tcp['max-src-conn-rates'] = $this->optionalInt($group['connection_rate_seconds']);
                $tcp['description'] = sprintf('ClientControl group=%s access=tcp%s', $groupUuid, $packetRate);
                $rules['group:' . $groupUuid . ':tcp'] = $this->desiredObject(
                    'group',
                    $groupUuid,
                    'filter_rule',
                    'CC_FR_' . $this->token($groupUuid) . '_TCP',
                    $tcp,
                    $order++
                );
            }
            $rules['group:' . $groupUuid . ':pass'] = $this->desiredObject(
                'group',
                $groupUuid,
                'filter_rule',
                'CC_FR_' . $this->token($groupUuid) . '_PASS',
                $fields,
                $order++
            );
        }

        $fields = $base;
        $fields['action'] = 'block';
        $fields['source_net'] = 'any';
        $fields['log'] = '1';
        $fields['description'] = 'ClientControl system=unknown-block';
        $rules['system:unknown-block'] = $this->desiredObject(
            'system',
            'unknown-block',
            'filter_rule',
            'CC_UNKNOWN_BLOCK',
            $fields,
            10000
        );
        return $rules;
    }

    private function compileShaper(&$desired, $general, $groups, $clients, $groupAddresses, $clientAddresses)
    {
        $protectedInterfaces = array_values($this->sortedUnique($general['protected_interfaces']));
        $wanInterfaces = array_values($this->sortedUnique($general['wan_interfaces']));
        $groupOrder = 1000;

        foreach ($groups as $groupUuid => $group) {
            if (!$group['enabled'] || $group['shaping_mode'] === 'unlimited') {
                continue;
            }
            $addresses = implode(',', $groupAddresses[$groupUuid] ?? []);
            if ($addresses === '') {
                continue;
            }
            $downloadMask = $group['shaping_mode'] === 'per_client' ? 'dst-ip' : 'none';
            $uploadMask = $group['shaping_mode'] === 'per_client' ? 'src-ip' : 'none';
            $downloadName = 'CC_P_' . $this->token($groupUuid) . '_DN';
            $uploadName = 'CC_P_' . $this->token($groupUuid) . '_UP';
            $desired['pipes']['group:' . $groupUuid . ':download'] = $this->pipe(
                'group',
                $groupUuid,
                $downloadName,
                $group['download'],
                $group['metric'],
                $downloadMask,
                'download'
            );
            $desired['pipes']['group:' . $groupUuid . ':upload'] = $this->pipe(
                'group',
                $groupUuid,
                $uploadName,
                $group['upload'],
                $group['metric'],
                $uploadMask,
                'upload'
            );
            foreach ($wanInterfaces as $wanInterface) {
                foreach ($protectedInterfaces as $protectedInterface) {
                    $path = $wanInterface . ':' . $protectedInterface;
                    $pathToken = $this->interfaceToken($path);
                    $downloadId = 'group:' . $groupUuid . ':download:' . $path;
                    $desired['shaper_rules'][$downloadId] = $this->shaperRule(
                        'group',
                        $groupUuid,
                        'CC_SR_' . $this->token($groupUuid) . '_DN_' . $pathToken,
                        $wanInterface,
                        $protectedInterface,
                        'in',
                        'any',
                        $addresses,
                        'group:' . $groupUuid . ':download',
                        $groupOrder++
                    );
                    $uploadId = 'group:' . $groupUuid . ':upload:' . $path;
                    $desired['shaper_rules'][$uploadId] = $this->shaperRule(
                        'group',
                        $groupUuid,
                        'CC_SR_' . $this->token($groupUuid) . '_UP_' . $pathToken,
                        $wanInterface,
                        $protectedInterface,
                        'out',
                        $addresses,
                        'any',
                        'group:' . $groupUuid . ':upload',
                        $groupOrder++
                    );
                }
            }
        }

        $order = 100;
        foreach ($clients as $clientUuid => $client) {
            $group = $groups[$client['group']];
            $effectiveAccess = $client['access_override'] === 'inherit' ?
                $group['access'] : $client['access_override'];
            if (!$this->effectiveEnabled($client, $group) || $effectiveAccess !== 'allow' ||
                empty($clientAddresses[$clientUuid])) {
                continue;
            }
            if ($client['shaping_override'] !== 'limited') {
                continue;
            }

            $downloadName = 'CC_P_' . $this->token($clientUuid) . '_DN';
            $uploadName = 'CC_P_' . $this->token($clientUuid) . '_UP';
            $desired['pipes']['client:' . $clientUuid . ':download'] = $this->pipe(
                'client',
                $clientUuid,
                $downloadName,
                $client['download_override'],
                $client['metric_override'],
                'none',
                'download'
            );
            $desired['pipes']['client:' . $clientUuid . ':upload'] = $this->pipe(
                'client',
                $clientUuid,
                $uploadName,
                $client['upload_override'],
                $client['metric_override'],
                'none',
                'upload'
            );
            $addresses = implode(',', $clientAddresses[$clientUuid]);
            foreach ($wanInterfaces as $wanInterface) {
                foreach ($protectedInterfaces as $protectedInterface) {
                    $path = $wanInterface . ':' . $protectedInterface;
                    $pathToken = $this->interfaceToken($path);
                    $downloadId = 'client:' . $clientUuid . ':download:' . $path;
                    $desired['shaper_rules'][$downloadId] = $this->shaperRule(
                        'client',
                        $clientUuid,
                        'CC_SR_' . $this->token($clientUuid) . '_DN_' . $pathToken,
                        $wanInterface,
                        $protectedInterface,
                        'in',
                        'any',
                        $addresses,
                        'client:' . $clientUuid . ':download',
                        $order++
                    );
                    $uploadId = 'client:' . $clientUuid . ':upload:' . $path;
                    $desired['shaper_rules'][$uploadId] = $this->shaperRule(
                        'client',
                        $clientUuid,
                        'CC_SR_' . $this->token($clientUuid) . '_UP_' . $pathToken,
                        $wanInterface,
                        $protectedInterface,
                        'out',
                        $addresses,
                        'any',
                        'client:' . $clientUuid . ':upload',
                        $order++
                    );
                }
            }
        }
    }

    private function pipe($ownerType, $ownerUuid, $name, $bandwidth, $metric, $mask, $direction)
    {
        return $this->desiredObject(
            $ownerType,
            $ownerUuid,
            'pipe',
            $name,
            [
                'enabled' => '1',
                'bandwidth' => (string)$bandwidth,
                'bandwidthMetric' => $metric,
                'mask' => $mask,
                'scheduler' => 'fq_codel',
                'origin' => self::ORIGIN,
                'description' => sprintf('ClientControl %s=%s direction=%s', $ownerType, $ownerUuid, $direction),
            ]
        );
    }

    private function shaperRule(
        $ownerType,
        $ownerUuid,
        $name,
        $interface,
        $interface2,
        $direction,
        $source,
        $destination,
        $targetLogicalId,
        $order
    ) {
        return $this->desiredObject(
            $ownerType,
            $ownerUuid,
            'shaper_rule',
            $name,
            [
                'enabled' => '1',
                'interface' => $interface,
                'interface2' => $interface2,
                'proto' => 'ip',
                'source' => $source,
                'source_not' => '0',
                'src_port' => 'any',
                'destination' => $destination,
                'destination_not' => '0',
                'dst_port' => 'any',
                'direction' => $direction,
                'target_logical_id' => $targetLogicalId,
                'origin' => self::ORIGIN,
                'description' => sprintf('ClientControl %s=%s shaper=%s', $ownerType, $ownerUuid, $name),
            ],
            $order
        );
    }

    private function desiredObject($ownerType, $ownerUuid, $coreType, $coreName, $fields, $order = null)
    {
        if (in_array($coreType, ['filter_rule', 'pipe', 'shaper_rule'], true)) {
            $description = preg_replace('/^ClientControl\s*/', '', (string)($fields['description'] ?? ''));
            $fields['description'] = substr(
                'ClientControl name=' . $coreName . ($description !== '' ? ' ' . $description : ''),
                0,
                255
            );
        }
        $object = [
            'owner_type' => $ownerType,
            'owner_uuid' => $ownerUuid,
            'core_type' => $coreType,
            'core_name' => $coreName,
            'fields' => $fields,
        ];
        if ($order !== null) {
            $object['order'] = $order;
        }
        $object['fingerprint'] = Canonical::fingerprint($fields);
        return $object;
    }

    private function destination($general)
    {
        if ($general['destination_scope'] === 'wan') {
            return ['net' => 'CC_PRIVATE', 'not' => '1'];
        }
        if ($general['destination_scope'] === 'custom') {
            return ['net' => $general['destination_alias'], 'not' => '0'];
        }
        return ['net' => 'any', 'not' => '0'];
    }

    private function effectiveEnabled($client, $group)
    {
        return !empty($client['enabled']) && !empty($group['enabled']);
    }

    private function optionalInt($value)
    {
        return (int)$value > 0 ? (string)(int)$value : '';
    }

    private function token($uuid)
    {
        return strtoupper(substr(str_replace('-', '', $uuid), 0, 12));
    }
    private function interfaceToken($interface)
    {
        return strtoupper(substr(hash('sha256', (string)$interface), 0, 6));
    }


    private function sortedUnique($values)
    {
        $values = array_values(array_unique($values));
        natcasesort($values);
        return array_values($values);
    }
    private function degradeUnavailableSchedules(array &$state)
    {
        $notices = [];
        foreach ($state['groups'] as $groupUuid => &$group) {
            if (empty($group['enabled']) || trim((string)($group['schedule'] ?? '')) === '' ||
                !array_key_exists('schedule_exists', $group) || !empty($group['schedule_exists'])) {
                continue;
            }
            $group['enabled'] = false;
            $notices[] = [
                'reason' => 'missing_schedule',
                'group_uuid' => (string)$groupUuid,
                'message' => sprintf(
                    gettext('Group %s is fail-closed because schedule %s no longer exists.'),
                    (string)($group['name'] ?? $groupUuid),
                    (string)$group['schedule']
                ),
            ];
        }
        unset($group);
        return $notices;
    }


    private function unsupportedPlatformWarnings(array $state)
    {
        if (Platform::supportsPacketRate()) {
            return [];
        }
        $warnings = [];
        foreach ($state['groups'] as $groupUuid => $group) {
            if (empty($group['enabled']) || (int)($group['packet_rate'] ?? 0) === 0) {
                continue;
            }
            $groupName = trim((string)($group['name'] ?? '')) ?: (string)$groupUuid;
            $warnings[] = [
                'identity' => 'group|' . $groupUuid,
                'core_type' => 'filter_rule',
                'core_name' => $groupName,
                'core_uuid' => (string)$groupUuid,
                'reason' => 'unsupported_packet_rate',
                'message' => sprintf(
                    gettext('Group %s is fail-closed because this firewall backend does not support packet-rate limits.'),
                    $groupName
                ),
                'before' => null,
                'desired' => [
                    'packet_rate' => (int)$group['packet_rate'],
                    'packet_rate_seconds' => (int)($group['packet_rate_seconds'] ?? 0),
                ],
                'changes' => [],
            ];
        }
        return $warnings;
    }

    private function validateStateShape(array &$state)
    {
        foreach (['general', 'groups', 'clients'] as $key) {
            if (!isset($state[$key]) || !is_array($state[$key])) {
                throw new InvalidArgumentException(sprintf('Missing state section: %s', $key));
            }
        }
        $warnings = [];
        foreach ($state['clients'] as $clientUuid => $client) {
            if (!isset($state['groups'][$client['group']])) {
                $clientName = trim((string)($client['name'] ?? '')) ?: (string)$clientUuid;
                $warnings[] = [
                    'identity' => 'client|' . $clientUuid,
                    'core_type' => 'client',
                    'core_name' => $clientName,
                    'core_uuid' => (string)$clientUuid,
                    'reason' => 'missing_group',
                    'message' => sprintf(
                        gettext('Client %s was excluded from policy compilation because its group is missing.'),
                        $clientName
                    ),
                    'before' => ['group' => (string)($client['group'] ?? '')],
                    'desired' => null,
                    'changes' => [],
                ];
                unset($state['clients'][$clientUuid]);
                continue;
            }
            foreach ($client['endpoints'] as $endpoint) {
                if (!in_array($endpoint['kind'], ['ipv4', 'ipv6', 'mac'], true)) {
                    throw new InvalidArgumentException(gettext('Unknown endpoint kind.'));
                }
            }
        }
        if (!in_array($state['general']['enforcement_mode'], ['observe', 'enforce'], true) ||
            !in_array($state['general']['destination_scope'], ['any', 'wan', 'custom'], true)) {
            throw new InvalidArgumentException(gettext('Unknown enforcement or destination mode.'));
        }
        return $warnings;
    }
}
