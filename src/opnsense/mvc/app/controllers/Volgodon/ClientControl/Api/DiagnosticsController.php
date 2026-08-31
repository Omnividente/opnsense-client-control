<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\Api;

use OPNsense\Core\Backend;
use Volgodon\ClientControl\Reconciler;
use Volgodon\ClientControl\Platform;
use Volgodon\ClientControl\Translations;

class DiagnosticsController extends ClientControlControllerBase
{
    protected static $internalModelName = 'diagnostics';

    public function runtimeAction()
    {
        $model = $this->lockModel();
        try {
            $backend = new Backend();
            $arp = json_decode($backend->configdRun('interface list arp json'), true) ?? [];
            $ndp = json_decode($backend->configdRun('interface list ndp json'), true) ?? [];
            $stateResponse = json_decode(
                $backend->configdpRun('filter list states', ['', 10000, 0, '', '']),
                true
            ) ?? [];
            $states = $stateResponse['details'] ?? [];
            $shaperAction = Platform::usesRuntimeFilterRegistry() ? 'ipfw stats' : 'shaper stats';
            $shaper = json_decode($backend->configdRun($shaperAction), true) ?? [];

            $neighborsByIp = [];
            $neighborsByMac = [];
            foreach (array_merge($arp, $ndp) as $neighbor) {
                $ip = $this->firstValue($neighbor, ['ip', 'address', 'hostname']);
                $mac = strtolower($this->firstValue($neighbor, ['mac', 'lladdr', 'link_layer_address']));
                if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                    $neighborsByIp[strtolower($ip)][] = $neighbor;
                }
                if (filter_var($mac, FILTER_VALIDATE_MAC) !== false) {
                    $neighborsByMac[$mac][] = $neighbor;
                }
            }

            $clients = [];
            $warnings = [];
            foreach ($model->clients->client->iterateItems() as $uuid => $client) {
                $neighbors = [];
                $clientAddresses = [];
                $unresolvedMacs = [];
                foreach ($model->getClientEndpoints($uuid) as $endpoint) {
                    $value = strtolower($endpoint['value']);
                    if ($endpoint['kind'] === 'mac') {
                        $resolved = $neighborsByMac[$value] ?? [];
                        $neighbors = array_merge($neighbors, $resolved);
                        if ($resolved === []) {
                            $unresolvedMacs[] = $endpoint['value'];
                            $warnings[] = [
                                'client_uuid' => $uuid,
                                'client_name' => (string)$client->name,
                                'endpoint' => $endpoint['value'],
                                'policy' => 'deny',
                                'message' => gettext('MAC endpoint is absent from ARP/NDP and is denied as unknown.'),
                            ];
                        }
                        foreach ($resolved as $neighbor) {
                            $ip = strtolower($this->firstValue($neighbor, ['ip', 'address']));
                            if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                                $clientAddresses[$ip] = true;
                            }
                        }
                    } else {
                        $clientAddresses[$value] = true;
                        $neighbors = array_merge($neighbors, $neighborsByIp[$value] ?? []);
                    }
                }
                $stateCount = 0;
                foreach ($states as $state) {
                    foreach (['src_addr', 'dst_addr', 'nat_addr'] as $field) {
                        $address = strtolower((string)($state[$field] ?? ''));
                        if (isset($clientAddresses[$address])) {
                            ++$stateCount;
                            break;
                        }
                    }
                }
                $neighbors = $this->deduplicateRecords($neighbors);
                $clients[] = [
                    'uuid' => $uuid,
                    'name' => (string)$client->name,
                    'enabled' => ((string) $client->enabled === (string) '1'),
                    'online' => $neighbors !== [] || $stateCount > 0,
                    'neighbors' => $neighbors,
                    'unresolved_mac_endpoints' => $unresolvedMacs,
                    'state_count' => $stateCount,
                    'effective_policy' => $model->getEffectivePolicy($uuid),
                    'sync_state' => $model->getSyncState(),
                ];
            }

            try {
                $plan = (new Reconciler($model))->plan('fail');
                $nonNoop = array_values(array_filter(
                    $plan['operations'],
                    fn($operation) => $operation['action'] !== 'noop'
                ));
                $health = [
                    'status' => $plan['status'],
                    'pending_operations' => count($nonNoop),
                    'conflicts' => $plan['conflicts'],
                    'plan_fingerprint' => $plan['plan_fingerprint'],
                ];
            } catch (\Throwable $error) {
                $health = [
                    'status' => 'error',
                    'message' => $error->getMessage(),
                    'pending_operations' => null,
                    'conflicts' => [],
                ];
            }

            return [
                'status' => 'ok',
                'clients' => $clients,
                'health' => $health,
                'neighbor_policy' => [
                    'unresolved_mac' => (string)$model->general->stale_neighbor_policy,
                    'effect' => gettext('An unresolved MAC alias is empty; default block denies its traffic.'),
                ],
                'warnings' => $warnings,
                'arp' => $arp,
                'ndp' => $ndp,
                'pf_states' => [
                    'total' => $stateResponse['total_entries'] ?? count($states),
                    'returned' => count($states),
                ],
                'traffic_shaper' => $this->managedShaperStats($model, $shaper),
                'sync_state' => $model->getSyncState(),
                'revision' => ((int) (string) $model->general->revision),
            ];
        } finally {
            $this->unlockModel();
        }
    }

    public function auditAction()
    {
        $model = $this->getModel();
        $records = [];
        foreach ($model->audit->entry->iterateItems() as $uuid => $entry) {
            $records[] = [
                'uuid' => $uuid,
                'timestamp' => (string)$entry->timestamp,
                'username' => (string)$entry->username,
                'operation' => (string)$entry->operation,
                'summary' => Translations::auditSummary((string)$entry->operation, (string)$entry->summary),
                'result' => (string)$entry->result,
            ];
        }
        return $this->searchRecordsetBase($records, null, 'timestamp', null, SORT_NATURAL | SORT_FLAG_CASE);
    }

    private function managedShaperStats($model, $stats)
    {
        $pipeUuids = [];
        foreach ($model->managed_objects->object->iterateItems() as $object) {
            if (((string) $object->core_type === (string) 'pipe')) {
                $pipeUuids[(string)$object->core_uuid] = [
                    'logical_id' => (string)$object->logical_id,
                    'core_name' => (string)$object->core_name,
                ];
            }
        }
        if (empty($pipeUuids) || empty($stats['pipes'])) {
            return ['pipes' => [], 'rules' => [], 'raw_status' => empty($stats) ? 'unavailable' : 'ok'];
        }

        $pipes = [];
        $shaperModel = new \OPNsense\TrafficShaper\TrafficShaper();
        foreach ($shaperModel->pipes->pipe->iterateItems() as $uuid => $pipe) {
            if (!isset($pipeUuids[$uuid])) {
                continue;
            }
            $number = (string)$pipe->number;
            $runtime = $stats['pipes'][$number] ?? null;
            $pipes[] = array_merge(
                $pipeUuids[$uuid],
                [
                    'uuid' => $uuid,
                    'number' => $number,
                    'description' => (string)$pipe->description,
                    'runtime' => $runtime,
                ]
            );
        }
        return [
            'pipes' => $pipes,
            'rules' => $stats['rules'] ?? [],
            'raw_status' => 'ok',
        ];
    }

    private function firstValue($record, $keys)
    {
        foreach ($keys as $key) {
            if (!empty($record[$key])) {
                return (string)$record[$key];
            }
        }
        return '';
    }

    private function deduplicateRecords($records)
    {
        $result = [];
        foreach ($records as $record) {
            $result[hash('sha256', json_encode($record))] = $record;
        }
        return array_values($result);
    }
}
