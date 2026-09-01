<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

class Planner
{
    public function build(array $desired, array $actual, array $managed, $strategy = 'fail')
    {
        if (!in_array($strategy, ['fail', 'restore'], true)) {
            throw new \InvalidArgumentException(gettext('Unknown conflict strategy.'));
        }
        $desiredObjects = $this->flattenDesired($desired);
        $operations = [];
        $conflicts = array_values(array_filter($desired['warnings'] ?? [], 'is_array'));
        $matchedActual = [];
        $matchedManaged = [];

        foreach ($desiredObjects as $identity => $entry) {
            $object = $entry['object'];
            $managedRecord = $managed[$identity] ?? null;
            $actualObject = null;
            if ($managedRecord !== null && !empty($managedRecord['core_uuid'])) {
                $actualObject = $actual['by_uuid'][$object['core_type']][$managedRecord['core_uuid']] ?? null;
            }
            if ($actualObject === null) {
                $actualObject = $actual['by_name'][$object['core_type']][$object['core_name']] ?? null;
            }
            if ($actualObject !== null) {
                $matchedActual[$actualObject['identity']] = true;
            }
            if ($managedRecord !== null) {
                $matchedManaged[$identity] = true;
            }

            if ($actualObject === null) {
                if ($managedRecord !== null && !empty($managedRecord['applied_fingerprint']) && $strategy === 'fail') {
                    $conflicts[] = $this->conflict(
                        $identity,
                        $object,
                        null,
                        'managed_object_missing',
                        gettext('The previously applied managed object is missing.')
                    );
                    continue;
                }
                $operations[] = $this->operation('create', $identity, null, $object);
                continue;
            }

            if (empty($actualObject['owned'])) {
                $conflicts[] = $this->conflict(
                    $identity,
                    $object,
                    $actualObject,
                    'name_or_uuid_collision',
                    gettext('An unmanaged object occupies the deterministic name or recorded UUID.')
                );
                continue;
            }
            if ($actualObject['core_name'] !== $object['core_name']) {
                $conflicts[] = $this->conflict(
                    $identity,
                    $object,
                    $actualObject,
                    'identity_changed',
                    gettext('The deterministic managed object name was changed externally.')
                );
                continue;
            }
            if ($managedRecord === null) {
                $operations[] = $this->operation('update', $identity, $actualObject, $object);
                continue;
            }

            $allocationChanged = ($object['allocation'] ?? []) !== ($actualObject['allocation'] ?? []);

            $drift = $managedRecord !== null && !empty($managedRecord['applied_fingerprint']) &&
                !hash_equals($managedRecord['applied_fingerprint'], $actualObject['full_fingerprint']);
            if ($drift && $strategy === 'fail') {
                $conflicts[] = $this->conflict(
                    $identity,
                    $object,
                    $actualObject,
                    'external_change',
                    gettext('The managed object differs from its last applied fingerprint.')
                );
                continue;
            }

            if (($drift && $strategy === 'restore') ||
                !hash_equals($object['fingerprint'], $actualObject['semantic_fingerprint']) ||
                $allocationChanged) {
                $operations[] = $this->operation('update', $identity, $actualObject, $object);
            } else {
                $operations[] = $this->operation('noop', $identity, $actualObject, $object);
            }
        }

        foreach ($managed as $identity => $record) {
            if (isset($matchedManaged[$identity]) || isset($desiredObjects[$identity])) {
                continue;
            }
            $actualObject = null;
            if (!empty($record['core_uuid'])) {
                $actualObject = $actual['by_uuid'][$record['core_type']][$record['core_uuid']] ?? null;
            }
            if ($actualObject === null && !empty($record['core_name'])) {
                $actualObject = $actual['by_name'][$record['core_type']][$record['core_name']] ?? null;
            }
            if ($actualObject === null) {
                $operations[] = [
                    'action' => 'drop_record',
                    'identity' => $identity,
                    'core_type' => $record['core_type'],
                    'core_name' => $record['core_name'],
                    'core_uuid' => $record['core_uuid'] ?? '',
                    'before' => null,
                    'after' => null,
                    'changes' => [],
                ];
                continue;
            }
            $matchedActual[$actualObject['identity']] = true;
            if (empty($actualObject['ownership_intact'])) {
                $conflicts[] = $this->conflict(
                    $identity,
                    null,
                    $actualObject,
                    'ownership_marker_changed',
                    gettext('An obsolete registered object lost its ownership markers and will not be deleted.')
                );
                continue;
            }
            $drift = !empty($record['applied_fingerprint']) &&
                !hash_equals($record['applied_fingerprint'], $actualObject['full_fingerprint']);
            if ($drift && $strategy !== 'restore') {
                $conflicts[] = $this->conflict(
                    $identity,
                    null,
                    $actualObject,
                    'orphan_external_change',
                    gettext('An obsolete managed object was changed externally before deletion.')
                );
            } else {
                $operations[] = $this->operation('delete', $identity, $actualObject, null);
            }
        }

        foreach ($actual['owned'] as $actualObject) {
            if (isset($matchedActual[$actualObject['identity']])) {
                continue;
            }
            $identity = $actualObject['core_type'] . '|orphan:' . $actualObject['core_uuid'];
            $operations[] = $this->operation('delete', $identity, $actualObject, null);
        }

        usort($operations, function ($left, $right) {
            $weights = [
                'category' => 0,
                'alias' => 10,
                'pipe' => 20,
                'shaper_rule' => 30,
                'filter_rule' => 40,
            ];
            $actionWeights = ['drop_record' => 110, 'noop' => 105];
            $leftWeight = $left['action'] === 'delete'
                ? 100 - ($weights[$left['core_type']] ?? 0)
                : ($actionWeights[$left['action']] ?? ($weights[$left['core_type']] ?? 80));
            $rightWeight = $right['action'] === 'delete'
                ? 100 - ($weights[$right['core_type']] ?? 0)
                : ($actionWeights[$right['action']] ?? ($weights[$right['core_type']] ?? 80));
            return [$leftWeight, $left['identity']] <=> [$rightWeight, $right['identity']];
        });

        $counts = [];
        foreach ($operations as $operation) {
            $counts[$operation['action']] = ($counts[$operation['action']] ?? 0) + 1;
        }
        ksort($counts, SORT_STRING);
        return [
            'status' => empty($conflicts) ? 'ok' : 'conflict',
            'strategy' => $strategy,
            'desired_fingerprint' => $desired['fingerprint'] ?? '',
            'runtime_fingerprint' => $desired['runtime_fingerprint'] ?? '',
            'forecast' => $desired['forecast'] ?? [],
            'notices' => array_values(array_filter($desired['notices'] ?? [], 'is_array')),
            'counts' => $counts,
            'operations' => $operations,
            'conflicts' => $conflicts,
        ];
    }

    public function flattenDesired(array $desired)
    {
        $sections = [
            'categories' => 'category',
            'aliases' => 'alias',
            'filter_rules' => 'filter_rule',
            'pipes' => 'pipe',
            'shaper_rules' => 'shaper_rule',
        ];
        $result = [];
        foreach ($sections as $section => $coreType) {
            foreach ($desired[$section] ?? [] as $logicalId => $object) {
                $identity = $coreType . '|' . $logicalId;
                $result[$identity] = [
                    'logical_id' => $logicalId,
                    'section' => $section,
                    'object' => $object,
                ];
            }
        }
        return $result;
    }

    private function operation($action, $identity, $actual, $desired)
    {
        $coreType = $desired['core_type'] ?? $actual['core_type'];
        $coreName = $desired['core_name'] ?? $actual['core_name'];
        $before = $actual['fields'] ?? null;
        $after = $desired['fields'] ?? null;
        if (is_array($before)) {
            foreach ($actual['allocation'] ?? [] as $field => $value) {
                $before['@' . $field] = $value;
            }
        }
        if (is_array($after)) {
            foreach ($desired['allocation'] ?? [] as $field => $value) {
                $after['@' . $field] = $value;
            }
        }
        return [
            'action' => $action,
            'identity' => $identity,
            'core_type' => $coreType,
            'core_name' => $coreName,
            'core_uuid' => $actual['core_uuid'] ?? '',
            'before' => $before,
            'after' => $after,
            'changes' => $this->fieldDiff($before, $after),
            'desired' => $desired,
            'actual' => $actual,
        ];
    }

    private function conflict($identity, $desired, $actual, $reason, $message)
    {
        return [
            'identity' => $identity,
            'core_type' => $desired['core_type'] ?? ($actual['core_type'] ?? ''),
            'core_name' => $desired['core_name'] ?? ($actual['core_name'] ?? ''),
            'core_uuid' => $actual['core_uuid'] ?? '',
            'reason' => $reason,
            'message' => $message,
            'before' => $actual['fields'] ?? null,
            'desired' => $desired['fields'] ?? null,
            'changes' => $this->fieldDiff($actual['fields'] ?? null, $desired['fields'] ?? null),
        ];
    }

    private function fieldDiff($before, $after)
    {
        $before = is_array($before) ? $before : [];
        $after = is_array($after) ? $after : [];
        $keys = array_values(array_unique(array_merge(array_keys($before), array_keys($after))));
        sort($keys, SORT_STRING);
        $result = [];
        foreach ($keys as $key) {
            $old = $before[$key] ?? null;
            $new = $after[$key] ?? null;
            if ($old !== $new) {
                $result[$key] = ['before' => $old, 'after' => $new];
            }
        }
        return $result;
    }
}
