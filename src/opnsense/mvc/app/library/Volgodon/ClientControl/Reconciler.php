<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

use OPNsense\Base\UserException;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\Firewall\Category;
use OPNsense\Firewall\Filter;
use OPNsense\Firewall\Util;
use OPNsense\TrafficShaper\TrafficShaper;

class Reconciler
{
    private $model;
    private $compiler;
    private $planner;
    private $desired = [];
    private $categoryModel;
    private $aliasModel;
    private $filterModel;
    private $shaperModel;
    private $resolvedMacs;

    public function __construct($model, $compiler = null, $planner = null, $resolvedMacs = null)
    {
        $this->model = $model;
        $this->compiler = $compiler ?? new Compiler();
        $this->planner = $planner ?? new Planner();
        $this->resolvedMacs = is_array($resolvedMacs) ? $resolvedMacs : null;
    }

    public function plan($strategy = 'fail')
    {
        $resolvedMacs = $this->resolvedMacs ?? $this->resolvedMacAddresses();
        $this->resolvedMacs = $resolvedMacs;
        $this->desired = $this->compiler->compile($this->model, $resolvedMacs);
        $managed = $this->snapshotManaged();
        $raw = $this->collectRawObjects($managed);
        $this->allocateDesired($this->desired, $raw, $managed);
        $actual = $this->snapshotActual($raw, $this->desired, $managed);
        $plan = $this->planner->build($this->desired, $actual, $managed, $strategy);
        $plan['revision'] = ((int) (string) $this->model->general->revision);
        $plan['mode'] = (string)$this->model->general->enforcement_mode;
        $plan['notices'] = $this->desired['notices'] ?? [];
        $plan['plan_fingerprint'] = PlanFingerprint::intent(
            $plan['revision'],
            $plan['mode'],
            $strategy,
            $this->desired,
            $managed,
            $raw
        );
        $plan['runtime_plan_fingerprint'] = PlanFingerprint::runtime(
            $plan['plan_fingerprint'],
            $this->desired,
            $plan
        );
        return $plan;
    }

    public function apply($strategy = 'fail', $plan = null)
    {
        $plan = is_array($plan) ? $plan : $this->plan($strategy);
        if ($plan['status'] !== 'ok') {
            throw new UserException(
                gettext('Managed objects contain conflicts. Resolve them or explicitly restore module state.'),
                gettext('Client Control')
            );
        }

        $upserts = array_values(array_filter(
            $plan['operations'],
            fn($operation) => in_array($operation['action'], ['create', 'update'], true)
        ));
        $deletes = array_values(array_filter(
            $plan['operations'],
            fn($operation) => $operation['action'] === 'delete'
        ));
        $this->applyCategory($upserts);
        $this->applyAliases($upserts);
        $this->applyShaper($upserts);
        $this->applyFilter($upserts);
        $this->applyFilter($deletes);
        $this->applyShaper($deletes);
        $this->applyAliases($deletes);
        $this->applyCategory($deletes);
        $this->syncManagedRecords($plan);
        $this->assertValid($this->model, 'Client Control');
        return $plan;
    }

    public function getDesired()
    {
        return $this->desired;
    }
    public function getResolvedMacs()
    {
        return $this->resolvedMacs ?? [];
    }


    private function applyCategory($operations)
    {
        $this->categoryModel = new Category();
        $changed = false;
        foreach ($operations as $operation) {
            if ($operation['core_type'] !== 'category') {
                continue;
            }
            if (in_array($operation['action'], ['create', 'update'], true)) {
                $node = $this->findNode($this->categoryModel, 'category', $operation);
                if ($node === null) {
                    $node = $this->categoryModel->categories->category->Add();
                }
                $this->setNodeFields($node, 'category', $operation['desired'], $operation['action'] === 'update');
                $changed = true;
            } elseif ($operation['action'] === 'delete') {
                $node = $this->findNode($this->categoryModel, 'category', $operation);
                if ($node !== null) {
                    $this->categoryModel->categories->category->del($node->getAttribute('uuid'));
                    $changed = true;
                }
            }
        }
        $this->assertValid($this->categoryModel, 'Firewall category', false);
        if ($changed) {
            $this->categoryModel->serializeToConfig(false, true);
            if (method_exists(Category::class, 'flushCacheData')) {
                Category::flushCacheData();
            }
        }
    }

    private function applyAliases($operations)
    {
        $this->aliasModel = new Alias();
        $changed = false;
        $ignoredValidationFields = [];
        foreach ($this->orderedOperations($operations, 'alias', false) as $operation) {
            if (in_array($operation['action'], ['create', 'update'], true)) {
                $node = $this->findNode($this->aliasModel, 'alias', $operation);
                if ($node === null) {
                    $node = $this->aliasModel->aliases->alias->Add();
                }
                $this->setNodeFields($node, 'alias', $operation['desired'], $operation['action'] === 'update');
                if (Platform::usesRuntimeFilterRegistry() && isset($node->categories)) {
                    // TING does not refresh relation options after creating the category in this transaction.
                    $ignoredValidationFields[] = $node->categories->__reference;
                }
                $changed = true;
            }
        }
        foreach ($this->orderedOperations($operations, 'alias', true) as $operation) {
            if ($operation['action'] !== 'delete') {
                continue;
            }
            $node = $this->findNode($this->aliasModel, 'alias', $operation);
            if ($node !== null) {
                $this->aliasModel->aliases->alias->del($node->getAttribute('uuid'));
                $changed = true;
            }
        }
        Util::attachAliasObject($this->aliasModel);
        $this->assertValid($this->aliasModel, 'Firewall aliases', false, $ignoredValidationFields);
        if ($changed) {
            $this->aliasModel->serializeToConfig(false, true);
            if (method_exists($this->aliasModel, 'flushCache')) {
                $this->aliasModel->flushCache();
            } elseif (method_exists(Alias::class, 'flushCacheData')) {
                Alias::flushCacheData();
            }
        }
    }

    private function applyShaper($operations)
    {
        $this->shaperModel = new TrafficShaper();
        $pipesChanged = false;
        foreach ($this->orderedOperations($operations, 'pipe', false) as $operation) {
            if (!in_array($operation['action'], ['create', 'update'], true)) {
                continue;
            }
            $node = $this->findNode($this->shaperModel, 'pipe', $operation);
            if ($node === null) {
                $node = $this->shaperModel->pipes->pipe->Add();
            }
            $this->setNodeFields($node, 'pipe', $operation['desired'], $operation['action'] === 'update');
            $pipesChanged = true;
        }
        if ($pipesChanged) {
            $this->shaperModel->serializeToConfig(false, true);
        }

        $this->shaperModel = new TrafficShaper();
        $rulesChanged = false;
        $ignoredValidationFields = [];
        foreach ($this->orderedOperations($operations, 'shaper_rule', false) as $operation) {
            if (!in_array($operation['action'], ['create', 'update'], true)) {
                continue;
            }
            $node = $this->findNode($this->shaperModel, 'shaper_rule', $operation);
            if ($node === null) {
                $node = $this->shaperModel->rules->rule->Add();
            }
            $this->setNodeFields($node, 'shaper_rule', $operation['desired'], $operation['action'] === 'update');
            $node->target = $this->resolveShaperTarget($operation['desired']['fields']['target_logical_id']);
            if (Platform::usesRuntimeFilterRegistry()) {
                // TING does not refresh pipe relation options after creating pipes in this transaction.
                $ignoredValidationFields[] = $node->target->__reference;
            }
            $rulesChanged = true;
        }
        foreach ($this->orderedOperations($operations, 'shaper_rule', true) as $operation) {
            if ($operation['action'] !== 'delete') {
                continue;
            }
            $node = $this->findNode($this->shaperModel, 'shaper_rule', $operation);
            if ($node !== null) {
                $this->shaperModel->rules->rule->del($node->getAttribute('uuid'));
                $rulesChanged = true;
            }
        }
        if ($rulesChanged) {
            $this->assertValid($this->shaperModel, 'Traffic Shaper rules', false, $ignoredValidationFields);
            $this->shaperModel->serializeToConfig(false, true);
        }

        $this->shaperModel = new TrafficShaper();
        $pipesDeleted = false;
        foreach ($this->orderedOperations($operations, 'pipe', true) as $operation) {
            if ($operation['action'] !== 'delete') {
                continue;
            }
            $node = $this->findNode($this->shaperModel, 'pipe', $operation);
            if ($node !== null) {
                $this->shaperModel->pipes->pipe->del($node->getAttribute('uuid'));
                $pipesDeleted = true;
            }
        }
        if ($pipesDeleted) {
            $this->assertValid($this->shaperModel, 'Traffic Shaper pipes', false);
            $this->shaperModel->serializeToConfig(false, true);
        }
    }

    private function applyFilter($operations)
    {
        if (Platform::usesRuntimeFilterRegistry()) {
            return;
        }
        $this->filterModel = new Filter();
        $changed = false;
        foreach ($this->orderedOperations($operations, 'filter_rule', false) as $operation) {
            if (!in_array($operation['action'], ['create', 'update'], true)) {
                continue;
            }
            $node = $this->findNode($this->filterModel, 'filter_rule', $operation);
            if ($node === null) {
                $node = $this->filterModel->rules->rule->Add();
            }
            $this->setNodeFields($node, 'filter_rule', $operation['desired'], $operation['action'] === 'update');
            foreach (['source_net', 'destination_net'] as $field) {
                if (isset($node->{$field})) {
                    $node->{$field}->resetStaticOptions();
                    $node->{$field}->eventPostLoading();
                }
            }
            $changed = true;
        }
        foreach ($this->orderedOperations($operations, 'filter_rule', true) as $operation) {
            if ($operation['action'] !== 'delete') {
                continue;
            }
            $node = $this->findNode($this->filterModel, 'filter_rule', $operation);
            if ($node !== null) {
                $this->filterModel->rules->rule->del($node->getAttribute('uuid'));
                $changed = true;
            }
        }
        $this->assertValid($this->filterModel, 'Firewall rules', false);
        if ($changed) {
            $this->filterModel->serializeToConfig(false, true);
        }
    }

    private function resolveShaperTarget($logicalId)
    {
        $targetIdentity = 'pipe|' . $logicalId;
        $targetEntry = $this->planner->flattenDesired($this->desired)[$targetIdentity] ?? null;
        if ($targetEntry === null) {
            throw new UserException(gettext('A desired shaper pipe target is missing.'), gettext('Client Control'));
        }
        $targetOperation = [
            'core_uuid' => '',
            'core_name' => $targetEntry['object']['core_name'],
        ];
        $targetNode = $this->findNode($this->shaperModel, 'pipe', $targetOperation);
        if ($targetNode === null) {
            throw new UserException(gettext('Unable to resolve a desired shaper pipe.'), gettext('Client Control'));
        }
        return $targetNode->getAttribute('uuid');
    }

    private function setNodeFields($node, $coreType, $desired, $reset = false)
    {
        if ($reset) {
            $this->resetNode($node, $coreType);
        }
        $fields = $desired['fields'];
        $categoryUuid = $coreType === 'category' ? '' : $this->categoryUuid();
        foreach ($fields as $field => $value) {
            if ($field === 'target_logical_id') {
                continue;
            }
            if (!isset($node->{$field})) {
                if ((string)$value === '') {
                    continue;
                }
                throw new UserException(
                    sprintf(gettext('The installed OPNsense version does not support firewall field %s.'), $field),
                    gettext('Client Control compatibility error')
                );
            }
            if ($field === 'categories' && $value === Compiler::CATEGORY) {
                $value = $categoryUuid;
            }
            $node->{$field} = $value;
        }
        foreach ($desired['allocation'] ?? [] as $field => $value) {
            $node->{$field} = (string)$value;
        }
    }

    private function syncManagedRecords($plan)
    {
        $managedNodes = [];
        foreach ($this->model->managed_objects->object->iterateItems() as $uuid => $node) {
            $managedNodes[(string)$node->logical_id] = ['uuid' => $uuid, 'node' => $node];
        }
        $raw = $this->collectRawObjects($this->snapshotManaged());
        $actual = $this->snapshotActual($raw, $this->desired, $this->snapshotManaged());
        $desiredFlat = $this->planner->flattenDesired($this->desired);

        $keep = [];

        foreach ($desiredFlat as $identity => $entry) {
            $object = $entry['object'];
            if (Platform::usesRuntimeFilterRegistry() && $object['core_type'] === 'filter_rule') {
                $actualObject = $this->virtualActualFromDesired($identity, $object);
            } else {
                $actualObject = $actual['by_name'][$object['core_type']][$object['core_name']] ?? null;
            }
            if ($actualObject === null) {
                throw new UserException(
                    sprintf(gettext('Managed object %s was not present after reconciliation.'), $object['core_name']),
                    gettext('Client Control')
                );
            }
            if (isset($managedNodes[$identity])) {
                $record = $managedNodes[$identity]['node'];
            } else {
                $record = $this->model->managed_objects->object->Add();
                $managedNodes[$identity] = [
                    'uuid' => $record->getAttribute('uuid'),
                    'node' => $record,
                ];
            }
            $keep[$identity] = true;
            $record->logical_id = $identity;
            $record->owner_type = $object['owner_type'];
            $record->owner_uuid = $object['owner_uuid'];
            $record->core_type = $object['core_type'];
            $record->core_uuid = $actualObject['core_uuid'];
            $record->core_name = $object['core_name'];
            $record->desired_fingerprint = $object['fingerprint'];
            $record->applied_fingerprint = $actualObject['full_fingerprint'];
            $record->applied_state = Canonical::encode([
                'fields' => $actualObject['fields'],
                'allocation' => $actualObject['allocation'],
            ]);

        }

        foreach ($managedNodes as $identity => $data) {
            if (!isset($keep[$identity])) {
                $this->model->managed_objects->object->del($data['uuid']);
            }
        }
    }
    private function resetNode($node, $coreType)
    {
        $model = [
            'category' => $this->categoryModel,
            'alias' => $this->aliasModel,
            'filter_rule' => $this->filterModel,
            'pipe' => $this->shaperModel,
            'shaper_rule' => $this->shaperModel,
        ][$coreType];
        $collection = $this->modelCollection($model, $coreType);
        $template = $collection->Add();
        $templateUuid = $template->getAttribute('uuid');
        foreach ($template->iterateItems() as $field => $defaultNode) {
            if (!$defaultNode->isContainer()) {
                $node->{$field} = (string)$defaultNode;
            }
        }
        $collection->del($templateUuid);
    }

    private function snapshotManaged()
    {
        $result = [];
        foreach ($this->model->managed_objects->object->iterateItems() as $node) {
            $identity = (string)$node->logical_id;
            if ($identity === '') {
                continue;
            }
            $result[$identity] = [
                'identity' => $identity,
                'owner_type' => (string)$node->owner_type,
                'owner_uuid' => (string)$node->owner_uuid,
                'core_type' => (string)$node->core_type,
                'core_uuid' => (string)$node->core_uuid,
                'core_name' => (string)$node->core_name,
                'desired_fingerprint' => (string)$node->desired_fingerprint,
                'applied_fingerprint' => (string)$node->applied_fingerprint,
                'applied_state' => (string)$node->applied_state,
            ];
        }
        return $result;
    }


    private function collectRawObjects($managed)
    {
        $managedByUuid = [];
        foreach ($managed as $record) {
            if (!empty($record['core_uuid'])) {
                $managedByUuid[$record['core_type']][$record['core_uuid']] = $record;
            }
        }
        $cfg = Config::getInstance()->object();
        $categoryUuid = '';
        $categoryContainer = $cfg->OPNsense->Firewall->Category->categories ?? null;
        foreach ($this->xmlItems($categoryContainer, 'category') as $node) {
            if ((string)$node->name === Compiler::CATEGORY) {
                $categoryUuid = (string)$node->attributes()['uuid'];
                break;
            }
        }
        $paths = [
            'category' => [$categoryContainer, 'category'],
            'alias' => [$cfg->OPNsense->Firewall->Alias->aliases ?? null, 'alias'],
            'filter_rule' => [$cfg->OPNsense->Firewall->Filter->rules ?? null, 'rule'],
            'pipe' => [$cfg->OPNsense->TrafficShaper->pipes ?? null, 'pipe'],
            'shaper_rule' => [$cfg->OPNsense->TrafficShaper->rules ?? null, 'rule'],
        ];
        if (Platform::usesRuntimeFilterRegistry()) {
            unset($paths['filter_rule']);
        }
        $result = [];
        foreach ($paths as $coreType => [$container, $tag]) {
            foreach ($this->xmlItems($container, $tag) as $node) {
                $uuid = (string)$node->attributes()['uuid'];
                if ($uuid === '') {
                    continue;
                }
                $fields = [];
                foreach ($node->children() as $child) {
                    $fields[$child->getName()] = (string)$child;
                }
                $coreName = '';
                if ($coreType === 'category' || $coreType === 'alias') {
                    $coreName = $fields['name'] ?? '';
                } elseif (preg_match('/\bname=(CC_[A-Za-z0-9_]+)\b/', $fields['description'] ?? '', $matches)) {
                    $coreName = $matches[1];
                } elseif (isset($managedByUuid[$coreType][$uuid])) {
                    $coreName = $managedByUuid[$coreType][$uuid]['core_name'];
                }
                $registered = isset($managedByUuid[$coreType][$uuid]);
                $owned = false;
                $ownershipIntact = false;
                if ($coreType === 'category') {
                    $ownershipIntact = $coreName === Compiler::CATEGORY;
                } elseif ($coreType === 'alias') {
                    $ownershipIntact = str_starts_with($coreName, 'CC_') &&
                        str_starts_with($fields['description'] ?? '', 'ClientControl ') &&
                        $this->containsToken($fields['categories'] ?? '', $categoryUuid);
                } elseif ($coreType === 'filter_rule') {
                    $ownershipIntact = str_starts_with($coreName, 'CC_') &&
                        str_starts_with($fields['description'] ?? '', 'ClientControl ') &&
                        $this->containsToken($fields['categories'] ?? '', $categoryUuid);
                } else {
                    $ownershipIntact = str_starts_with($coreName, 'CC_') &&
                        ($fields['origin'] ?? '') === Compiler::ORIGIN &&
                        str_starts_with($fields['description'] ?? '', 'ClientControl ');
                }
                $owned = $registered && $ownershipIntact;
                $result[] = [
                    'identity' => $coreType . ':' . $uuid,
                    'core_type' => $coreType,
                    'core_uuid' => $uuid,
                    'core_name' => $coreName,
                    'raw_fields' => $fields,
                    'owned' => $owned,
                    'ownership_intact' => $ownershipIntact,
                    'category_uuid' => $categoryUuid,
                ];
            }
        }
        return $result;
    }

    private function snapshotActual($raw, $desired, $managed)
    {
        $desiredFlat = $this->planner->flattenDesired($desired);
        $desiredByName = [];
        foreach ($desiredFlat as $entry) {
            $object = $entry['object'];
            $desiredByName[$object['core_type']][$object['core_name']] = $object;
        }
        $pipeTargetMap = [];
        foreach ($raw as $record) {
            if ($record['core_type'] !== 'pipe' || $record['core_name'] === '') {
                continue;
            }
            foreach ($desiredFlat as $identity => $entry) {
                if ($entry['object']['core_type'] === 'pipe' &&
                    $entry['object']['core_name'] === $record['core_name']) {
                    $pipeTargetMap[$record['core_uuid']] = $entry['logical_id'];
                    break;
                }
            }
        }
        foreach ($managed as $identity => $record) {
            if ($record['core_type'] === 'pipe' && !empty($record['core_uuid'])) {
                $pipeTargetMap[$record['core_uuid']] = explode('|', $identity, 2)[1] ?? $identity;
            }
        }

        $result = ['by_uuid' => [], 'by_name' => [], 'owned' => []];
        foreach ($raw as $record) {
            $desiredObject = $desiredByName[$record['core_type']][$record['core_name']] ?? null;
            $semantic = [];
            if ($desiredObject !== null) {
                foreach ($desiredObject['fields'] as $field => $unused) {
                    if ($field === 'target_logical_id') {
                        $semantic[$field] = $pipeTargetMap[$record['raw_fields']['target'] ?? ''] ??
                            ($record['raw_fields']['target'] ?? '');
                    } else {
                        $semantic[$field] = $this->normalizeActualValue(
                            $field,
                            $record['raw_fields'][$field] ?? '',
                            $record['category_uuid']
                        );
                    }
                }
            } else {
                $semantic = $this->normalizeAllFields(
                    $record['raw_fields'],
                    $record['category_uuid'],
                    $pipeTargetMap
                );
            }
            $allFields = $this->normalizeAllFields(
                $record['raw_fields'],
                $record['category_uuid'],
                $pipeTargetMap
            );
            $allocation = [];
            if ($record['core_type'] === 'pipe') {
                $allocation['number'] = $record['raw_fields']['number'] ?? '';
                unset($allFields['number']);
            } elseif (in_array($record['core_type'], ['filter_rule', 'shaper_rule'], true)) {
                $allocation['sequence'] = $record['raw_fields']['sequence'] ?? '';
                unset($allFields['sequence']);
            }
            $snapshot = [
                'identity' => $record['identity'],
                'core_type' => $record['core_type'],
                'core_uuid' => $record['core_uuid'],
                'core_name' => $record['core_name'],
                'fields' => $semantic,
                'all_fields' => $allFields,
                'allocation' => $allocation,
                'semantic_fingerprint' => Canonical::fingerprint($semantic),
                'full_fingerprint' => Canonical::fingerprint([
                    'fields' => $allFields,
                    'allocation' => $allocation,
                ]),
                'owned' => $record['owned'],
                'ownership_intact' => $record['ownership_intact'],
            ];
            $result['by_uuid'][$record['core_type']][$record['core_uuid']] = $snapshot;
            if ($record['core_name'] !== '') {
                $result['by_name'][$record['core_type']][$record['core_name']] = $snapshot;
            }
            if ($record['owned']) {
                $result['owned'][] = $snapshot;
            }
        }
        if (Platform::usesRuntimeFilterRegistry()) {
            foreach ($managed as $identity => $record) {
                if ($record['core_type'] !== 'filter_rule') {
                    continue;
                }
                $snapshot = $this->virtualActualFromManaged($identity, $record);
                if ($snapshot['core_name'] !== '') {
                    $result['by_name']['filter_rule'][$snapshot['core_name']] = $snapshot;
                }
                $result['owned'][] = $snapshot;
            }
        }
        return $result;
    }

    private function virtualActualFromDesired($identity, $object)
    {
        $fields = $object['fields'] ?? [];
        $allocation = $object['allocation'] ?? [];
        return [
            'identity' => 'filter_rule:runtime:' . hash('sha256', (string)$identity),
            'core_type' => 'filter_rule',
            'core_uuid' => '',
            'core_name' => $object['core_name'],
            'fields' => $fields,
            'all_fields' => $fields,
            'allocation' => $allocation,
            'semantic_fingerprint' => $object['fingerprint'] ?? Canonical::fingerprint($fields),
            'full_fingerprint' => Canonical::fingerprint([
                'fields' => $fields,
                'allocation' => $allocation,
            ]),
            'owned' => true,
            'ownership_intact' => true,
        ];
    }

    private function virtualActualFromManaged($identity, $record)
    {
        $state = json_decode($record['applied_state'] ?? '', true);
        $fields = is_array($state['fields'] ?? null) ? $state['fields'] : [];
        $allocation = is_array($state['allocation'] ?? null) ? $state['allocation'] : [];
        $snapshot = $this->virtualActualFromDesired($identity, [
            'core_name' => $record['core_name'],
            'fields' => $fields,
            'allocation' => $allocation,
            'fingerprint' => $record['desired_fingerprint'] ?: Canonical::fingerprint($fields),
        ]);
        if (!empty($record['applied_fingerprint'])) {
            $snapshot['full_fingerprint'] = $record['applied_fingerprint'];
        }
        return $snapshot;
    }

    private function allocateDesired(&$desired, $raw, $managed)
    {
        $flat = $this->planner->flattenDesired($desired);
        $desiredByName = [];
        foreach ($flat as $identity => $entry) {
            $desiredByName[$entry['object']['core_type']][$entry['object']['core_name']] = $identity;
        }

        foreach (['filter_rule', 'shaper_rule'] as $coreType) {
            $used = [];
            foreach ($raw as $record) {
                if ($record['core_type'] !== $coreType) {
                    continue;
                }
                if (!$record['owned']) {
                    $sequence = (int)($record['raw_fields']['sequence'] ?? 0);
                    if ($sequence > 0) {
                        $used[$sequence] = true;
                    }
                }
            }
            $entries = [];
            foreach ($flat as $identity => $entry) {
                if ($entry['object']['core_type'] === $coreType) {
                    $entries[$identity] = $entry;
                }
            }
            uasort($entries, function ($left, $right) {
                return [($left['object']['order'] ?? 0), $left['logical_id']] <=>
                    [($right['object']['order'] ?? 0), $right['logical_id']];
            });
            $sequences = $this->allocateBlock($used, count($entries), 1, $coreType === 'filter_rule' ? 999999 : 1000000);
            $index = 0;
            foreach ($entries as $entry) {
                $desired[$entry['section']][$entry['logical_id']]['allocation'] = [
                    'sequence' => (string)$sequences[$index++],
                ];
            }
        }

        $used = [];
        $existing = [];
        $reserved = [];
        foreach ($raw as $record) {
            if ($record['core_type'] !== 'pipe') {
                continue;
            }
            $number = (int)($record['raw_fields']['number'] ?? 0);
            if ($record['owned'] && isset($desiredByName['pipe'][$record['core_name']])) {
                $existing[$record['core_name']] = $number;
                if ($number > 0) {
                    $reserved[$number] = true;
                }
            } elseif (!$record['owned'] && $number > 0) {
                $used[$number] = true;
            }
        }
        $next = 10000;
        $pipeEntries = [];
        foreach ($flat as $entry) {
            if ($entry['object']['core_type'] === 'pipe') {
                $pipeEntries[] = $entry;
            }
        }
        usort($pipeEntries, fn($left, $right) => $left['logical_id'] <=> $right['logical_id']);
        foreach ($pipeEntries as $entry) {
            $name = $entry['object']['core_name'];
            $number = $existing[$name] ?? 0;
            if ($number > 0 && !isset($used[$number])) {
                unset($reserved[$number]);
            } else {
                while ((isset($used[$next]) || isset($reserved[$next])) && $next <= 65535) {
                    $next++;
                }
                if ($next > 65535) {
                    throw new UserException(gettext('No Traffic Shaper pipe numbers are available.'), gettext('Client Control'));
                }
                $number = $next++;
            }
            $used[$number] = true;
            $desired[$entry['section']][$entry['logical_id']]['allocation'] = ['number' => (string)$number];
        }
    }

    private function allocateBlock($used, $count, $minimum, $maximum)
    {
        if ($count === 0) {
            return [];
        }
        for ($start = $minimum; $start + $count - 1 <= $maximum; $start++) {
            $available = true;
            for ($offset = 0; $offset < $count; $offset++) {
                if (isset($used[$start + $offset])) {
                    $available = false;
                    $start += $offset;
                    break;
                }
            }
            if ($available) {
                return range($start, $start + $count - 1);
            }
        }
        throw new UserException(gettext('No contiguous rule sequence range is available.'), gettext('Client Control'));
    }

    private function orderedOperations($operations, $coreType, $reverse)
    {
        $result = array_values(array_filter(
            $operations,
            fn($operation) => $operation['core_type'] === $coreType
        ));
        usort($result, function ($left, $right) use ($reverse) {
            $comparison = [($left['desired']['order'] ?? 0), $left['identity']] <=>
                [($right['desired']['order'] ?? 0), $right['identity']];
            return $reverse ? -$comparison : $comparison;
        });
        return $result;
    }

    private function findNode($model, $coreType, $operation)
    {
        $path = [
            'category' => 'categories.category',
            'alias' => 'aliases.alias',
            'filter_rule' => 'rules.rule',
            'pipe' => 'pipes.pipe',
            'shaper_rule' => 'rules.rule',
        ][$coreType];
        if (!empty($operation['core_uuid'])) {
            $node = $model->getNodeByReference($path . '.' . $operation['core_uuid']);
            if ($node !== null) {
                return $node;
            }
        }
        $collection = $this->modelCollection($model, $coreType);
        foreach ($collection->iterateItems() as $node) {
            if (in_array($coreType, ['category', 'alias'], true)) {
                $name = (string)$node->name;
            } elseif (preg_match('/\bname=(CC_[A-Za-z0-9_]+)\b/', (string)$node->description, $matches)) {
                $name = $matches[1];
            } else {
                $name = '';
            }
            if ($name === $operation['core_name']) {
                return $node;
            }
        }
        return null;
    }

    private function modelCollection($model, $coreType)
    {
        if ($coreType === 'category') {
            return $model->categories->category;
        }
        if ($coreType === 'alias') {
            return $model->aliases->alias;
        }
        if ($coreType === 'pipe') {
            return $model->pipes->pipe;
        }
        return $model->rules->rule;
    }

    private function categoryUuid()
    {
        if ($this->categoryModel === null) {
            $this->categoryModel = new Category();
        }
        $node = $this->categoryModel->getByName(Compiler::CATEGORY);
        if ($node === null) {
            throw new UserException(gettext('ClientControl firewall category is missing.'), gettext('Client Control'));
        }
        return $node->getAttribute('uuid');
    }

    private function resolvedMacAddresses()
    {
        $result = [];
        try {
            $backend = new Backend();
            foreach (['arp', 'ndp'] as $kind) {
                $rows = json_decode($backend->configdRun('interface list ' . $kind . ' json'), true);
                foreach (is_array($rows) ? $rows : [] as $row) {
                    if (!is_array($row)) {
                        continue;
                    }
                    $mac = strtolower((string)($row['mac'] ?? ''));
                    $ip = (string)($row['ip'] ?? '');
                    if (filter_var($mac, FILTER_VALIDATE_MAC) !== false &&
                        filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                        $result[$mac][$ip] = true;
                    }
                }
            }
        } catch (\Throwable $error) {
            return [];
        }
        foreach ($result as $mac => $addresses) {
            $result[$mac] = array_keys($addresses);
            natcasesort($result[$mac]);
            $result[$mac] = array_values($result[$mac]);
        }
        return $result;
    }


    private function assertValid($model, $label, $fullModel = true, array $ignoredFields = [])
    {
        $errors = [];
        foreach ($model->performValidation($fullModel) as $message) {
            if (in_array($message->getField(), $ignoredFields, true)) {
                continue;
            }
            $errors[] = sprintf('%s: %s', $message->getField(), $message->getMessage());
        }
        if (!empty($errors)) {
            throw new UserException(
                sprintf("%s\n%s", $label, implode("\n", array_values(array_unique($errors)))),
                gettext('Client Control validation failed')
            );
        }
    }

    private function normalizeAllFields($fields, $categoryUuid, $pipeTargetMap)
    {
        $result = [];
        foreach ($fields as $field => $value) {
            if ($field === 'target') {
                $result['target_logical_id'] = $pipeTargetMap[$value] ?? $value;
            } elseif (!in_array($field, ['number', 'sequence'], true)) {
                $result[$field] = $this->normalizeActualValue($field, $value, $categoryUuid);
            }
        }
        ksort($result, SORT_STRING);
        return $result;
    }

    private function normalizeActualValue($field, $value, $categoryUuid)
    {
        if ($field !== 'categories' || $categoryUuid === '') {
            return (string)$value;
        }
        $tokens = array_filter(explode(',', (string)$value), 'strlen');
        foreach ($tokens as &$token) {
            if ($token === $categoryUuid) {
                $token = Compiler::CATEGORY;
            }
        }
        return implode(',', $tokens);
    }

    private function xmlItems($container, $tag)
    {
        if ($container === null || !isset($container->{$tag})) {
            return [];
        }
        return $container->{$tag};
    }

    private function containsToken($value, $token)
    {
        return $token !== '' && in_array($token, explode(',', (string)$value), true);
    }
}
