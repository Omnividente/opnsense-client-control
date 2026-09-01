<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\Api;

use OPNsense\Base\UserException;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use Volgodon\ClientControl\AuditLog;
use Volgodon\ClientControl\ClientControl;
use Volgodon\ClientControl\Platform;
use Volgodon\ClientControl\Reconciler;
use Volgodon\ClientControl\Translations;

class ServiceController extends ClientControlControllerBase
{
    protected static $internalModelName = 'service';

    public function planAction()
    {
        $model = $this->lockModel();
        try {
            $invalid = $this->modelValidation($model);
            if (!empty($invalid)) {
                return [
                    'status' => 'invalid',
                    'revision' => ((int) (string) $model->general->revision),
                    'validations' => $invalid,
                ];
            }
            $strategy = $this->request->getPost('strategy', 'string', 'fail');
            return (new Reconciler($model))->plan($strategy);
        } finally {
            $this->unlockModel();
        }
    }

    public function applyAction()
    {
        $this->requirePost();
        $model = $this->lockModel();
        $mutating = false;
        $backup = null;
        $flushIpFw = false;
        try {
            $this->assertRevision($model);
            $invalid = $this->modelValidation($model);
            if (!empty($invalid)) {
                return [
                    'status' => 'invalid',
                    'revision' => ((int) (string) $model->general->revision),
                    'validations' => $invalid,
                ];
            }
            $strategy = $this->request->getPost('strategy', 'string', 'fail');
            $reconciler = new Reconciler($model);
            $plan = $reconciler->plan($strategy);
            $postedFingerprint = (string)$this->request->getPost('plan_fingerprint');
            if ($postedFingerprint === '' || !hash_equals($plan['plan_fingerprint'], $postedFingerprint)) {
                throw new UserException(
                    gettext('The configuration or managed objects changed. Review the current diff before applying.'),
                    gettext('Client Control')
                );
            }
            $postedRuntimeFingerprint = (string)$this->request->getPost('runtime_plan_fingerprint');
            if ($postedRuntimeFingerprint === '' ||
                !hash_equals($plan['runtime_plan_fingerprint'], $postedRuntimeFingerprint)) {
                throw new UserException(
                    gettext('Current network addresses changed after this plan was built. Review the current diff before applying.'),
                    gettext('Client Control')
                );
            }
            if ($plan['status'] !== 'ok') {
                throw new UserException(
                    gettext('The current plan contains managed-object conflicts.'),
                    gettext('Client Control')
                );
            }
            if (((string) $model->general->enabled === (string) '1') &&
                ((string) $model->general->enforcement_mode === (string) 'enforce') &&
                !hash_equals($plan['runtime_plan_fingerprint'], (string)$this->request->getPost('confirm_enforce'))) {
                throw new UserException(
                    gettext('Confirm the exact current diff before enabling enforcement.'),
                    gettext('Client Control')
                );
            }

            $backup = Config::getInstance()->backup();
            $mutating = true;
            $plan = $reconciler->apply($strategy, $plan);
            foreach ($plan['operations'] as $operation) {
                if ($operation['action'] === 'delete' &&
                    in_array($operation['core_type'], ['pipe', 'shaper_rule'], true)) {
                    $flushIpFw = true;
                    break;
                }
            }
            $model->general->last_applied_revision = (string)$model->general->revision;
            $model->general->last_apply_status = 'ok';
            $model->general->last_apply_message = $this->countSummary($plan['counts']);
            $model->general->last_apply_time = gmdate('c');
            $model->general->applied_filter_backend = Platform::featureMatrix()['filter_backend'];
            $model->appendAudit(
                $this->getUserName(),
                'service.apply',
                sprintf('applied revision %d: %s', ((int) (string) $model->general->revision), $this->countSummary($plan['counts']))
            );
            $invalid = $this->modelValidation($model);
            if (!empty($invalid)) {
                throw new UserException(implode("\n", $invalid), gettext('Client Control validation failed'));
            }
            $model->serializeToConfig(false, true);
            Config::getInstance()->save([
                'description' => sprintf('Client Control apply revision %d', ((int) (string) $model->general->revision)),
            ]);

            $runtime = $this->reloadRuntime($flushIpFw, $model);
            $verified = $this->verifyAppliedState($model, $reconciler->getResolvedMacs());
            $model->flushAuditLog();
            $verified['runtime'] = $runtime;
            $verified['plan'] = $plan;
            $verified['result'] = 'applied';
            return $verified;
        } catch (\Throwable $error) {
            $this->unlockModel();
            if ($mutating && $backup !== null) {
                $this->rollback($backup, $error);
            }
            throw $error;
        } finally {
            $this->unlockModel();
        }
    }

    public function reconcileAction()
    {
        return $this->applyAction();
    }

    public function statusAction()
    {
        $model = $this->lockModel();
        try {
            $counts = [];
            foreach ($model->managed_objects->object->iterateItems() as $object) {
                $type = (string)$object->core_type;
                $counts[$type] = ($counts[$type] ?? 0) + 1;
            }
            ksort($counts, SORT_STRING);
            $syncState = $model->getSyncState();
            $platform = Platform::featureMatrix((string)$model->general->applied_filter_backend);
            return [
                'status' => (string)$model->general->last_apply_status,
                'sync_state' => $syncState,
                'revision' => (int)(string)$model->general->revision,
                'last_applied_revision' => (int)(string)$model->general->last_applied_revision,
                'last_apply_time' => (string)$model->general->last_apply_time,
                'last_apply_message' => Translations::countSummary((string)$model->general->last_apply_message),
                'managed_objects' => $counts,
                'health_status' => in_array($syncState, ['error', 'conflict'], true) ? $syncState : 'ok',
                'conflicts' => [],
                'deep_check_required' => true,
                'platform' => $platform,
            ];
        } finally {
            $this->unlockModel();
        }
    }

    private function verifyAppliedState(ClientControl $model, array $resolvedMacs = [])
    {
        $plan = (new Reconciler($model, null, null, $resolvedMacs))->plan('fail');
        $unexpected = array_values(array_filter(
            $plan['operations'],
            fn($operation) => $operation['action'] !== 'noop'
        ));
        if ($plan['status'] !== 'ok' || !empty($unexpected)) {
            $details = array_map(
                fn($operation) => sprintf(
                    '%s:%s:%s',
                    $operation['action'],
                    $operation['core_type'],
                    $operation['core_name']
                ),
                $unexpected
            );
            throw new UserException(
                sprintf(
                    '%s%s',
                    gettext('Post-apply verification found a non-idempotent managed state.'),
                    empty($details) ? '' : ' ' . implode(', ', $details)
                ),
                gettext('Client Control')
            );
        }
        return [
            'verified' => true,
            'revision' => (int)(string)$model->general->revision,
            'managed_objects' => count($plan['operations']),
            'plan_fingerprint' => $plan['plan_fingerprint'],
            'runtime_plan_fingerprint' => $plan['runtime_plan_fingerprint'],
        ];
    }

    private function reloadRuntime($flushIpFw = false, ClientControl $model = null, $backend = null)
    {
        $backend = $backend ?? new Backend();
        $backend->configdRun('template reload OPNsense/Filter');
        $aliasOutput = trim($backend->configdRun('filter refresh_aliases'));
        $aliasResult = json_decode($aliasOutput, true);
        if (is_array($aliasResult) && !empty($aliasResult['messages'])) {
            throw new UserException(implode("\n", $aliasResult['messages']), gettext('Alias reload failed'));
        }
        $backend->configdRun('cron restart', true);

        $flush = 'not_required';
        if (Platform::usesLegacyShaperRuntime()) {
            $backend->configdRun('template reload OPNsense/IPFW');
            if ($flushIpFw) {
                $flush = trim($backend->configdRun('ipfw flush'));
                if ($flush !== 'OK') {
                    throw new UserException(sprintf(gettext('IPFW flush failed: %s'), $flush), gettext('Client Control'));
                }
            }
            $shaper = 'integrated_ipfw';
        } else {
            $backend->configdRun('template reload OPNsense/Shaper');
            $backend->configdRun('template reload OPNsense/IPFW');
            if ($flushIpFw) {
                $flush = trim($backend->configdRun('ipfw flush'));
                if ($flush !== 'OK') {
                    throw new UserException(sprintf(gettext('IPFW flush failed: %s'), $flush), gettext('Client Control'));
                }
            }
            $shaper = trim($backend->configdRun('shaper reload'));
            if ($shaper !== 'OK') {
                throw new UserException(sprintf(gettext('Traffic Shaper reload failed: %s'), $shaper), gettext('Client Control'));
            }
        }
        $ipfw = trim($backend->configdRun('ipfw reload'));
        if ($ipfw !== 'OK') {
            throw new UserException(sprintf(gettext('IPFW reload failed: %s'), $ipfw), gettext('Client Control'));
        }
        $filter = trim($backend->configdRun('filter reload skip_alias'));
        if ($filter !== 'OK') {
            throw new UserException(sprintf(gettext('Firewall reload failed: %s'), $filter), gettext('Client Control'));
        }
        $schedule = json_decode(trim($backend->configdRun('clientcontrol schedule')), true);
        if (!is_array($schedule) || ($schedule['status'] ?? '') !== 'ok') {
            throw new UserException(
                gettext('Client Control schedule state synchronization failed.'),
                gettext('Client Control')
            );
        }
        $guard = json_decode(trim($backend->configdRun('clientcontrol runtime_guard')), true);
        if (!is_array($guard) || ($guard['status'] ?? '') !== 'ok') {
            throw new UserException(gettext('Client Control runtime firewall guards failed verification.'), gettext('Client Control'));
        }
        return [
            'ipfw_flush' => $flush,
            'aliases' => 'ok',
            'shaper' => $shaper,
            'ipfw' => $ipfw,
            'filter' => $filter,
            'runtime_guard' => $guard['runtime_guard'] ?? 'unknown',
            'schedule' => $schedule,
        ];
    }

    private function rollback($backup, $error)
    {
        $rollbackError = null;
        // TING restoreBackup() opens and locks a second config descriptor; release our transaction lock first.
        Config::getInstance()->unlock();
        try {
            if (!Config::getInstance()->restoreBackup($backup)) {
                throw new \RuntimeException(gettext('Configuration restore returned false.'));
            }
            $this->reloadRuntime(true);
        } catch (\Throwable $failure) {
            $rollbackError = $failure;
        }

        try {
            Config::getInstance()->lock(true);
            $model = new ClientControl();
            $fullMessage = (string)$error->getMessage();
            if ($rollbackError !== null) {
                $fullMessage .= '; rollback: ' . $rollbackError->getMessage();
            }
            $message = AuditLog::compactSummary($fullMessage);
            $model->general->last_apply_status = 'error';
            $model->general->last_apply_message = $message;
            $model->general->last_apply_time = gmdate('c');
            $model->appendAudit($this->getUserName(), 'service.rollback', $fullMessage, 'error');
            $model->serializeToConfig(false, true);
            Config::getInstance()->save(['description' => 'Client Control apply rollback']);
            $model->flushAuditLog();
        } catch (\Throwable $statusError) {
            $this->getLogger('clientcontrol')->error('Unable to record rollback status: ' . $statusError->getMessage());
        } finally {
            Config::getInstance()->unlock();
        }
        if ($rollbackError !== null) {
            $this->getLogger('clientcontrol')->critical('Client Control rollback failed: ' . $rollbackError->getMessage());
        } else {
            $this->getLogger('clientcontrol')->error('Client Control apply rolled back: ' . $error->getMessage());
        }
    }

    private function modelValidation($model)
    {
        $result = [];
        foreach ($model->performValidation(true) as $message) {
            $result[$message->getField()] = $message->getMessage();
        }
        return $result;
    }

    private function countSummary($counts)
    {
        $parts = [];
        foreach ($counts as $action => $count) {
            if ($action !== 'noop' && $count > 0) {
                $parts[] = sprintf('%s=%d', $action, $count);
            }
        }
        return empty($parts) ? 'no changes' : implode(', ', $parts);
    }
}
