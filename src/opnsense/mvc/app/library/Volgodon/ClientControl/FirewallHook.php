<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

final class FirewallHook
{
    private const PRIORITY = 399000;

    public function register($firewall, $model)
    {
        if (!((string) $model->general->enabled === (string) '1') ||
            !((string) $model->general->enforcement_mode === (string) 'enforce')) {
            return;
        }

        $desired = (new Compiler())->compile($model);
        $rules = array_values($desired['filter_rules']);
        usort($rules, function ($left, $right) {
            return [($left['order'] ?? 0), $left['core_name']] <=>
                [($right['order'] ?? 0), $right['core_name']];
        });

        $scheduleEvaluator = new ScheduleEvaluator();
        foreach ($rules as $rule) {
            $packetRate = 0;
            $packetRateSeconds = 0;
            $scheduleActive = true;
            if ($rule['owner_type'] === 'group') {
                $group = $model->getNodeByReference('groups.group.' . $rule['owner_uuid']);
                if ($group !== null) {
                    $packetRate = ((int) (string) $group->packet_rate);
                    $packetRateSeconds = ((int) (string) $group->packet_rate_seconds);
                    $scheduleActive = $scheduleEvaluator->isActive((string)$group->schedule);
                    if ($packetRate > 0 && !Platform::supportsPacketRate()) {
                        $scheduleActive = false;
                    }
                }
            }
            $firewall->registerFilterRule(
                self::PRIORITY,
                $this->ruleConfig(
                    $rule['fields'],
                    $rule['core_name'],
                    $packetRate,
                    $packetRateSeconds,
                    $scheduleActive
                )
            );
        }
    }

    public function ruleConfig(
        array $fields,
        $coreName,
        $packetRate = 0,
        $packetRateSeconds = 0,
        $scheduleActive = true
    ) {
        $config = [
            'disabled' => ($fields['enabled'] ?? '0') !== '1' || !$scheduleActive,
            'type' => (string)($fields['action'] ?? 'pass'),
            'quick' => ($fields['quick'] ?? '0') === '1',
            'interface' => (string)($fields['interface'] ?? ''),
            'direction' => (string)($fields['direction'] ?? 'in'),
            'ipprotocol' => (string)($fields['ipprotocol'] ?? 'inet46'),
            'from' => $this->runtimeAddress(
                (string)($fields['source_net'] ?? 'any'),
                ($fields['source_not'] ?? '0') === '1'
            ),
            'to' => $this->runtimeAddress(
                (string)($fields['destination_net'] ?? 'any'),
                ($fields['destination_not'] ?? '0') === '1'
            ),
            'log' => ($fields['log'] ?? '0') === '1',
            'statetype' => (string)($fields['statetype'] ?? 'keep'),
            'descr' => substr((string)($fields['description'] ?? $coreName) . ' runtime-guard', 0, 255),
            'label' => 'clientcontrol_' . substr(Canonical::fingerprint([
                'core_name' => (string)$coreName,
                'fields' => $fields,
                'packet_rate' => (int)$packetRate,
                'packet_rate_seconds' => (int)$packetRateSeconds,
            ]), 0, 32),
        ];

        $protocol = strtolower((string)($fields['protocol'] ?? ''));
        if ($protocol !== '' && $protocol !== 'any') {
            $config['protocol'] = $protocol;
        }
        foreach (['source_port' => 'from_port', 'destination_port' => 'to_port',
            'icmp6type' => 'icmp6-type', 'sched' => 'sched'] as $source => $target) {
            if (($fields[$source] ?? '') !== '') {
                $config[$target] = (string)$fields[$source];
            }
        }
        foreach (['max-src-states', 'max-src-conn', 'max-src-conn-rate', 'max-src-conn-rates'] as $field) {
            if (($fields[$field] ?? '') !== '') {
                $config[$field] = (string)$fields[$field];
            }
        }
        if ((int)$packetRate > 0 && (int)$packetRateSeconds > 0) {
            if (Platform::supportsPacketRate()) {
                $config['max-pkt-rate'] = sprintf('%d/%d', (int)$packetRate, (int)$packetRateSeconds);
            } else {
                $config['disabled'] = true;
            }
        }
        return $config;
    }

    private function runtimeAddress($value, $negated)
    {
        $value = trim((string)$value);
        if ($value === '') {
            $value = 'any';
        } elseif (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $value) && $value !== 'any') {
            $value = '$' . $value;
        }
        if ($negated && $value !== 'any') {
            $value = '!' . $value;
        }
        return $value;
    }
}
