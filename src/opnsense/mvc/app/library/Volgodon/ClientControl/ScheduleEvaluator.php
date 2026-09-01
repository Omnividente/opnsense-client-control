<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

use OPNsense\Core\Config;

final class ScheduleEvaluator
{
    public function isActive($name, $now = null, $config = null)
    {
        $name = trim((string)$name);
        if ($name === '') {
            return true;
        }
        $config = $config ?? Config::getInstance()->object();
        if (!($now instanceof \DateTimeInterface)) {
            $now = new \DateTimeImmutable('now', $this->configuredTimezone($config));
        }
        $schedule = $this->findSchedule($name, $config);
        return $schedule === null ? false : $this->scheduleIsActive($schedule, $now);
    }

    public function exists($name, $config = null)
    {
        $name = trim((string)$name);
        if ($name === '') {
            return true;
        }
        $config = $config ?? Config::getInstance()->object();
        return $this->findSchedule($name, $config) !== null;
    }

    public function timezoneName($config = null)
    {
        $config = $config ?? Config::getInstance()->object();
        return $this->configuredTimezone($config)->getName();
    }

    private function findSchedule($name, $config)
    {
        if (!isset($config->schedules->schedule)) {
            return null;
        }
        foreach ($config->schedules->schedule as $schedule) {
            if ((string)$schedule->name === (string)$name) {
                return $schedule;
            }
        }
        return null;
    }

    private function configuredTimezone($config)
    {
        $name = trim((string)($config->system->timezone ?? '')) ?: 'UTC';
        try {
            return new \DateTimeZone($name);
        } catch (\Throwable $error) {
            return new \DateTimeZone('UTC');
        }
    }

    private function scheduleIsActive($schedule, \DateTimeInterface $now)
    {
        if (!isset($schedule->timerange)) {
            return false;
        }
        foreach ($schedule->timerange as $range) {
            if (!$this->timeMatches((string)($range->hour ?? ''), $now)) {
                continue;
            }
            $positions = $this->csv((string)($range->position ?? ''));
            if (!empty($positions)) {
                if (in_array((string)$now->format('N'), $positions, true)) {
                    return true;
                }
                continue;
            }
            $months = $this->csv((string)($range->month ?? ''));
            $days = $this->csv((string)($range->day ?? ''));
            if (count($months) !== count($days)) {
                continue;
            }
            foreach ($days as $index => $day) {
                if ((int)$day === (int)$now->format('j') &&
                    (int)$months[$index] === (int)$now->format('n')) {
                    return true;
                }
            }
        }
        return false;
    }

    private function timeMatches($range, \DateTimeInterface $now)
    {
        $range = trim((string)$range);
        if ($range === '') {
            return true;
        }
        $parts = explode('-', $range, 2);
        if (count($parts) !== 2) {
            return false;
        }
        $start = $this->minutes($parts[0]);
        $end = $this->minutes($parts[1]);
        if ($start === null || $end === null) {
            return false;
        }
        $current = ((int)$now->format('G') * 3600) + ((int)$now->format('i') * 60) +
            (int)$now->format('s');
        $endSecond = $end === 24 * 60 ? $end * 60 : ($end * 60) + 59;
        return $current >= ($start * 60) && $current <= $endSecond;
    }

    private function minutes($value)
    {
        if (!preg_match('/^(?:([01]?\d|2[0-4])):([0-5]\d)$/', trim((string)$value), $matches)) {
            return null;
        }
        $hours = (int)$matches[1];
        $minutes = (int)$matches[2];
        if ($hours === 24 && $minutes !== 0) {
            return null;
        }
        return ($hours * 60) + $minutes;
    }

    private function csv($value)
    {
        return array_values(array_filter(array_map('trim', explode(',', (string)$value)), 'strlen'));
    }
}
