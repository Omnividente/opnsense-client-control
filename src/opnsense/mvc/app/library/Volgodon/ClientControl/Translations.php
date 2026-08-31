<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

final class Translations
{
    public const DOMAIN = 'os-client-control';
    public const DIRECTORY = '/usr/local/share/locale';

    public static function bind($langcode, $directory = self::DIRECTORY)
    {
        $locale = str_replace('-', '_', (string)$langcode);
        if (!str_ends_with(strtoupper($locale), '.UTF-8')) {
            $locale .= '.UTF-8';
        }
        bindtextdomain(self::DOMAIN, $directory);
        bind_textdomain_codeset(self::DOMAIN, 'UTF-8');
        return $locale;
    }

    public static function activate($langcode, $directory = self::DIRECTORY)
    {
        $locale = self::bind($langcode, $directory);
        putenv('LANG=' . $locale);
        setlocale(LC_MESSAGES, $locale);
        textdomain(self::DOMAIN);
    }

    public static function restoreCoreDomain()
    {
        textdomain('OPNsense');
    }

    public static function translate($message)
    {
        return dgettext(self::DOMAIN, (string)$message);
    }

    public static function countSummary($summary)
    {
        $summary = trim((string)$summary);
        if ($summary === 'no changes') {
            return self::translate('No changes.');
        }
        if ($summary === '') {
            return '';
        }

        $labels = [
            'create' => self::translate('Created'),
            'update' => self::translate('Updated'),
            'delete' => self::translate('Deleted'),
            'drop_record' => self::translate('Registry entries removed'),
        ];
        $parts = [];
        foreach (explode(',', $summary) as $part) {
            if (preg_match('/^\s*([a-z_]+)=(\d+)\s*$/', $part, $match) && isset($labels[$match[1]])) {
                $parts[] = sprintf('%s: %d', $labels[$match[1]], (int)$match[2]);
            } else {
                $parts[] = trim($part);
            }
        }
        return implode(', ', $parts);
    }

    public static function auditSummary($operation, $summary)
    {
        $operation = (string)$operation;
        $summary = (string)$summary;
        $match = [];

        switch ($operation) {
            case 'settings.set':
                return self::translate('Updated module settings.');
            case 'client.add':
                if (preg_match('/^added client (.*) \{([^{}]+)\}$/u', $summary, $match)) {
                    return sprintf(self::translate('Added client %s {%s}.'), $match[1], $match[2]);
                }
                break;
            case 'client.set':
                if (preg_match('/^updated client (.*) \{([^{}]+)\}$/u', $summary, $match)) {
                    return sprintf(self::translate('Updated client %s {%s}.'), $match[1], $match[2]);
                }
                break;
            case 'client.delete':
                if (preg_match('/^deleted (\d+) client\(s\)$/', $summary, $match)) {
                    return sprintf(self::translate('Deleted clients: %d.'), (int)$match[1]);
                }
                break;
            case 'client.toggle':
                if (preg_match('/^(enabled|disabled) client (.*) \{([^{}]+)\}$/u', $summary, $match)) {
                    if ($match[1] === 'enabled') {
                        return sprintf(self::translate('Enabled client %s {%s}.'), $match[2], $match[3]);
                    }
                    return sprintf(self::translate('Disabled client %s {%s}.'), $match[2], $match[3]);
                }
                break;
            case 'client.bulk_move':
                if (preg_match('/^moved (\d+) client\(s\) to group \{([^{}]+)\}$/', $summary, $match)) {
                    return sprintf(
                        self::translate('Moved clients: %d; target group {%s}.'),
                        (int)$match[1],
                        $match[2]
                    );
                }
                break;
            case 'client.bulk_toggle':
                if (preg_match('/^(enabled|disabled) (\d+) client\(s\)$/', $summary, $match)) {
                    if ($match[1] === 'enabled') {
                        return sprintf(self::translate('Enabled clients: %d.'), (int)$match[2]);
                    }
                    return sprintf(self::translate('Disabled clients: %d.'), (int)$match[2]);
                }
                break;
            case 'client.copy':
                if (preg_match(
                    '/^copied client (.*) \{([^{}]+)\} to disabled client \{([^{}]+)\} without endpoints$/u',
                    $summary,
                    $match
                )) {
                    return sprintf(
                        self::translate('Copied client %s {%s} to disabled client {%s} without endpoints.'),
                        $match[1],
                        $match[2],
                        $match[3]
                    );
                }
                break;
            case 'endpoint.add':
                if (preg_match('/^added endpoint \{([^{}]+)\} to client \{([^{}]+)\}$/', $summary, $match)) {
                    return sprintf(self::translate('Added endpoint {%s} to client {%s}.'), $match[1], $match[2]);
                }
                break;
            case 'endpoint.set':
                if (preg_match('/^updated endpoint \{([^{}]+)\}$/', $summary, $match)) {
                    return sprintf(self::translate('Updated endpoint {%s}.'), $match[1]);
                }
                break;
            case 'endpoint.delete':
                if (preg_match('/^deleted endpoint \{([^{}]+)\}$/', $summary, $match)) {
                    return sprintf(self::translate('Deleted endpoint {%s}.'), $match[1]);
                }
                break;
            case 'group.add':
                if (preg_match('/^added group (.*) \{([^{}]+)\}$/u', $summary, $match)) {
                    return sprintf(self::translate('Added group %s {%s}.'), $match[1], $match[2]);
                }
                break;
            case 'group.set':
                if (preg_match('/^updated group (.*) \{([^{}]+)\}$/u', $summary, $match)) {
                    return sprintf(self::translate('Updated group %s {%s}.'), $match[1], $match[2]);
                }
                break;
            case 'group.delete':
                if (preg_match(
                    '/^deleted group (.*) \{([^{}]+)\} and moved (\d+) client\(s\)$/u',
                    $summary,
                    $match
                )) {
                    return sprintf(
                        self::translate('Deleted group %s {%s}; moved clients: %d.'),
                        $match[1],
                        $match[2],
                        (int)$match[3]
                    );
                }
                break;
            case 'group.toggle':
                if (preg_match('/^(enabled|disabled) group (.*) \{([^{}]+)\}$/u', $summary, $match)) {
                    if ($match[1] === 'enabled') {
                        return sprintf(self::translate('Enabled group %s {%s}.'), $match[2], $match[3]);
                    }
                    return sprintf(self::translate('Disabled group %s {%s}.'), $match[2], $match[3]);
                }
                break;
            case 'group.copy':
                if (preg_match('/^copied group (.*) \{([^{}]+)\} to \{([^{}]+)\}$/u', $summary, $match)) {
                    return sprintf(
                        self::translate('Copied group %s {%s} to {%s}.'),
                        $match[1],
                        $match[2],
                        $match[3]
                    );
                }
                break;
            case 'import.apply':
                if (preg_match(
                    '/^imported aliases without modifying source objects: groups=(\d+) clients=(\d+) endpoints=(\d+)$/',
                    $summary,
                    $match
                )) {
                    return sprintf(
                        self::translate('Imported without changing source aliases: groups=%d, clients=%d, endpoints=%d.'),
                        (int)$match[1],
                        (int)$match[2],
                        (int)$match[3]
                    );
                }
                break;
            case 'service.apply':
                if (preg_match('/^applied revision (\d+): (.*)$/', $summary, $match)) {
                    return sprintf(
                        self::translate('Applied revision %d: %s'),
                        (int)$match[1],
                        self::countSummary($match[2])
                    );
                }
                break;
            case 'service.rollback':
                return sprintf(self::translate('Apply failed and was rolled back: %s'), $summary);
        }

        return $summary;
    }
}
