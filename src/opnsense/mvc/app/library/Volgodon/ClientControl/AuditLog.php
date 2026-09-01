<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

use RuntimeException;

class AuditLog
{
    public const PATH = '/var/log/clientcontrol/audit.log';
    public const CONFIG_LIMIT = 200;

    private $path;

    public function __construct($path = self::PATH)
    {
        $this->path = (string)$path;
        if ($this->path === '') {
            throw new RuntimeException('Audit log path cannot be empty.');
        }
    }

    /**
     * Append structured records after their corresponding config change commits.
     * Migration callers enable de-duplication to make retries idempotent.
     */
    public function append(array $records, $deduplicate = false)
    {
        if ($records === []) {
            return;
        }
        $this->ensureStorage();

        $handle = @fopen($this->path, 'ab');
        if ($handle === false) {
            throw new RuntimeException('Unable to open the Client Control audit log.');
        }
        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            throw new RuntimeException('Unable to lock the Client Control audit log.');
        }
        try {
            $known = [];
            if ($deduplicate) {
                foreach ($this->read() as $record) {
                    $known[$this->recordKey($record)] = true;
                }
            }
            foreach ($records as $record) {
                $record = $this->normalize($record);
                if ($record === null) {
                    continue;
                }
                $key = $this->recordKey($record);
                if (isset($known[$key])) {
                    continue;
                }
                $line = json_encode(
                    $record,
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
                );
                if ($line === false) {
                    throw new RuntimeException('Unable to encode a Client Control audit record.');
                }
                $this->writeAll($handle, $line . "\n");
                $known[$key] = true;
            }
            if (!fflush($handle)) {
                throw new RuntimeException('Unable to flush the Client Control audit log.');
            }
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
        @chmod($this->path, 0640);
    }

    /**
     * Verify that the current process can read, lock, and append to storage.
     */
    public function probe()
    {
        $this->ensureStorage();
        $handle = @fopen($this->path, 'c+b');
        if ($handle === false) {
            throw new RuntimeException('Unable to open the Client Control audit log for reading and writing.');
        }
        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            throw new RuntimeException('Unable to lock the Client Control audit log.');
        }
        try {
            if (!fflush($handle)) {
                throw new RuntimeException('Unable to flush the Client Control audit log.');
            }
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
        return true;
    }

    /**
     * Combine retained config records with the longer file-backed history.
     */
    public function merge(array $configRecords)
    {
        $records = [];
        $known = [];
        foreach (array_merge($this->read(), $configRecords) as $record) {
            $record = $this->normalize($record);
            if ($record === null) {
                continue;
            }
            $key = $this->recordKey($record);
            if (!isset($known[$key])) {
                $known[$key] = true;
                $records[] = $record;
            }
        }
        return $records;
    }

    /**
     * Read the current JSON-lines file and uncompressed newsyslog generations.
     */
    public function read()
    {
        $records = [];
        $known = [];
        foreach ($this->files() as $filename) {
            $handle = @fopen($filename, 'rb');
            if ($handle === false) {
                throw new RuntimeException('Unable to read the Client Control audit log.');
            }
            try {
                while (($line = fgets($handle)) !== false) {
                    $record = $this->normalize(json_decode(trim($line), true));
                    if ($record === null) {
                        continue;
                    }
                    $key = $this->recordKey($record);
                    if (!isset($known[$key])) {
                        $known[$key] = true;
                        $records[] = $record;
                    }
                }
            } finally {
                fclose($handle);
            }
        }
        return $records;
    }

    public static function compactSummary($summary, $limit = 255)
    {
        $summary = (string)$summary;
        $limit = max(1, (int)$limit);
        if (strlen($summary) <= $limit) {
            return $summary;
        }
        $marker = '...';
        if ($limit <= strlen($marker)) {
            return substr($summary, 0, $limit);
        }
        $prefixLength = $limit - strlen($marker);
        if (function_exists('mb_strcut')) {
            return rtrim(mb_strcut($summary, 0, $prefixLength, 'UTF-8')) . $marker;
        }
        return substr($summary, 0, $prefixLength) . $marker;
    }

    private function ensureStorage()
    {
        $directory = dirname($this->path);
        if (is_link($directory) || is_link($this->path)) {
            throw new RuntimeException('The Client Control audit path cannot be a symbolic link.');
        }
        if (!is_dir($directory) && !@mkdir($directory, 0751, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to create the Client Control audit directory.');
        }
        if ($this->path === self::PATH) {
            @chmod($directory, 0751);
            @chown($directory, 'root');
            @chgrp($directory, 'wheel');
        }

        if (!file_exists($this->path)) {
            $handle = @fopen($this->path, 'xb');
            if ($handle === false) {
                throw new RuntimeException('Unable to create the Client Control audit log.');
            }
            fclose($handle);
            if ($this->path === self::PATH && !@chown($this->path, 'wwwonly')) {
                @chown($this->path, 'www');
            }
            if ($this->path === self::PATH) {
                @chgrp($this->path, 'wheel');
            }
            @chmod($this->path, 0640);
        }
    }

    private function files()
    {
        $files = [];
        if (is_file($this->path)) {
            $files[] = $this->path;
        }
        $rotated = glob($this->path . '.*');
        if (is_array($rotated)) {
            usort($rotated, function ($left, $right) {
                return (int)substr(strrchr($left, '.'), 1) <=> (int)substr(strrchr($right, '.'), 1);
            });
            foreach ($rotated as $filename) {
                if (preg_match('/\.[0-9]+$/D', $filename) === 1 && is_file($filename)) {
                    $files[] = $filename;
                }
            }
        }
        return $files;
    }

    private function normalize($record)
    {
        if (!is_array($record) || !array_key_exists('timestamp', $record) ||
            !array_key_exists('operation', $record)) {
            return null;
        }
        return [
            'uuid' => (string)($record['uuid'] ?? ''),
            'timestamp' => (string)$record['timestamp'],
            'username' => (string)($record['username'] ?? ''),
            'operation' => (string)$record['operation'],
            'summary' => (string)($record['summary'] ?? ''),
            'result' => (string)($record['result'] ?? 'ok') === 'error' ? 'error' : 'ok',
        ];
    }

    private function recordKey(array $record)
    {
        if ($record['uuid'] !== '') {
            return 'uuid:' . $record['uuid'];
        }
        return 'hash:' . hash(
            'sha256',
            json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
        );
    }

    private function writeAll($handle, $payload)
    {
        $length = strlen($payload);
        $offset = 0;
        while ($offset < $length) {
            $written = fwrite($handle, substr($payload, $offset));
            if ($written === false || $written === 0) {
                throw new RuntimeException('Unable to write the Client Control audit log.');
            }
            $offset += $written;
        }
    }
}
