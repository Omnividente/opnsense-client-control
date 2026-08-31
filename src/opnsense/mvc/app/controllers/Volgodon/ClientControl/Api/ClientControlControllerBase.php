<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Base\UserException;
use OPNsense\Core\Config;
use Volgodon\ClientControl\ClientControl;
use Volgodon\ClientControl\Translations;

abstract class ClientControlControllerBase extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = ClientControl::class;
    private $clientControlModel;

    protected function getModel()
    {
        if ($this->clientControlModel === null) {
            $this->clientControlModel = new ClientControl();
        }
        return $this->clientControlModel;
    }

    protected function invalidateModel()
    {
        $this->clientControlModel = null;
    }


    public function beforeExecuteRoute($dispatcher)
    {
        $result = parent::beforeExecuteRoute($dispatcher);
        if ($result === false) {
            return false;
        }
        Translations::activate($this->langcode);
        return $result;
    }

    protected function lockModel()
    {
        Config::getInstance()->lock();
        $this->invalidateModel();
        return $this->getModel();
    }

    protected function unlockModel()
    {
        Config::getInstance()->unlock();
    }
    protected function requirePost()
    {
        if (!$this->request->isPost()) {
            throw new UserException(gettext('This operation requires POST.'), gettext('Client Control'));
        }
    }

    protected function assertRevision(ClientControl $model)
    {
        $expected = $this->request->getPost('revision');
        if ($expected === null) {
            $expected = $this->request->getHeader('X-Client-Control-Revision');
        }
        if (!preg_match('/^[0-9]+$/', (string)$expected) ||
            (string)$expected !== (string)$model->general->revision) {
            throw new UserException(
                gettext('The configuration changed after this page was loaded. Reload and retry.'),
                gettext('Client Control')
            );
        }
    }

    protected function finishMutation(ClientControl $model, $operation, $summary, $extra = [])
    {
        $previousRevision = ((int) (string) $model->general->revision);
        $model->general->revision = (string)(((int) (string) $model->general->revision) + 1);
        $model->appendAudit($this->getUserName(), $operation, $summary);
        $validation = $this->validate(null, null, true);
        if (!empty($validation['validations'])) {
            $model->general->revision = (string)$previousRevision;
            $this->invalidateModel();
            return $validation;
        }
        if (method_exists(ApiMutableModelControllerBase::class, 'setSaveAuditMessage')) {
            parent::setSaveAuditMessage(sprintf('Client Control: %s', $summary));
        }
        $this->save(false, true);
        return array_merge([
            'result' => 'saved',
            'revision' => ((int) (string) $model->general->revision),
        ], $extra);
    }

    protected function searchRecordsetBase(
        $records,
        $fields = null,
        $defaultSort = null,
        $filter = null,
        $sortFlags = SORT_NATURAL | SORT_FLAG_CASE,
        $searchClauses = null
    ) {
        $records = is_array($records) ? array_values($records) : [];
        $itemsPerPage = (int)$this->request->getPost('rowCount', 'int', 9999);
        $itemsPerPage = $itemsPerPage === -1 ? count($records) : max(1, $itemsPerPage);
        $currentPage = max(1, (int)$this->request->getPost('current', 'int', 1));
        if (!is_array($searchClauses)) {
            $phrase = trim((string)$this->request->getPost('searchPhrase', null, ''));
            $searchClauses = $phrase === '' ? [] : preg_split('/\s+/', $phrase);
        }

        $sortOrder = SORT_ASC;
        $sortKey = $defaultSort;
        $postedSort = $this->request->getPost('sort');
        if (is_array($postedSort) && !empty($postedSort)) {
            $sortKey = (string)array_key_first($postedSort);
            $sortOrder = $postedSort[$sortKey] === 'asc' ? SORT_ASC : SORT_DESC;
        }
        if ($sortKey !== null && $sortKey !== '' && !empty($records)) {
            foreach ($records as &$record) {
                if (!array_key_exists($sortKey, $record)) {
                    $record[$sortKey] = null;
                }
            }
            unset($record);
            $keys = array_column($records, $sortKey);
            array_multisort($keys, $sortOrder, $sortFlags, $records);
        }

        $records = array_values(array_filter($records, function ($record) use ($fields, $filter, $searchClauses) {
            if (is_callable($filter) && !$filter($record)) {
                return false;
            }
            foreach ($searchClauses as $clause) {
                $matched = false;
                foreach ($record as $field => $value) {
                    if ($fields !== null && !in_array($field, $fields, true)) {
                        continue;
                    }
                    if (is_array($value)) {
                        $flat = [];
                        array_walk_recursive($value, function ($item) use (&$flat) {
                            $flat[] = $item;
                        });
                        $value = implode(' ', $flat);
                    }
                    foreach ((array)$clause as $term) {
                        if (stripos((string)$value, (string)$term) !== false) {
                            $matched = true;
                            break 2;
                        }
                    }
                }
                if (!$matched) {
                    return false;
                }
            }
            return true;
        }));
        $offset = ($currentPage - 1) * $itemsPerPage;
        $rows = array_slice($records, $offset, $itemsPerPage);
        return [
            'total' => count($records),
            'rowCount' => count($rows),
            'current' => $currentPage,
            'rows' => $rows,
        ];
    }

    protected function getRequiredArray($name)
    {
        $value = $this->request->getPost($name);
        if (!is_array($value)) {
            throw new UserException(
                sprintf(gettext('The %s payload must be an object or list.'), $name),
                gettext('Client Control')
            );
        }
        return $value;
    }
}
