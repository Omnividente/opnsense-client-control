<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

use OPNsense\Base\IndexController as BaseIndexController;

class IndexController extends BaseIndexController
{
    public function beforeExecuteRoute($dispatcher)
    {
        $result = parent::beforeExecuteRoute($dispatcher);
        if ($result === false) {
            return false;
        }
        $this->translator = new PluginViewTranslator($this->langcode, $this->translator);
        $this->view->setVar('lang', $this->translator);
        return $result;
    }

    /**
     * Build UIBootgrid metadata on platforms predating ControllerBase::getFormGrid().
     */
    private function formGrid($formName)
    {
        if (method_exists(get_parent_class($this), 'getFormGrid')) {
            return parent::getFormGrid($formName);
        }

        $filename = __DIR__ . '/forms/' . $formName . '.xml';
        if (!file_exists($filename)) {
            throw new \RuntimeException('form xml ' . $filename . ' missing');
        }
        $formXml = simplexml_load_file($filename);
        if ($formXml === false) {
            throw new \RuntimeException('form xml ' . $filename . ' not valid');
        }

        $fields = [[
            'column-id' => 'uuid',
            'label' => 'ID',
            'type' => 'string',
            'identifier' => 'true',
            'visible' => 'false',
        ]];
        foreach ($formXml->field as $field) {
            if (empty((string)$field->id)) {
                continue;
            }
            $parts = explode('.', (string)$field->id);
            $record = [
                'column-id' => end($parts),
                'label' => gettext((string)$field->label),
                'visible' => 'true',
                'sortable' => 'true',
                'identifier' => 'false',
                'type' => 'string',
            ];
            if (isset($field->grid_view)) {
                foreach ($field->grid_view->children() as $key => $value) {
                    if ($key === 'ignore' && (string)$value !== 'false') {
                        continue 2;
                    }
                    $record[$key] = $key === 'label' ? gettext((string)$value) : (string)$value;
                }
            }
            $fields[] = $record;
        }

        return [
            'edit_dialog_id' => 'dialog_' . $formName,
            'fields' => $fields,
            'table_id' => $formName,
        ];
    }

    public function indexAction()
    {
        Translations::activate($this->langcode);
        try {
            $this->view->pick('Volgodon/ClientControl/index');
            $this->view->formGeneral = $this->getForm('general');

            $this->view->formDialogGroup = $this->getForm('dialogGroup');
            $this->view->formGridGroups = $this->formGrid('dialogGroup');

            $this->view->formDialogClient = $this->getForm('dialogClient');
            $this->view->formGridClients = $this->formGrid('dialogClient');

            $this->view->formDialogEndpoint = $this->getForm('dialogEndpoint');
            $this->view->formGridEndpoints = $this->formGrid('dialogEndpoint');
        } finally {
            Translations::restoreCoreDomain();
        }
    }
}
