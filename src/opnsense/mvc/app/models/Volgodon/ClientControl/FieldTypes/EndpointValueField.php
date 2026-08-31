<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl\FieldTypes;

use OPNsense\Base\FieldTypes\BaseField;
use OPNsense\Base\Validators\CallbackValidator;

class EndpointValueField extends BaseField
{
    protected $internalIsContainer = false;

    public function setValue($value)
    {
        $value = strtolower(trim((string)$value));
        $mac = str_replace('-', ':', $value);
        if (filter_var($mac, FILTER_VALIDATE_MAC) !== false) {
            $value = $mac;
        } elseif (filter_var($value, FILTER_VALIDATE_IP) !== false) {
            $packed = inet_pton($value);
            if ($packed !== false) {
                $value = inet_ntop($packed);
            }
        }
        parent::setValue($value);
    }

    protected function defaultValidationMessage()
    {
        return gettext('Enter a valid address matching the selected endpoint type.');
    }

    public function getValidators()
    {
        $validators = parent::getValidators();
        if (!((string) $this === '')) {
            $validators[] = new CallbackValidator(['callback' => function ($data) {
                $kind = (string)$this->getParentNode()->kind;
                if ($kind === 'ipv4') {
                    $valid = filter_var($data, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
                } elseif ($kind === 'ipv6') {
                    $valid = filter_var($data, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
                } elseif ($kind === 'mac') {
                    $valid = filter_var($data, FILTER_VALIDATE_MAC) !== false;
                } else {
                    $valid = false;
                }
                return $valid ? [] : [$this->getValidationMessage()];
            }]);
        }
        return $validators;
    }
}
