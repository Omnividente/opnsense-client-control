<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace Volgodon\ClientControl;

use OPNsense\Base\ViewTranslator;
use Phalcon\Translate\InterpolatorFactory;

final class PluginViewTranslator extends ViewTranslator
{
    private $fallback;

    public function __construct($langcode, ViewTranslator $fallback)
    {
        $this->fallback = $fallback;
        $locale = Translations::bind($langcode);
        parent::__construct(new InterpolatorFactory(), [
            'directory' => Translations::DIRECTORY,
            'defaultDomain' => Translations::DOMAIN,
            'locale' => [$locale],
        ]);
    }

    public function _($translateKey, array $placeholders = []): string
    {
        if (dgettext(Translations::DOMAIN, (string)$translateKey) === (string)$translateKey) {
            Translations::restoreCoreDomain();
            return $this->fallback->_($translateKey, $placeholders);
        }
        textdomain(Translations::DOMAIN);
        try {
            return parent::_($translateKey, $placeholders);
        } finally {
            Translations::restoreCoreDomain();
        }
    }
}
