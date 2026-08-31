<?php

/*
 * Copyright (c) 2026 VOLGODON
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\Base\Messages\Message;
use Volgodon\ClientControl\ClientControl;
use Volgodon\ClientControl\FirewallHook;

function clientcontrol_firewall($firewall)
{
    if (file_exists('/var/run/clientcontrol-uninstalling')) {
        return;
    }
    try {
        (new FirewallHook())->register($firewall, new ClientControl());
    } catch (\Throwable $error) {
        syslog(LOG_ERR, 'Client Control firewall hook failed: ' . $error->getMessage());
        try {
            (new Message())->send('Client Control firewall hook failed: ' . $error->getMessage());
        } catch (\Throwable $ignored) {
        }
    }
}
