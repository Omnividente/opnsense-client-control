<?php

if (is_file('/usr/local/etc/inc/config.inc')) {
    require_once '/usr/local/etc/inc/config.inc';
    $appRoot = dirname(__DIR__) . '/src/opnsense/mvc/app';
    require_once $appRoot . '/library/Volgodon/ClientControl/PluginViewTranslator.php';
    require_once $appRoot . '/controllers/Volgodon/ClientControl/Api/ClientControlControllerBase.php';
    foreach (glob($appRoot . '/controllers/Volgodon/ClientControl/Api/*.php') as $controller) {
        require_once $controller;
    }
    require_once $appRoot . '/controllers/Volgodon/ClientControl/IndexController.php';
    check(
        is_subclass_of(
            Volgodon\ClientControl\IndexController::class,
            OPNsense\Base\IndexController::class
        ),
        'the Client Control page controller must load against the installed OPNsense API'
    );
    check(
        is_subclass_of(
            Volgodon\ClientControl\Api\ServiceController::class,
            Volgodon\ClientControl\Api\ClientControlControllerBase::class
        ),
        'all Client Control API controllers must load against the installed OPNsense API'
    );
    $indexReflection = new ReflectionClass(Volgodon\ClientControl\IndexController::class);
    $indexController = $indexReflection->newInstanceWithoutConstructor();
    $formGrid = $indexReflection->getMethod('formGrid');
    $formGrid->setAccessible(true);
    $clientGrid = $formGrid->invoke($indexController, 'dialogClient');
    same('dialogClient', $clientGrid['table_id'], 'the client grid must retain its form table identifier');
    same(
        'dialog_dialogClient',
        $clientGrid['edit_dialog_id'],
        'the client grid must retain its edit dialog identifier'
    );
    same('uuid', $clientGrid['fields'][0]['column-id'], 'the client grid must begin with the UUID identifier');
    $clientColumns = array_column($clientGrid['fields'], 'column-id');
    foreach (['name', 'group', 'endpoints_text', 'enabled'] as $column) {
        check(in_array($column, $clientColumns, true), 'the client grid must expose column ' . $column);
    }
}
