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
    $settingsReflection = new ReflectionClass(Volgodon\ClientControl\Api\SettingsController::class);
    $editableSettings = $settingsReflection->getReflectionConstant('EDITABLE_FIELDS')->getValue();
    check(
        !in_array('stale_neighbor_policy', $editableSettings, true),
        'the fixed stale-neighbor policy must not be mutable through the settings API'
    );
    $fakeBackend = function ($filterResult = 'OK') {
        return new class($filterResult) {
            public $commands = [];
            private $filterResult;

            public function __construct($filterResult)
            {
                $this->filterResult = $filterResult;
            }

            public function configdRun($action, $background = false)
            {
                $this->commands[] = $action;
                if ($action === 'filter refresh_aliases') {
                    return '{"messages":[]}';
                }
                if ($action === 'filter reload skip_alias') {
                    return $this->filterResult;
                }
                if (in_array($action, ['ipfw reload', 'shaper reload'], true)) {
                    return 'OK';
                }
                if ($action === 'clientcontrol schedule') {
                    return '{"status":"ok"}';
                }
                if ($action === 'clientcontrol runtime_guard') {
                    return '{"status":"ok","runtime_guard":"verified"}';
                }
                return '';
            }
        };
    };
    $serviceReflection = new ReflectionClass(Volgodon\ClientControl\Api\ServiceController::class);
    $serviceController = $serviceReflection->newInstanceWithoutConstructor();
    $reloadRuntime = $serviceReflection->getMethod('reloadRuntime');
    $reloadRuntime->setAccessible(true);
    $backend = $fakeBackend();
    $runtime = $reloadRuntime->invoke($serviceController, false, null, $backend);
    same('OK', $runtime['filter'], 'a successful runtime reload must verify the firewall result');
    $aliasPosition = array_search('filter refresh_aliases', $backend->commands, true);
    $filterPosition = array_search('filter reload skip_alias', $backend->commands, true);
    $ipfwPosition = array_search('ipfw reload', $backend->commands, true);
    check($aliasPosition !== false && $filterPosition !== false && $aliasPosition < $filterPosition,
        'aliases must refresh before the new filter ruleset is loaded');
    check($ipfwPosition !== false && $ipfwPosition < $filterPosition,
        'the filter ruleset must load after Traffic Shaper and IPFW runtime state');
    $reloadFailed = false;
    try {
        $reloadRuntime->invoke($serviceController, false, null, $fakeBackend('FAILED'));
    } catch (OPNsense\Base\UserException $error) {
        $reloadFailed = str_contains($error->getMessage(), 'Firewall reload failed');
    }
    check($reloadFailed, 'a failed filter reload must abort apply and enter rollback');
}
