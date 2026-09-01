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
    $previousMethod = $_SERVER['REQUEST_METHOD'] ?? null;
    $previousPost = $_POST;
    try {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $model = new Volgodon\ClientControl\ClientControl();
        $revision = (string)$model->general->revision;

        $_POST = [
            'revision' => $revision,
            'general' => [
                'destination_scope' => 'custom',
                'destination_alias' => 'CC_ALIAS_THAT_DOES_NOT_EXIST',
            ],
        ];
        $settingsController = $settingsReflection->newInstanceWithoutConstructor();
        $settingsController->request = new OPNsense\Mvc\Request();
        $settingsValidation = $settingsController->setAction();
        check(isset($settingsValidation['validations']['general.destination_alias']),
            'settings validation must use the exact form field identifier');
        check(!isset($settingsValidation['validations']['general.general.destination_alias']),
            'settings validation must not duplicate the model prefix');

        $_POST = ['revision' => $revision, 'group' => ['download' => '']];
        $groupsReflection = new ReflectionClass(Volgodon\ClientControl\Api\GroupsController::class);
        $groupsController = $groupsReflection->newInstanceWithoutConstructor();
        $groupsController->request = new OPNsense\Mvc\Request();
        $groupValidation = $groupsController->addGroupAction();
        check(isset($groupValidation['validations']['group.download']),
            'an empty group rate must return a field-level validation');
        check(str_contains(
            $groupValidation['validations']['group.download'],
            gettext('Download limit')
        ), 'the group rate validation must use a human field label');

        $_POST = ['revision' => $revision, 'client' => ['download_override' => '']];
        $clientsReflection = new ReflectionClass(Volgodon\ClientControl\Api\ClientsController::class);
        $clientsController = $clientsReflection->newInstanceWithoutConstructor();
        $clientsController->request = new OPNsense\Mvc\Request();
        $clientValidation = $clientsController->addClientAction();
        check(isset($clientValidation['validations']['client.download_override']),
            'an empty client override must return a field-level validation');
        check(str_contains(
            $clientValidation['validations']['client.download_override'],
            gettext('Client download limit')
        ), 'the client override validation must use a human field label');
    } finally {
        $_POST = $previousPost;
        if ($previousMethod === null) {
            unset($_SERVER['REQUEST_METHOD']);
        } else {
            $_SERVER['REQUEST_METHOD'] = $previousMethod;
        }
    }
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
    $auditLogResponse = $serviceReflection->getMethod('auditLogResponse');
    $auditLogResponse->setAccessible(true);
    $degradedAudit = $auditLogResponse->invoke($serviceController, false, 'audit unavailable');
    same('degraded', $degradedAudit['audit_log'],
        'a committed mutation must expose external audit degradation in its response');
    same('audit unavailable', $degradedAudit['audit_log_message'],
        'the audit degradation response must carry an operator-visible explanation');
    $shallowStatus = $serviceController->statusAction();
    check(!array_key_exists('conflicts', $shallowStatus),
        'the shallow status endpoint must not claim an empty deep conflict result');
    same(true, $shallowStatus['deep_check_required'],
        'the shallow status endpoint must direct callers to the explicit deep check');
    $diagnosticsReflection = new ReflectionClass(Volgodon\ClientControl\Api\DiagnosticsController::class);
    $diagnosticsController = $diagnosticsReflection->newInstanceWithoutConstructor();
    $diagnosticsController->request = new OPNsense\Mvc\Request();
    $auditPage = $diagnosticsController->auditAction();
    same(Volgodon\ClientControl\AuditLog::CONFIG_LIMIT, $auditPage['history_window'],
        'interactive audit API responses must declare their bounded history window');
    check(count($auditPage['rows']) <= Volgodon\ClientControl\AuditLog::CONFIG_LIMIT,
        'interactive audit API responses must not read past the bounded history window');
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
