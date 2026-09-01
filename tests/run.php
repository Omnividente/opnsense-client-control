<?php

if (!function_exists('gettext')) {
    function gettext($message)
    {
        return $message;
    }
}

require_once __DIR__ . '/../src/opnsense/mvc/app/library/Volgodon/ClientControl/Canonical.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/library/Volgodon/ClientControl/Compiler.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/library/Volgodon/ClientControl/Planner.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/library/Volgodon/ClientControl/FirewallHook.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/library/Volgodon/ClientControl/ScheduleEvaluator.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/library/Volgodon/ClientControl/Translations.php';

use Volgodon\ClientControl\Canonical;
use Volgodon\ClientControl\Compiler;
use Volgodon\ClientControl\Planner;
use Volgodon\ClientControl\FirewallHook;
use Volgodon\ClientControl\ScheduleEvaluator;

$assertions = 0;

function check($condition, $message)
{
    global $assertions;
    $assertions++;
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function same($expected, $actual, $message)
{
    check($expected === $actual, $message . "\nexpected: " . var_export($expected, true) .
        "\nactual: " . var_export($actual, true));
}

function groupState($mode = 'unlimited')
{
    return [
        'enabled' => true,
        'name' => 'Default',
        'access' => 'allow',
        'shaping_mode' => $mode,
        'download' => $mode === 'unlimited' ? 0 : 100,
        'upload' => $mode === 'unlimited' ? 0 : 20,
        'metric' => 'Mbit',
        'schedule' => '',
        'max_states' => 0,
        'max_tcp_connections' => 0,
        'connection_rate' => 0,
        'connection_rate_seconds' => 0,
        'packet_rate' => 0,
        'packet_rate_seconds' => 0,
    ];
}

function clientState($groupUuid, $override = 'inherit')
{
    return [
        'enabled' => true,
        'name' => 'Laptop',
        'group' => $groupUuid,
        'access_override' => 'inherit',
        'shaping_override' => $override,
        'download_override' => $override === 'limited' ? 50 : 0,
        'upload_override' => $override === 'limited' ? 10 : 0,
        'metric_override' => 'Mbit',
        'endpoints' => [
            ['kind' => 'ipv4', 'value' => '192.0.2.10', 'label' => 'v4'],
            ['kind' => 'ipv6', 'value' => '2001:db8::10', 'label' => 'v6'],
        ],
    ];
}

function moduleState($enabled, $mode, $shapingMode = 'unlimited', $override = 'inherit')
{
    $groupUuid = '11111111-1111-4111-8111-111111111111';
    $clientUuid = '22222222-2222-4222-8222-222222222222';
    return [
        'general' => [
            'enabled' => $enabled,
            'protected_interfaces' => ['lan'],
            'wan_interfaces' => ['wan'],
            'enforcement_mode' => $mode,
            'destination_scope' => 'wan',
            'destination_alias' => '',
        ],
        'groups' => [$groupUuid => groupState($shapingMode)],
        'clients' => [$clientUuid => clientState($groupUuid, $override)],
    ];
}

function desiredFixture()
{
    $fields = ['name' => 'CC_TEST', 'enabled' => '1'];
    $object = [
        'owner_type' => 'system',
        'owner_uuid' => 'test',
        'core_type' => 'alias',
        'core_name' => 'CC_TEST',
        'fields' => $fields,
        'allocation' => [],
        'fingerprint' => Canonical::fingerprint($fields),
    ];
    return [
        'categories' => [],
        'aliases' => ['system:test' => $object],
        'filter_rules' => [],
        'pipes' => [],
        'shaper_rules' => [],
        'fingerprint' => Canonical::fingerprint(['aliases' => ['system:test' => $object]]),
    ];
}

function actualFixture($fields = null, $allocation = [], $owned = true)
{
    $fields = $fields ?? ['name' => 'CC_TEST', 'enabled' => '1'];
    $full = Canonical::fingerprint(['fields' => $fields, 'allocation' => $allocation]);
    $snapshot = [
        'identity' => 'alias:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        'core_type' => 'alias',
        'core_uuid' => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        'core_name' => 'CC_TEST',
        'fields' => $fields,
        'all_fields' => $fields,
        'allocation' => $allocation,
        'semantic_fingerprint' => Canonical::fingerprint($fields),
        'full_fingerprint' => $full,
        'owned' => $owned,
        'ownership_intact' => $owned,
    ];
    return [
        'snapshot' => $snapshot,
        'actual' => [
            'by_uuid' => ['alias' => [$snapshot['core_uuid'] => $snapshot]],
            'by_name' => ['alias' => ['CC_TEST' => $snapshot]],
            'owned' => $owned ? [$snapshot] : [],
        ],
    ];
}

function managedFixture($appliedFingerprint)
{
    return [
        'alias|system:test' => [
            'identity' => 'alias|system:test',
            'core_type' => 'alias',
            'core_uuid' => 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            'core_name' => 'CC_TEST',
            'applied_fingerprint' => $appliedFingerprint,
        ],
    ];
}

$compiler = new Compiler();

$disabled = $compiler->compileState(moduleState(false, 'observe', 'per_client'));
same([], $disabled['filter_rules'], 'disabled mode must not compile filter rules');
same([], $disabled['pipes'], 'disabled mode must not compile shaper pipes');
same([], $disabled['shaper_rules'], 'disabled mode must not compile shaper rules');
check(isset($disabled['aliases']['system:allowed']), 'disabled plan still exposes deterministic alias preview');

$observe = $compiler->compileState(moduleState(true, 'observe', 'per_client'));
same([], $observe['filter_rules'], 'observe mode must not compile enforcing filter rules');
same([], $observe['pipes'], 'observe mode must not enforce traffic shaping');
same([], $observe['shaper_rules'], 'observe mode must not compile shaper rules');
check(!empty($observe['preview_filter_rules']), 'observe mode must expose preview filter rules');

$enforce = $compiler->compileState(moduleState(true, 'enforce', 'per_client'));
foreach (['system:self-pass', 'system:dhcp4-pass', 'system:dhcp6-pass',
    'system:ipv6-control-pass', 'system:unknown-block'] as $logicalId) {
    check(isset($enforce['filter_rules'][$logicalId]), "missing safety rule: {$logicalId}");
}
same('1,2,3,4,130,131,132,133,134,135,136,137',
    $enforce['filter_rules']['system:ipv6-control-pass']['fields']['icmp6type'],
    'IPv6 safety rule must use the numeric values stored by the OPNsense filter model');
check(isset($enforce['pipes']['group:11111111-1111-4111-8111-111111111111:download']),
    'per-client mode must allocate one group download pipe');
same('dst-ip', $enforce['pipes']['group:11111111-1111-4111-8111-111111111111:download']['fields']['mask'],
    'per-client download pipe must allocate an independent bucket per destination IP');
same('src-ip', $enforce['pipes']['group:11111111-1111-4111-8111-111111111111:upload']['fields']['mask'],
    'per-client upload pipe must allocate an independent bucket per source IP');
same(2, count($enforce['pipes']), 'a limited per-client group must compile exactly two pipes');
same(2, count($enforce['shaper_rules']), 'a limited per-client group must compile exactly two shaper rules');
same('192.0.2.10,2001:db8::10',
    $enforce['shaper_rules']['group:11111111-1111-4111-8111-111111111111:download:wan:lan']['fields']['destination'],
    'group download shaper rule must contain literal endpoint addresses accepted by Traffic Shaper');
same('192.0.2.10,2001:db8::10',
    $enforce['shaper_rules']['group:11111111-1111-4111-8111-111111111111:upload:wan:lan']['fields']['source'],
    'group upload shaper rule must contain literal endpoint addresses accepted by Traffic Shaper');
check(!isset($enforce['pipes']['client:22222222-2222-4222-8222-222222222222:download']),
    'an inherited per-client policy must not allocate a dedicated client pipe');
$packetRateState = moduleState(true, 'enforce', 'unlimited');
$packetRateState['groups']['11111111-1111-4111-8111-111111111111']['packet_rate'] = 120;
$packetRateState['groups']['11111111-1111-4111-8111-111111111111']['packet_rate_seconds'] = 3;
$packetRateDesired = $compiler->compileState($packetRateState);
$packetRateRule = $packetRateDesired['filter_rules'][
    'group:11111111-1111-4111-8111-111111111111:pass'
];
check(!isset($packetRateRule['fields']['max-pkt-rate-number']),
    'portable managed rules must not use fields missing from the installed OPNsense model');
check(strpos($packetRateRule['fields']['description'], 'packet_rate=120/3') !== false,
    'the managed-rule diff must expose the exact runtime packet-rate value');
$packetRateConfig = (new FirewallHook())->ruleConfig(
    $packetRateRule['fields'],
    $packetRateRule['core_name'],
    120,
    3
);
same('max-pkt-rate 120/3', $packetRateConfig['dn'],
    'the early runtime rule must enforce the configured packet rate');
same('$CC_G_111111111111', $packetRateConfig['from'],
    'the runtime rule must preserve the deterministic group alias');
same(true, $packetRateConfig['quick'], 'the early runtime rule must stop later broad allow rules');
$samePacketRateConfig = (new FirewallHook())->ruleConfig(
    $packetRateRule['fields'],
    $packetRateRule['core_name'],
    120,
    3
);
same($packetRateConfig['label'], $samePacketRateConfig['label'],
    'identical runtime rule semantics must produce the same verification label');
$changedPacketRateFields = $packetRateRule['fields'];
$changedPacketRateFields['destination_net'] = '198.51.100.0/24';
$changedPacketRateConfig = (new FirewallHook())->ruleConfig(
    $changedPacketRateFields,
    $packetRateRule['core_name'],
    120,
    3
);
check($packetRateConfig['label'] !== $changedPacketRateConfig['label'],
    'runtime verification labels must change when enforced rule semantics change');

$scheduleConfig = (object)[
    'schedules' => (object)[
        'schedule' => [
            (object)[
                'name' => 'WorkHours',
                'timerange' => [
                    (object)['position' => '1,2,3,4,5', 'hour' => '09:00-17:00'],
                ],
            ],
            (object)[
                'name' => 'Maintenance',
                'timerange' => [
                    (object)['month' => '8', 'day' => '31', 'hour' => '22:00-24:00'],
                ],
            ],
        ],
    ],
];
$scheduleEvaluator = new ScheduleEvaluator();
same(true, $scheduleEvaluator->isActive(
    'WorkHours', new DateTimeImmutable('2026-08-31 09:00:00+03:00'), $scheduleConfig
), 'a weekly schedule must include its start time');
same(false, $scheduleEvaluator->isActive(
    'WorkHours', new DateTimeImmutable('2026-08-31 17:00:01+03:00'), $scheduleConfig
), 'a weekly schedule must expire immediately after its stop time');
same(true, $scheduleEvaluator->isActive(
    'Maintenance', new DateTimeImmutable('2026-08-31 23:00:00+03:00'), $scheduleConfig
), 'a calendar schedule must match its month and day');
same(false, $scheduleEvaluator->isActive(
    'Missing', new DateTimeImmutable('2026-08-31 12:00:00+03:00'), $scheduleConfig
), 'a deleted schedule must fail closed');
same(true, $scheduleEvaluator->isActive(
    '', new DateTimeImmutable('2026-08-31 12:00:00+03:00'), $scheduleConfig
), 'an empty schedule must remain unrestricted');


$shared = $compiler->compileState(moduleState(true, 'enforce', 'shared'));
check(isset($shared['pipes']['group:11111111-1111-4111-8111-111111111111:download']),
    'shared group mode must allocate one group download pipe');
check(!isset($shared['pipes']['client:22222222-2222-4222-8222-222222222222:download']),
    'inherited shared shaping must not allocate a client pipe');
same('none', $shared['pipes']['group:11111111-1111-4111-8111-111111111111:download']['fields']['mask'],
    'shared download pipe must use one unmasked bucket');
same('none', $shared['pipes']['group:11111111-1111-4111-8111-111111111111:upload']['fields']['mask'],
    'shared upload pipe must use one unmasked bucket');
same(2, count($shared['pipes']), 'a limited shared group must compile exactly two pipes');
same(2, count($shared['shaper_rules']), 'a limited shared group must compile exactly two shaper rules');
$multiInterfaceState = moduleState(true, 'enforce', 'shared');
$multiInterfaceState['general']['protected_interfaces'] = ['lan', 'iot'];
$multiInterfaceState['general']['wan_interfaces'] = ['wan', 'wan2'];
$multiInterface = $compiler->compileState($multiInterfaceState);
same(8, count($multiInterface['shaper_rules']),
    'two protected and two WAN interfaces must compile both directions for all four paths');
foreach (['wan', 'wan2'] as $wanInterface) {
    foreach (['iot', 'lan'] as $protectedInterface) {
        $path = $wanInterface . ':' . $protectedInterface;
        $download = $multiInterface['shaper_rules'][
            'group:11111111-1111-4111-8111-111111111111:download:' . $path
        ]['fields'];
        same($wanInterface, $download['interface'], 'download path must receive on its WAN interface');
        same($protectedInterface, $download['interface2'], 'download path must transmit on its client interface');
        same('in', $download['direction'], 'download path must use Traffic Shaper inbound path matching');
        $upload = $multiInterface['shaper_rules'][
            'group:11111111-1111-4111-8111-111111111111:upload:' . $path
        ]['fields'];
        same($wanInterface, $upload['interface'], 'upload path must transmit on its WAN interface');
        same($protectedInterface, $upload['interface2'], 'upload path must receive on its client interface');
        same('out', $upload['direction'], 'upload path must use Traffic Shaper outbound path matching');
    }
}


$override = $compiler->compileState(moduleState(true, 'enforce', 'shared', 'limited'));
check(isset($override['pipes']['client:22222222-2222-4222-8222-222222222222:download']),
    'limited client override must allocate its own pipe');
check(strpos($override['aliases']['group:11111111-1111-4111-8111-111111111111:shaper']['fields']['content'],
    'CC_C_222222222222_IP') === false, 'limited override must be excluded from the shared group shaper alias');
same('192.0.2.10,2001:db8::10',
    $override['shaper_rules']['client:22222222-2222-4222-8222-222222222222:download:wan:lan']['fields']['destination'],
    'limited client override must compile a literal-address download match');

$macState = moduleState(true, 'enforce', 'shared');
$macState['clients']['22222222-2222-4222-8222-222222222222']['endpoints'] = [[
    'kind' => 'mac',
    'value' => '02:00:00:00:00:10',
    'label' => 'mac',
    'resolved_ips' => ['2001:db8::20', '192.0.2.20'],
]];
$resolvedMac = $compiler->compileState($macState);
same('192.0.2.20,2001:db8::20',
    $resolvedMac['shaper_rules']['group:11111111-1111-4111-8111-111111111111:download:wan:lan']['fields']['destination'],
    'resolved MAC endpoints must compile their current IP addresses into shaper rules');
$macState['clients']['22222222-2222-4222-8222-222222222222']['endpoints'][0]['resolved_ips'] = [];
$unresolvedMac = $compiler->compileState($macState);
same([], $unresolvedMac['pipes'], 'an unresolved MAC-only group must not create ineffective pipes');
same([], $unresolvedMac['shaper_rules'], 'an unresolved MAC-only group must not create ineffective shaper rules');

$unlimited = $compiler->compileState(moduleState(true, 'enforce', 'unlimited'));
same([], $unlimited['pipes'], 'unlimited groups must not compile pipes');
same([], $unlimited['shaper_rules'], 'unlimited groups must not compile shaper rules');

$blockedState = moduleState(true, 'enforce', 'unlimited');
$blockedState['groups']['11111111-1111-4111-8111-111111111111']['access'] = 'block';
$blocked = $compiler->compileState($blockedState);
same('', $blocked['aliases']['system:allowed']['fields']['content'],
    'blocked inherited clients must not be members of CC_ALLOWED');

$disabledState = moduleState(true, 'enforce', 'unlimited');
$disabledState['clients']['22222222-2222-4222-8222-222222222222']['enabled'] = false;
$disabledClient = $compiler->compileState($disabledState);
same('', $disabledClient['aliases']['system:allowed']['fields']['content'],
    'disabled clients must not be members of CC_ALLOWED');

$planner = new Planner();
$desired = desiredFixture();
$emptyActual = ['by_uuid' => [], 'by_name' => [], 'owned' => []];
$createPlan = $planner->build($desired, $emptyActual, [], 'fail');
same('create', $createPlan['operations'][0]['action'], 'missing desired object must be created');

$actual = actualFixture();
$managed = managedFixture($actual['snapshot']['full_fingerprint']);
$noopPlan = $planner->build($desired, $actual['actual'], $managed, 'fail');
same('noop', $noopPlan['operations'][0]['action'], 'matching managed object must be idempotent');

$unregistered = actualFixture(null, [], false);
$unregisteredPlan = $planner->build($desired, $unregistered['actual'], [], 'fail');
same('conflict', $unregisteredPlan['status'], 'an unregistered ownership marker must not authorize adoption');
same('name_or_uuid_collision', $unregisteredPlan['conflicts'][0]['reason'],
    'unregistered deterministic-name collision must be explicit');

$collision = actualFixture(null, [], false);
$collisionPlan = $planner->build($desired, $collision['actual'], [], 'fail');
same('conflict', $collisionPlan['status'], 'unmanaged deterministic-name collision must fail');
same('name_or_uuid_collision', $collisionPlan['conflicts'][0]['reason'], 'collision reason must be explicit');

$foreignFixture = actualFixture(null, [], false);
$foreignSnapshot = $foreignFixture['snapshot'];
$foreignSnapshot['core_name'] = 'FOREIGN_ALIAS';
$foreignActual = [
    'by_uuid' => ['alias' => [$foreignSnapshot['core_uuid'] => $foreignSnapshot]],
    'by_name' => ['alias' => ['FOREIGN_ALIAS' => $foreignSnapshot]],
    'owned' => [],
];
$foreignPlan = $planner->build($desired, $foreignActual, [], 'fail');
same(1, count($foreignPlan['operations']), 'unrelated unmanaged objects must not add cleanup operations');
same('create', $foreignPlan['operations'][0]['action'], 'unrelated unmanaged objects must remain untouched');

$emptyDesired = [
    'categories' => [],
    'aliases' => [],
    'filter_rules' => [],
    'pipes' => [],
    'shaper_rules' => [],
];
$markerLost = actualFixture(null, [], false);
$markerLostPlan = $planner->build($emptyDesired, $markerLost['actual'], $managed, 'restore');
same('conflict', $markerLostPlan['status'], 'lost ownership markers must block obsolete-object deletion');
same('ownership_marker_changed', $markerLostPlan['conflicts'][0]['reason'],
    'lost ownership marker conflict must be explicit');

$drifted = actualFixture(['name' => 'CC_TEST', 'enabled' => '0']);
$driftFail = $planner->build($desired, $drifted['actual'], $managed, 'fail');
same('conflict', $driftFail['status'], 'external drift must fail by default');
same('external_change', $driftFail['conflicts'][0]['reason'], 'drift reason must be explicit');

$driftRestore = $planner->build($desired, $drifted['actual'], $managed, 'restore');
same('update', $driftRestore['operations'][0]['action'], 'restore strategy must reset external drift');

$acceptRejected = false;
try {
    $planner->build($desired, $drifted['actual'], $managed, 'accept');
} catch (InvalidArgumentException $error) {
    $acceptRejected = true;
}
check($acceptRejected, 'external drift can only be preserved as a conflict or explicitly restored');

$generalForm = simplexml_load_file(
    __DIR__ . '/../src/opnsense/mvc/app/controllers/Volgodon/ClientControl/forms/general.xml'
);
check($generalForm !== false, 'the settings form must be valid XML');
$generalFieldIds = [];
foreach ($generalForm->field as $field) {
    $generalFieldIds[] = (string)$field->id;
}
check(
    !in_array('general.stale_neighbor_policy', $generalFieldIds, true),
    'the fixed stale-neighbor policy must not be serialized as an editable settings field'
);

require __DIR__ . '/controller-load.php';

if (extension_loaded('gettext')) {
    require __DIR__ . '/i18n.php';
}

echo "ok {$assertions} assertions\n";
