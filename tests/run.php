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
require_once __DIR__ . '/../src/opnsense/mvc/app/library/Volgodon/ClientControl/Platform.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/library/Volgodon/ClientControl/AuditLog.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/library/Volgodon/ClientControl/PlanFingerprint.php';

use Volgodon\ClientControl\Canonical;
use Volgodon\ClientControl\Compiler;
use Volgodon\ClientControl\Planner;
use Volgodon\ClientControl\FirewallHook;
use Volgodon\ClientControl\ScheduleEvaluator;
use Volgodon\ClientControl\Platform;
use Volgodon\ClientControl\AuditLog;
use Volgodon\ClientControl\PlanFingerprint;

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

same(200, AuditLog::CONFIG_LIMIT, 'config.xml must retain only the bounded recent audit fallback');
$auditTemp = tempnam(sys_get_temp_dir(), 'client-control-audit-');
if ($auditTemp === false || !unlink($auditTemp) || !mkdir($auditTemp, 0700)) {
    throw new RuntimeException('unable to create audit test directory');
}
try {
    $auditPath = $auditTemp . '/audit.log';
    $auditLog = new class($auditPath) extends AuditLog {
        public $filesRead = [];

        protected function readNewestFile($filename, $limit, array &$records, array &$known)
        {
            $this->filesRead[] = $filename;
            parent::readNewestFile($filename, $limit, $records, $known);
        }
    };
    $longSummary = str_repeat('full audit detail ', 32);
    $auditRecord = [
        'uuid' => '11111111-1111-4111-8111-111111111111',
        'timestamp' => '2026-09-01T00:00:00Z',
        'username' => 'operator',
        'operation' => 'service.rollback',
        'summary' => $longSummary,
        'result' => 'error',
    ];
    $auditLog->append([$auditRecord]);
    check($auditLog->probe(), 'audit storage health must verify readable and writable storage');
    same($longSummary, $auditLog->read()[0]['summary'],
        'the external audit log must preserve the complete summary');
    $auditLog->append([$auditRecord], true);
    same(1, count($auditLog->read()), 'migration retries must not duplicate audit UUIDs');
    $configOnly = [
        'uuid' => '22222222-2222-4222-8222-222222222222',
        'timestamp' => '2026-09-01T00:01:00Z',
        'username' => 'operator',
        'operation' => 'settings.set',
        'summary' => 'updated module settings',
        'result' => 'ok',
    ];
    $mergedAudit = $auditLog->merge([
        array_merge($auditRecord, ['summary' => AuditLog::compactSummary($longSummary)]),
        $configOnly,
    ]);
    same(2, count($mergedAudit), 'external and config audit records must merge by UUID');
    same($longSummary, $mergedAudit[0]['summary'],
        'the external full summary must take precedence over its config fallback');
    $compactSummary = AuditLog::compactSummary($longSummary);
    check(strlen($compactSummary) <= 255, 'the config audit fallback must remain bounded');
    check(str_ends_with($compactSummary, '...'), 'a truncated config summary must carry a marker');
    $newestRecord = array_merge($auditRecord, [
        'uuid' => '33333333-3333-4333-8333-333333333333',
        'timestamp' => '2026-09-01T00:02:00Z',
        'operation' => 'settings.set',
        'summary' => str_repeat('newest current detail ', 500),
        'result' => 'ok',
    ]);
    $auditLog->append([$newestRecord]);
    $rotatedOlder = array_merge($auditRecord, [
        'uuid' => '44444444-4444-4444-8444-444444444444',
        'timestamp' => '2025-12-30T00:00:00Z',
        'summary' => 'older rotated record',
    ]);
    $rotatedNewer = array_merge($auditRecord, [
        'uuid' => '55555555-5555-4555-8555-555555555555',
        'timestamp' => '2025-12-31T00:00:00Z',
        'summary' => 'newer rotated record',
    ]);
    $oldestRecord = array_merge($auditRecord, [
        'uuid' => '66666666-6666-4666-8666-666666666666',
        'timestamp' => '2025-01-01T00:00:00Z',
        'summary' => 'oldest generation record',
    ]);
    file_put_contents(
        $auditPath . '.0',
        json_encode($rotatedOlder) . "\n" . json_encode($rotatedNewer) . "\n"
    );
    file_put_contents($auditPath . '.1', json_encode($oldestRecord) . "\n");
    $boundedAudit = $auditLog->read(3);
    same(3, count($boundedAudit), 'interactive audit reads must stop at the requested window');
    same($newestRecord['uuid'], $boundedAudit[0]['uuid'],
        'bounded audit reads must start at the newest current-file record');
    same($newestRecord['summary'], $boundedAudit[0]['summary'],
        'bounded reverse reads must preserve a JSON record spanning multiple chunks');
    same($rotatedNewer['uuid'], $boundedAudit[2]['uuid'],
        'bounded audit reads must continue from the newest line in the next rotation');
    same([$auditPath, $auditPath . '.0'], $auditLog->filesRead,
        'bounded audit reads must not open generations older than the requested window');
    $boundedMerge = $auditLog->merge([
        array_merge($auditRecord, ['summary' => AuditLog::compactSummary($longSummary)]),
        $configOnly,
    ], 2);
    same([$newestRecord['uuid'], $configOnly['uuid']], array_column($boundedMerge, 'uuid'),
        'bounded audit merge must return the latest unique records across file and config fallbacks');
    $fullAudit = $auditLog->read();
    same(5, count($fullAudit), 'unbounded audit export reads must retain every generation');
    check(in_array($oldestRecord['uuid'], array_column($fullAudit, 'uuid'), true),
        'unbounded audit export must include the oldest retained generation');
    file_put_contents($auditTemp . '/not-a-directory', 'blocked');
    $probeFailed = false;
    try {
        (new AuditLog($auditTemp . '/not-a-directory/audit.log'))->probe();
    } catch (RuntimeException $error) {
        $probeFailed = true;
    }
    check($probeFailed, 'audit storage health must fail instead of reporting an unavailable path as healthy');
} finally {
    foreach (glob($auditTemp . '/*') ?: [] as $auditFile) {
        unlink($auditFile);
    }
    rmdir($auditTemp);
}

$postDeinstall = file_get_contents(__DIR__ . '/../+POST_DEINSTALL.post');
check(
    str_contains($postDeinstall, '/etc/newsyslog.conf.d/clientcontrol'),
    'package uninstall must remove the generated newsyslog entry while preserving audit files'
);
$lifecycleScripts = [
    file_get_contents(__DIR__ . '/../+POST_INSTALL.post'),
    file_get_contents(__DIR__ . '/../+PRE_DEINSTALL.pre'),
    $postDeinstall,
];
foreach ($lifecycleScripts as $lifecycleScript) {
    check(
        str_contains($lifecycleScript, '/usr/local/opnsense/mvc/app/cache/*volgodon_clientcontrol*.volt.php'),
        'package lifecycle must clear the installed OPNsense Volt cache path'
    );
    check(
        !str_contains($lifecycleScript, '/var/lib/php/cache/'),
        'package lifecycle must not rely on the obsolete Volt cache path'
    );
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

$platform = Platform::featureMatrix();
check(in_array($platform['filter_backend'], ['runtime_registry', 'persistent_model'], true),
    'platform capabilities must select an explicit firewall backend');
same($platform['filter_backend'] === 'persistent_model', $platform['packet_rate'],
    'packet-rate support must be explicit in the platform matrix');
$otherBackend = $platform['filter_backend'] === 'runtime_registry' ? 'persistent_model' : 'runtime_registry';
$platformTransition = Platform::featureMatrix($otherBackend);
same(true, $platformTransition['transition_pending'],
    'a capability-driven firewall backend transition must be visible');
check($platformTransition['warning'] !== '',
    'a firewall backend transition must include an operator warning');

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
same('unsupported_packet_rate', $packetRateDesired['warnings'][0]['reason'] ?? '',
    'an unsupported packet-rate limit must be an explicit plan conflict');
$packetRateConfig = (new FirewallHook())->ruleConfig(
    $packetRateRule['fields'],
    $packetRateRule['core_name'],
    120,
    3
);
same(true, $packetRateConfig['disabled'],
    'an unsupported packet-rate rule must fail closed rather than silently ignore the limit');
check(!isset($packetRateConfig['dn']),
    'packet-rate limits must never be misrouted through the traffic-shaper dn field');
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
$scheduleConfig->system = (object)['timezone' => 'Europe/Moscow'];
$scheduleEvaluator = new ScheduleEvaluator();
same('Europe/Moscow', $scheduleEvaluator->timezoneName($scheduleConfig),
    'schedule evaluation must use the configured firewall timezone');
same(true, $scheduleEvaluator->isActive(
    'WorkHours', new DateTimeImmutable('2026-08-31 09:00:00+03:00'), $scheduleConfig
), 'a weekly schedule must include its start time');
same(true, $scheduleEvaluator->isActive(
    'WorkHours', new DateTimeImmutable('2026-08-31 17:00:59+03:00'), $scheduleConfig
), 'a weekly schedule must include every second of its ending minute');
same(false, $scheduleEvaluator->isActive(
    'WorkHours', new DateTimeImmutable('2026-08-31 17:01:00+03:00'), $scheduleConfig
), 'a weekly schedule must expire after its ending minute');
same(true, $scheduleEvaluator->isActive(
    'Maintenance', new DateTimeImmutable('2026-08-31 23:00:00+03:00'), $scheduleConfig
), 'a calendar schedule must match its month and day');
same(false, $scheduleEvaluator->isActive(
    'Missing', new DateTimeImmutable('2026-08-31 12:00:00+03:00'), $scheduleConfig
), 'a deleted schedule must fail closed');
$endOfDayConfig = (object)[
    'schedules' => (object)[
        'schedule' => [(object)[
            'name' => 'AllDay',
            'timerange' => [(object)['position' => '1', 'hour' => '00:00-23:59']],
        ]],
    ],
];
same(true, $scheduleEvaluator->isActive(
    'AllDay', new DateTimeImmutable('2026-08-31 23:59:59+03:00'), $endOfDayConfig
), 'a 23:59 schedule boundary must include its final 59 seconds');
same(true, $scheduleEvaluator->isActive(
    '', new DateTimeImmutable('2026-08-31 12:00:00+03:00'), $scheduleConfig
), 'an empty schedule must remain unrestricted');
$missingScheduleState = moduleState(true, 'enforce', 'unlimited');
$missingScheduleState['groups']['11111111-1111-4111-8111-111111111111']['schedule'] = 'Deleted';
$missingScheduleState['groups']['11111111-1111-4111-8111-111111111111']['schedule_exists'] = false;
$missingSchedule = $compiler->compileState($missingScheduleState);
check(!isset($missingSchedule['filter_rules']['group:11111111-1111-4111-8111-111111111111:pass']),
    'a deleted schedule must remove the affected group allow rule');
check(isset($missingSchedule['filter_rules']['system:unknown-block']),
    'a deleted schedule must preserve the default deny rule');
same('missing_schedule', $missingSchedule['notices'][0]['reason'] ?? '',
    'a deleted schedule must be an explicit fail-closed plan notice');
$existingScheduleState = $missingScheduleState;
$existingScheduleState['groups']['11111111-1111-4111-8111-111111111111']['schedule_exists'] = true;
$existingSchedule = $compiler->compileState($existingScheduleState);
same($existingSchedule['fingerprint'], $missingSchedule['fingerprint'],
    'external schedule availability must not change the settings fingerprint');



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
same(8, $multiInterface['forecast']['shaper_rules'],
    'the plan forecast must expose the exact Traffic Shaper rule count');
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
check(!isset($override['aliases']['group:11111111-1111-4111-8111-111111111111:shaper']),
    'the compiler must not create an unused group shaper alias');
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
same($resolvedMac['fingerprint'], $unresolvedMac['fingerprint'],
    'runtime MAC resolution must not change the configuration fingerprint');
check($resolvedMac['runtime_fingerprint'] !== $unresolvedMac['runtime_fingerprint'],
    'runtime MAC resolution must remain visible in the runtime fingerprint');
$resolvedIntent = PlanFingerprint::intent(7, 'enforce', 'fail', $resolvedMac, [], []);
$unresolvedIntent = PlanFingerprint::intent(7, 'enforce', 'fail', $unresolvedMac, [], []);
same($resolvedIntent, $unresolvedIntent,
    'ARP resolution must not invalidate the configuration and managed-state plan intent');
$shaperRawA = [[
    'core_type' => 'shaper_rule',
    'core_uuid' => '33333333-3333-4333-8333-333333333333',
    'core_name' => 'CC_SHAPER',
    'owned' => true,
    'ownership_intact' => true,
    'raw_fields' => [
        'source' => '192.0.2.20',
        'destination' => 'any',
        'interface' => 'wan',
    ],
]];
$shaperRawB = $shaperRawA;
$shaperRawB[0]['raw_fields']['source'] = '192.0.2.21';
same(
    PlanFingerprint::intent(7, 'enforce', 'fail', $resolvedMac, [], $shaperRawA),
    PlanFingerprint::intent(7, 'enforce', 'fail', $resolvedMac, [], $shaperRawB),
    'ARP-derived addresses in actual shaper rules must not change the configuration intent'
);
$shaperRawB[0]['raw_fields']['interface'] = 'wan2';
check(
    PlanFingerprint::intent(7, 'enforce', 'fail', $resolvedMac, [], $shaperRawA) !==
        PlanFingerprint::intent(7, 'enforce', 'fail', $resolvedMac, [], $shaperRawB),
    'non-address changes in actual shaper rules must invalidate the configuration intent'
);
$filterRawA = [[
    'core_type' => 'filter_rule',
    'core_uuid' => '44444444-4444-4444-8444-444444444444',
    'core_name' => 'CC_FILTER',
    'owned' => true,
    'ownership_intact' => true,
    'raw_fields' => ['source' => 'CC_ALLOWED', 'destination' => 'any'],
]];
$filterRawB = $filterRawA;
$filterRawB[0]['raw_fields']['source'] = 'any';
check(
    PlanFingerprint::intent(7, 'enforce', 'fail', $resolvedMac, [], $filterRawA) !==
        PlanFingerprint::intent(7, 'enforce', 'fail', $resolvedMac, [], $filterRawB),
    'configured filter matches must remain part of the configuration intent'
);
$resolvedRuntimePlan = PlanFingerprint::runtime($resolvedIntent, $resolvedMac, [
    'operations' => array_values($resolvedMac['shaper_rules']),
    'conflicts' => [],
]);
$unresolvedRuntimePlan = PlanFingerprint::runtime($unresolvedIntent, $unresolvedMac, [
    'operations' => [],
    'conflicts' => [],
]);
check($resolvedRuntimePlan !== $unresolvedRuntimePlan,
    'ARP resolution changes must invalidate the exact runtime diff');
$changedActualIntent = PlanFingerprint::intent(7, 'enforce', 'fail', $resolvedMac, [], [[
    'core_type' => 'alias',
    'core_uuid' => '33333333-3333-4333-8333-333333333333',
    'core_name' => 'CC_CHANGED',
    'raw_fields' => ['content' => '192.0.2.200'],
]]);
check($resolvedIntent !== $changedActualIntent,
    'actual managed-object changes must invalidate the plan intent');

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

$orphanedState = moduleState(true, 'enforce', 'unlimited');
$orphanedState['clients']['22222222-2222-4222-8222-222222222222']['group'] = '';
$orphanedDesired = $compiler->compileState($orphanedState);
check(isset($orphanedDesired['filter_rules']['system:unknown-block']),
    'an orphaned client must not prevent compilation of the default deny rule');
same([], array_filter($orphanedDesired['aliases'], function ($object) {
    return ($object['owner_type'] ?? '') === 'client';
}), 'an orphaned client must be excluded from compiled objects');
same('missing_group', $orphanedDesired['warnings'][0]['reason'] ?? '',
    'an orphaned client must produce an explicit plan warning');
$orphanedPlan = (new Planner())->build($orphanedDesired, [
    'by_uuid' => [], 'by_name' => [], 'owned' => [],
], [], 'fail');
same('conflict', $orphanedPlan['status'],
    'an orphaned client warning must block apply without removing runtime guards');


$planner = new Planner();
$desired = desiredFixture();
$emptyActual = ['by_uuid' => [], 'by_name' => [], 'owned' => []];
$createPlan = $planner->build($desired, $emptyActual, [], 'fail');
same('create', $createPlan['operations'][0]['action'], 'missing desired object must be created');
$ownedObjects = [];
foreach (['category', 'alias', 'pipe', 'shaper_rule', 'filter_rule'] as $index => $coreType) {
    $fields = ['name' => 'CC_DELETE_' . $index];
    $ownedObjects[] = [
        'identity' => $coreType . ':00000000-0000-4000-8000-' . str_pad((string)$index, 12, '0', STR_PAD_LEFT),
        'core_type' => $coreType,
        'core_uuid' => '00000000-0000-4000-8000-' . str_pad((string)$index, 12, '0', STR_PAD_LEFT),
        'core_name' => 'CC_DELETE_' . $index,
        'fields' => $fields,
        'allocation' => [],
        'semantic_fingerprint' => Canonical::fingerprint($fields),
        'full_fingerprint' => Canonical::fingerprint(['fields' => $fields, 'allocation' => []]),
        'owned' => true,
        'ownership_intact' => true,
    ];
}
$deletePlan = $planner->build([
    'categories' => [], 'aliases' => [], 'filter_rules' => [],
    'pipes' => [], 'shaper_rules' => [], 'fingerprint' => '',
], ['by_uuid' => [], 'by_name' => [], 'owned' => $ownedObjects], [], 'fail');
same(
    ['filter_rule', 'shaper_rule', 'pipe', 'alias', 'category'],
    array_column($deletePlan['operations'], 'core_type'),
    'managed objects must be deleted in reverse dependency order'
);


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
$modelDefinition = simplexml_load_file(
    __DIR__ . '/../src/opnsense/mvc/app/models/Volgodon/ClientControl/ClientControl.xml'
);
check($modelDefinition !== false, 'the Client Control model must be valid XML');
$modelVersion = (string)$modelDefinition->version;
same('1.0.3', $modelVersion, 'the external audit migration must advance the model version');
$modelVersionParts = array_map('intval', explode('.', $modelVersion));
for ($patchVersion = 1; $patchVersion <= $modelVersionParts[2]; $patchVersion++) {
    $migrationFile = sprintf(
        '%s/../src/opnsense/mvc/app/models/Volgodon/ClientControl/Migrations/M%d_%d_%d.php',
        __DIR__,
        $modelVersionParts[0],
        $modelVersionParts[1],
        $patchVersion
    );
    check(is_file($migrationFile), 'the model migration chain must include ' . basename($migrationFile));
}

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

$acl = simplexml_load_file(
    __DIR__ . '/../src/opnsense/mvc/app/models/Volgodon/ClientControl/ACL/ACL.xml'
);
check($acl !== false, 'the Client Control ACL must be valid XML');
$aclPatterns = ['clientcontrol-view' => [], 'clientcontrol-manage' => []];
foreach ($aclPatterns as $privilege => &$patterns) {
    foreach ($acl->$privilege->patterns->pattern as $pattern) {
        $patterns[] = (string)$pattern;
    }
}
unset($patterns);
$mutationPrefixes = ['add', 'set', 'del', 'toggle', 'bulk', 'copy', 'apply', 'reconcile'];
$apiControllerRoot = __DIR__ . '/../src/opnsense/mvc/app/controllers/Volgodon/ClientControl/Api';
foreach (glob($apiControllerRoot . '/*Controller.php') as $controllerFile) {
    if (basename($controllerFile) === 'ClientControlControllerBase.php') {
        continue;
    }
    $controller = strtolower(preg_replace('/Controller\.php$/', '', basename($controllerFile)));
    preg_match_all('/public\s+function\s+([A-Za-z0-9_]+)Action\s*\(/', file_get_contents($controllerFile), $actions);
    foreach ($actions[1] as $method) {
        $action = strtolower(preg_replace('/(?<!^)[A-Z]/', '_$0', $method));
        $route = 'api/clientcontrol/' . $controller . '/' . $action;
        $isMutation = false;
        foreach ($mutationPrefixes as $prefix) {
            if ($action === $prefix || str_starts_with($action, $prefix . '_')) {
                $isMutation = true;
                break;
            }
        }
        foreach ($aclPatterns as $privilege => $patterns) {
            $covered = false;
            foreach ($patterns as $pattern) {
                if (fnmatch($pattern, $route)) {
                    $covered = true;
                    break;
                }
            }
            if ($isMutation && $privilege === 'clientcontrol-view') {
                same(false, $covered, 'read-only ACL must not cover mutation route ' . $route);
            } else {
                check($covered, $privilege . ' ACL must cover route ' . $route);
            }
        }
    }
}

require __DIR__ . '/controller-load.php';

if (extension_loaded('gettext')) {
    require __DIR__ . '/i18n.php';
}

echo "ok {$assertions} assertions\n";
