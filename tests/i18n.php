<?php

use Volgodon\ClientControl\Translations;

function clientControlTranslationMsgids($root)
{
    $result = [];
    $sourceRoot = $root . '/src/opnsense/mvc/app';
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
        $sourceRoot,
        FilesystemIterator::SKIP_DOTS
    ));
    foreach ($iterator as $file) {
        $path = $file->getPathname();
        $extension = $file->getExtension();
        if ($extension === 'php' || $extension === 'volt') {
            $source = file_get_contents($path);
            $patterns = $extension === 'php' ? [
                "/\\bgettext\\(\\s*'((?:\\\\.|[^'])*)'\\s*\\)/s",
                "/(?:self::|Translations::)translate\\(\\s*'((?:\\\\.|[^'])*)'\\s*\\)/s",
            ] : [
                "/lang\\._\\(\\s*'((?:\\\\.|[^'])*)'\\s*\\)/s",
            ];
            foreach ($patterns as $pattern) {
                preg_match_all($pattern, $source, $matches);
                foreach ($matches[1] as $message) {
                    $result[stripcslashes($message)] = true;
                }
            }
        } elseif ($extension === 'xml') {
            $xml = simplexml_load_file($path);
            check($xml !== false, 'translation XML source must parse: ' . $path);
            foreach ($xml->xpath('//label|//help|//hint|//ValidationMessage|//description|//OptionValues/*') as $node) {
                $message = trim((string)$node);
                if ($message !== '') {
                    $result[$message] = true;
                }
            }
            if ($file->getBasename() === 'ACL.xml') {
                foreach ($xml->xpath('//name') as $node) {
                    $message = trim((string)$node);
                    if ($message !== '') {
                        $result[$message] = true;
                    }
                }
            }
            foreach ($xml->xpath('//@VisibleName|//@description') as $node) {
                $message = trim((string)$node);
                if ($message !== '') {
                    $result[$message] = true;
                }
            }
        }
    }
    ksort($result, SORT_STRING);
    return array_keys($result);
}

$translationRoot = dirname(__DIR__);
$po = $translationRoot . '/translations/ru_RU.po';
$mo = $translationRoot . '/src/share/locale/ru_RU/LC_MESSAGES/os-client-control.mo';
same(
    trim(file_get_contents($translationRoot . '/translations/ru_RU.po.sha256')),
    hash_file('sha256', $po),
    'the Russian PO digest must match its source'
);
same(
    trim(file_get_contents($translationRoot . '/translations/ru_RU.mo.sha256')),
    hash_file('sha256', $mo),
    'the compiled Russian catalog digest must be current'
);

$coreUiMessages = [
    'Add',
    'Add Favorite',
    'All',
    'Back',
    'Clear All',
    'Click to expand/collapse cell',
    'Clone',
    'Close',
    'Commands',
    'Delete selected',
    'Disable',
    'Edit',
    'Enable',
    'Info',
    'Maximize grid',
    'Minimize grid',
    'No results found',
    'Nothing selected',
    'Paste',
    'Please wait...',
    'Processing request...',
    'Refresh',
    'Remove Favorite',
    'Remove selected item(s)?',
    'Reset grid layout',
    'Save',
    'Search',
    'Search columns',
    'Select All',
    'Show system status',
    'Showing %s to %s',
    'Showing %s to %s of %s entries',
    'Text',
    'Toggle navigation',
    'Toggle sidebar',
    'advanced mode',
    'full help',
];
$messages = array_values(array_unique(array_merge(
    clientControlTranslationMsgids($translationRoot),
    $coreUiMessages
)));
sort($messages, SORT_STRING);
check(count($messages) >= 352, 'the localization inventory must include module and shared form strings');
$identityMessages = ['IP / MAC', 'IPv4', 'IPv6', 'MAC'];
putenv('LANGUAGE');
putenv('LANG=C');
check(setlocale(LC_MESSAGES, 'C') !== false, 'the C locale must be available for English fallback');
bindtextdomain(Translations::DOMAIN, $translationRoot . '/src/share/locale');
bind_textdomain_codeset(Translations::DOMAIN, 'UTF-8');
same(
    'Client Control',
    dgettext(Translations::DOMAIN, 'Client Control'),
    'English must fall back to source strings without a separate catalog'
);

putenv('LANGUAGE=ru_RU');
putenv('LANG=ru_RU.UTF-8');
check(setlocale(LC_MESSAGES, 'ru_RU.UTF-8') !== false, 'the Russian UTF-8 locale must be available');
foreach ($messages as $message) {
    $translated = dgettext(Translations::DOMAIN, $message);
    check($translated !== '', 'Russian translation must not be empty: ' . $message);
    if (!in_array($message, $identityMessages, true)) {
        check($translated !== $message, 'missing Russian translation: ' . $message);
    }
    preg_match_all('/%(?:\d+\$)?[sd]/', $message, $sourcePlaceholders);
    preg_match_all('/%(?:\d+\$)?[sd]/', $translated, $translatedPlaceholders);
    same(
        $sourcePlaceholders[0],
        $translatedPlaceholders[0],
        'translation placeholders must match: ' . $message
    );
}

same(
    'Добавлен клиент Test {uuid}.',
    Translations::auditSummary('client.add', 'added client Test {uuid}'),
    'audit summaries must be localized at response time'
);
same(
    'Создано: 2, Удалено: 1',
    Translations::countSummary('create=2, delete=1'),
    'apply count summaries must be localized'
);

textdomain('OPNsense');
