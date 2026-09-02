{#
 # Copyright (c) 2026 VOLGODON
 # SPDX-License-Identifier: BSD-2-Clause
 #}

<style>
    .cc-status-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
    .cc-status-bar .label { font-size: 12px; padding: 6px 9px; }
    .cc-panel-actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
    .cc-console { max-height: 360px; overflow: auto; white-space: pre-wrap; word-break: break-word; margin: 0; }
    .cc-risk { border-left: 4px solid #f0ad4e; padding-left: 12px; }
    .cc-diff-table td, .cc-diff-table th { vertical-align: top !important; }
    .cc-diff-value { max-width: 420px; white-space: pre-wrap; word-break: break-word; }
    .cc-inline-form { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .cc-inline-form .form-control { width: auto; min-width: 180px; }
    .cc-section-intro { margin: 0 0 14px; color: #555; }
    .cc-technical { margin-top: 14px; }
    .cc-summary-counts { font-size: 15px; margin-bottom: 10px; }
</style>

<script>
'use strict';

$(document).ready(function () {
    const state = {
        revision: 0,
        lastPlan: null,
        deepCheckRevision: null,
        hasGroups: false,
        importPreview: null,
        auditLogDegraded: false,
        auditLogMessage: ''
    };

    const policyLabels = {
        allow: '{{ lang._('Allow') }}',
        block: '{{ lang._('Block') }}',
        unlimited: '{{ lang._('Unlimited') }}',
        per_client: '{{ lang._('Per client') }}',
        shared: '{{ lang._('Shared') }}'
    };

    const stateLabels = {
        unknown: '{{ lang._('Unknown') }}',
        never: '{{ lang._('Not applied yet') }}',
        ok: '{{ lang._('Active') }}',
        error: '{{ lang._('Error') }}',
        conflict: '{{ lang._('Changed outside Client Control') }}',
        pending: '{{ lang._('Changes not applied') }}',
        in_sync: '{{ lang._('Rules match settings') }}',
        invalid: '{{ lang._('Check the fields') }}'
    };
    const planStatusLabels = {
        ok: '{{ lang._('Ready') }}',
        conflict: '{{ lang._('Needs attention') }}',
        invalid: '{{ lang._('Check the settings') }}'
    };
    const metricLabels = {
        Kbit: '{{ lang._('Kbit/s') }}',
        Mbit: '{{ lang._('Mbit/s') }}',
        Gbit: '{{ lang._('Gbit/s') }}'
    };
    const actionLabels = {
        create: '{{ lang._('Create') }}',
        update: '{{ lang._('Update') }}',
        delete: '{{ lang._('Delete') }}',
        drop_record: '{{ lang._('Remove registry entry') }}',
        noop: '{{ lang._('No changes') }}',
        conflict: '{{ lang._('Conflict') }}'
    };
    const coreTypeLabels = {
        category: '{{ lang._('Category') }}',
        alias: '{{ lang._('Alias') }}',
        filter_rule: '{{ lang._('Firewall rule') }}',
        pipe: '{{ lang._('Traffic Shaper pipe') }}',
        shaper_rule: '{{ lang._('Traffic Shaper rule') }}',
        client: '{{ lang._('Client') }}'
    };
    const operationLabels = {
        'settings.set': '{{ lang._('Update module settings') }}',
        'client.add': '{{ lang._('Add client') }}',
        'client.set': '{{ lang._('Update client') }}',
        'client.delete': '{{ lang._('Delete clients') }}',
        'client.toggle': '{{ lang._('Enable or disable client') }}',
        'client.bulk_move': '{{ lang._('Move clients') }}',
        'client.bulk_toggle': '{{ lang._('Enable or disable clients') }}',
        'client.copy': '{{ lang._('Copy client') }}',
        'endpoint.add': '{{ lang._('Add address') }}',
        'endpoint.set': '{{ lang._('Update address') }}',
        'endpoint.delete': '{{ lang._('Delete address') }}',
        'group.add': '{{ lang._('Add group') }}',
        'group.set': '{{ lang._('Update group') }}',
        'group.delete': '{{ lang._('Delete group') }}',
        'group.toggle': '{{ lang._('Enable or disable group') }}',
        'group.copy': '{{ lang._('Copy group') }}',
        'import.apply': '{{ lang._('Import aliases') }}',
        'service.apply': '{{ lang._('Apply plan') }}',
        'service.rollback': '{{ lang._('Roll back failed apply') }}'
    };
    const resultLabels = {
        ok: '{{ lang._('Success') }}',
        error: '{{ lang._('Error') }}'
    };
    const aliasTypeLabels = {
        host: '{{ lang._('Host alias') }}',
        network: '{{ lang._('Network alias') }}',
        mac: '{{ lang._('MAC alias') }}',
        networkgroup: '{{ lang._('Alias group') }}'
    };

    function localizedTabulatorOptions() {
        return {
            locale: 'client-control',
            langs: {
                'client-control': {
                    pagination: {
                        page_size: '{{ lang._('Page size') }}',
                        page_title: '{{ lang._('Show page') }}',
                        first: '{{ lang._('First') }}',
                        first_title: '{{ lang._('First page') }}',
                        last: '{{ lang._('Last') }}',
                        last_title: '{{ lang._('Last page') }}',
                        prev: '{{ lang._('Previous') }}',
                        prev_title: '{{ lang._('Previous page') }}',
                        next: '{{ lang._('Next') }}',
                        next_title: '{{ lang._('Next page') }}',
                        all: '{{ lang._('All') }}',
                        counter: {
                            showing: '{{ lang._('Showing') }}',
                            of: '{{ lang._('of') }}',
                            rows: '{{ lang._('rows') }}',
                            pages: '{{ lang._('pages') }}'
                        }
                    }
                }
            }
        };
    }

    function localizeGeneratedControls(root) {
        const controls = $(root).find('*').addBack();
        controls.filter('input[aria-label="Select Row"]')
            .attr('aria-label', '{{ lang._('Select row') }}');
        controls.filter('.bs-searchbox input[aria-label="Search"]')
            .attr('aria-label', '{{ lang._('Search') }}');
    }

    const generatedControlObserver = new MutationObserver(function (mutations) {
        mutations.forEach(function (mutation) {
            mutation.addedNodes.forEach(function (node) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    applyNumericConstraints(node);
                    localizeGeneratedControls(node);
                }
            });
        });
    });
    generatedControlObserver.observe(document.body, {childList: true, subtree: true});
    localizeGeneratedControls(document);

    function translatedLabel(labels, value) {
        return labels[value] || value || '';
    }

    function escapeHtml(value) {
        return $('<div/>').text(value === null || value === undefined ? '' : String(value)).html();
    }

    function renderJson(value) {
        return JSON.stringify(value === undefined ? null : value, null, 2);
    }
    const planChangeLimit = 250;
    const planDiffCharacterLimit = 4000;

    function renderJsonLimited(value, characterLimit) {
        const rendered = renderJson(value);
        return rendered.length <= characterLimit
            ? rendered
            : rendered.slice(0, characterLimit) + '\n… {{ lang._('Output truncated.') }}';
    }

    function renderTechnicalPlan(plan) {
        const technical = Object.assign({}, plan);
        const operations = plan.operations || [];
        technical.operations = operations.slice(0, planChangeLimit);
        if (operations.length > technical.operations.length) {
            technical.operations_truncated = operations.length - technical.operations.length;
        }
        return renderJson(technical);
    }


    function formatDateTime(value) {
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
    }

    function downloadJson(filename, value) {
        const blob = new Blob([renderJson(value) + '\n'], {type: 'application/json;charset=utf-8'});
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
    }
    const numericFields = {
        'group.download': [0, 1000000],
        'group.upload': [0, 1000000],
        'group.max_states': [0, 2147483647],
        'group.max_tcp_connections': [0, 2147483647],
        'group.connection_rate': [0, 4294967],
        'group.connection_rate_seconds': [0, 2147483647],
        'group.packet_rate': [0, 4294967],
        'group.packet_rate_seconds': [0, 2147483647],
        'client.download_override': [0, 1000000],
        'client.upload_override': [0, 1000000]
    };

    function applyNumericConstraints(root) {
        Object.entries(numericFields).forEach(function (entry) {
            const input = $(root).find('[id="' + entry[0] + '"]').addBack('[id="' + entry[0] + '"]');
            input.attr({type: 'number', min: entry[1][0], max: entry[1][1], step: 1, inputmode: 'numeric'});
        });
    }
    applyNumericConstraints(document);


    function setBanner(kind, message) {
        $('#cc-banner')
            .removeClass('alert-info alert-success alert-warning alert-danger')
            .addClass('alert-' + kind)
            .text(message)
            .show();
    }

    function updateAuditLogStatus(data) {
        if (data && data.audit_log === 'degraded') {
            state.auditLogDegraded = true;
            state.auditLogMessage = data.audit_log_message || '{{ lang._('The full audit history is unavailable. Only the bounded config.xml history is available.') }}';
        } else if (data && data.audit_log === 'ok') {
            state.auditLogDegraded = false;
            state.auditLogMessage = '';
        }
        $('#cc-audit-warning')
            .toggle(state.auditLogDegraded)
            .text(state.auditLogMessage);
        return state.auditLogDegraded;
    }

    function apiError(xhr) {
        let message = '{{ lang._('Request failed.') }}';
        if (xhr && xhr.responseJSON) {
            message = xhr.responseJSON.errorMessage || xhr.responseJSON.message || renderJson(xhr.responseJSON);
        } else if (xhr && xhr.responseText) {
            message = xhr.responseText;
        }
        setBanner('danger', message);
        const staleMessage = '{{ lang._('The configuration changed after this page was loaded. Reload and retry.') }}';
        if ((xhr && xhr.status === 409) || message.indexOf(staleMessage) !== -1) {
            state.lastPlan = null;
            state.deepCheckRevision = null;
            $('#apply-plan').prop('disabled', true);
            ajaxGet('/api/clientcontrol/service/status', {}, function (data) {
                if (data && data.revision !== undefined) {
                    state.revision = Number(data.revision);
                    $('#cc-revision').text(data.revision);
                }
            });
        }
    }

    function getJson(url, data) {
        return ajaxGet(url, data || {}, null).fail(apiError);
    }

    function queryJson(url, data) {
        return ajaxCall(url, data || {}, null).fail(apiError);
    }

    function postJson(url, data) {
        return ajaxCall(url, data || {}, null).fail(apiError);
    }

    $.ajaxPrefilter(function (options) {
        if ((options.type || '').toUpperCase() === 'POST' && options.url.indexOf('/api/clientcontrol/') === 0) {
            options.headers = options.headers || {};
            options.headers['X-Client-Control-Revision'] = String(state.revision);
        }
    });

    function accessFormatter(column, row) {
        const value = row[column.id] || '';
        return $('<span/>')
            .addClass(value === 'block' ? 'label label-danger' : 'label label-success')
            .text(policyLabels[value] || value)[0].outerHTML;
    }

    function shapingFormatter(column, row) {
        const value = row[column.id] || '';
        return $('<span/>')
            .addClass(value === 'unlimited' ? 'label label-success' : 'label label-info')
            .text(policyLabels[value] || value)[0].outerHTML;
    }
    function effectiveRateFormatter(column, row) {
        const value = Number(row[column.id] || 0);
        const unit = metricLabels[row.metric] || row.metric || '';
        return value > 0 ? escapeHtml(value + ' ' + unit) : '&mdash;';
    }

    function onlineFormatter(column, row) {
        return $('<span/>')
            .addClass(row.online ? 'label label-success' : 'label label-default')
            .text(row.online ? '{{ lang._('Online') }}' : '{{ lang._('Offline') }}')[0].outerHTML;
    }

    function syncFormatter(column, row) {
        const value = row[column.id] || '';
        return $('<span/>')
            .addClass(value === 'in_sync' ? 'label label-success' : 'label label-warning')
            .text(translatedLabel(stateLabels, value))[0].outerHTML;
    }

    const groupGrid = $("#{{ formGridGroups['table_id'] }}").UIBootgrid({
        search: '/api/clientcontrol/groups/search_group',
        get: '/api/clientcontrol/groups/get_group/',
        add: '/api/clientcontrol/groups/add_group',
        set: '/api/clientcontrol/groups/set_group/',
        del: '/api/clientcontrol/groups/del_group/',
        toggle: '/api/clientcontrol/groups/toggle_group/',
        tabulatorOptions: localizedTabulatorOptions(),
        commands: {
            delete: {
                title: '{{ lang._('Delete group') }}',
                method: function (event, cell) {
                    event.stopPropagation();
                    const uuid = $(event.currentTarget).data('row-id') || '';
                    const row = cell && cell.getRow ? cell.getRow().getData() : {};
                    prepareGroupDeletion(uuid, Number(row.members || 0));
                }
            },
            copy: {
                title: '{{ lang._('Copy group') }}',
                classname: 'fa fa-copy fa-fw',
                sequence: 15,
                method: function (event) {
                    const uuid = $(event.currentTarget).data('row-id') || '';
                    postJson('/api/clientcontrol/groups/copy_group/' + uuid, {
                        revision: state.revision
                    }).done(mutationSucceeded);
                }
            }
        },
        options: {
            selection: false,
            formatters: {
                access: accessFormatter,
                shaping: shapingFormatter,
                effectiveRate: effectiveRateFormatter,
                syncState: syncFormatter
            }
        }
    });

    const clientGrid = $("#{{ formGridClients['table_id'] }}").UIBootgrid({
        search: '/api/clientcontrol/clients/search_client',
        get: '/api/clientcontrol/clients/get_client/',
        add: '/api/clientcontrol/clients/add_client',
        set: '/api/clientcontrol/clients/set_client/',
        del: '/api/clientcontrol/clients/del_client/',
        toggle: '/api/clientcontrol/clients/toggle_client/',
        tabulatorOptions: localizedTabulatorOptions(),
        commands: {
            copy: {
                title: '{{ lang._('Copy client without addresses') }}',
                classname: 'fa fa-copy fa-fw',
                sequence: 15,
                method: function (event) {
                    const uuid = $(event.currentTarget).data('row-id') || '';
                    stdDialogConfirm(
                        '{{ lang._('Copy client') }}',
                        '{{ lang._('Create a copy without IP or MAC addresses? The copy will stay disabled.') }}',
                        '{{ lang._('Copy') }}',
                        '{{ lang._('Cancel') }}',
                        function () {
                            postJson('/api/clientcontrol/clients/copy_client/' + uuid, {
                                revision: state.revision
                            }).done(mutationSucceeded);
                        }
                    );
                }
            }
        },
        options: {
            formatters: {
                accessState: accessFormatter,
                effectiveRate: effectiveRateFormatter,
                onlineState: onlineFormatter,
                syncState: syncFormatter
            },
            requestHandler: function (request) {
                if ($('#client-filter-group').val()) {
                    request.group_uuid = $('#client-filter-group').val();
                }
                if ($('#client-filter-access').val()) {
                    request.access = $('#client-filter-access').val();
                }
                if ($('#client-filter-sync').val()) {
                    request.sync_state = $('#client-filter-sync').val();
                }
                return request;
            }
        }
    });

    const endpointGrid = $("#{{ formGridEndpoints['table_id'] }}").UIBootgrid({
        search: '/api/clientcontrol/clients/search_endpoints',
        get: '/api/clientcontrol/clients/get_endpoint/',
        add: '/api/clientcontrol/clients/add_endpoint',
        set: '/api/clientcontrol/clients/set_endpoint/',
        del: '/api/clientcontrol/clients/del_endpoint/',
        tabulatorOptions: localizedTabulatorOptions()
    });

    function reloadAllGrids() {
        [groupGrid, clientGrid, endpointGrid].forEach(function (grid) {
            grid.bootgrid('reload');
        });
    }

    function setClientCreationAvailable(hasGroups) {
        state.hasGroups = hasGroups;
        const message = '{{ lang._('Create a group before adding clients.') }}';
        const addButton = $("#{{ formGridClients['table_id'] }} .command-add");
        addButton.prop('disabled', !hasGroups).attr('title', hasGroups ? '' : message);
        $('#quick-name, #quick-endpoint, #quick-kind, #quick-group, #quick-client-form button[type="submit"]')
            .prop('disabled', !hasGroups)
            .attr('title', hasGroups ? '' : message);
        $('#quick-kind, #quick-group').selectpicker('refresh');
    }

    function refreshGroupSelectors() {
        queryJson('/api/clientcontrol/clients/selectors', {}).done(function (data) {
            const groups = data.groups || [];
            const groupSelects = $('[id="client.group"], #bulk-group, #quick-group, #client-filter-group, #delete-group-source, #delete-group-target');
            const selected = {};
            groupSelects.each(function () {
                selected[this.id] = $(this).val();
                $(this).empty();
                if (this.id === 'client-filter-group') {
                    $(this).append($('<option/>').val('').text('{{ lang._('Any group') }}'));
                } else if (this.id === 'delete-group-source' || this.id === 'delete-group-target') {
                    $(this).append($('<option/>').val('').text('—'));
                }
            });
            setClientCreationAvailable(groups.length > 0);
            groups.forEach(function (group) {
                groupSelects.each(function () {
                    $(this).append($('<option/>').val(group.uuid).text(group.name));
                });
            });
            groupSelects.each(function () {
                if (selected[this.id]) {
                    $(this).val(selected[this.id]);
                }
            }).selectpicker('refresh');

            const clientSelect = $('[id="endpoint.client"]');
            const selectedClient = clientSelect.val();
            clientSelect.empty();
            (data.clients || []).forEach(function (client) {
                clientSelect.append($('<option/>').val(client.uuid).text(client.name));
            });
            if (selectedClient) {
                clientSelect.val(selectedClient);
            }
            clientSelect.selectpicker('refresh');
        });
    }

    function markDirty(message) {
        state.lastPlan = null;
        state.deepCheckRevision = null;
        $('#apply-plan').prop('disabled', true);
        setBanner('warning', message || '{{ lang._('Changes saved. Check and apply them when ready.') }}');
        refreshStatus();
    }

    function mutationSucceeded(data) {
        if (data && data.validations) {
            setBanner('danger', Object.values(data.validations).join('\n'));
            return false;
        }
        if (!data || data.result === 'failed' || data.status === 'error' || data.errorMessage) {
            setBanner('danger', (data && (data.errorMessage || data.message)) || '{{ lang._('Request failed.') }}');
            return false;
        }
        updateAuditLogStatus(data);
        if (data.revision !== undefined) {
            state.revision = Number(data.revision);
        }
        reloadAllGrids();
        refreshGroupSelectors();
        markDirty(data.audit_log === 'degraded' ? data.audit_log_message : null);
        return true;
    }

    $(document).on('settings-changed', function () {
        window.setTimeout(function () {
            getJson('/api/clientcontrol/settings/get').done(function (data) {
                state.revision = Number(data.revision || 0);
                refreshGroupSelectors();
                markDirty();
            });
        }, 150);
    });

    function setDeepCheckStatus(kind, message) {
        $('#cc-deep-check')
            .removeClass('alert-info alert-success alert-warning alert-danger')
            .addClass('alert-' + kind)
            .show();
        $('#cc-deep-check-message').text(message);
    }

    function refreshStatus() {
        getJson('/api/clientcontrol/service/status').done(function (data) {
            updateAuditLogStatus(data);
            state.revision = Number(data.revision || 0);
            $('#cc-revision').text(data.revision);
            $('#cc-applied-revision').text(data.last_applied_revision);
            $('#cc-sync')
                .text(translatedLabel(stateLabels, data.sync_state))
                .attr('class', 'label ' + (data.sync_state === 'in_sync' ? 'label-success' : 'label-warning'));
            $('#cc-last-status')
                .text(translatedLabel(stateLabels, data.status || 'never'))
                .attr('class', 'label ' +
                    (data.status === 'ok' ? 'label-success' :
                        (data.status === 'error' || data.status === 'conflict' ? 'label-danger' : 'label-default')));
            const lastMessage = (data.status === 'error' || data.status === 'conflict') && data.last_apply_message
                ? data.last_apply_message
                : (data.last_apply_time ? '{{ lang._('Last applied') }}: ' + formatDateTime(data.last_apply_time) : '');
            $('#cc-last-message').text(lastMessage);
            $('#cc-managed-count').text(Object.values(data.managed_objects || {}).reduce(function (sum, value) {
                return sum + Number(value);
            }, 0));
            const platformWarning = (data.platform || {}).warning || '';
            $('#cc-platform-warning').toggle(platformWarning !== '').text(platformWarning);
            if (!data.deep_check_required) {
                $('#cc-deep-check').hide();
            } else if (state.deepCheckRevision !== Number(data.revision)) {
                setDeepCheckStatus('warning', '{{ lang._('Managed objects have not been deeply checked in this browser session.') }}');
            }
        });
    }

    function loadSettings() {
        mapDataToFormUI({frm_general: '/api/clientcontrol/settings/get'}).done(function (data) {
            state.revision = Number(data.revision || (data.general || {}).revision || 0);
            $('#revision').val(state.revision);

            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            refreshStatus();
        });
    }

    $('#save-settings').click(function () {
        $('#revision').val(state.revision);
        saveFormToEndpoint('/api/clientcontrol/settings/set', 'frm_general', function (data) {
            if (mutationSucceeded(data)) {
                loadSettings();
            }
        }, true, function (data) {
            mutationSucceeded(data);
        });
    });

    function resetGroupDeletionControls() {
        $('#delete-group-source, #delete-group-target').val('').selectpicker('refresh');
    }

    function deleteGroup(uuid, targetGroupUuid) {
        const payload = {revision: state.revision};
        if (targetGroupUuid) {
            payload.target_group_uuid = targetGroupUuid;
        }
        stdDialogConfirm(
            '{{ lang._('Delete group') }}',
            targetGroupUuid
                ? '{{ lang._('Clients will be moved to the chosen group. Delete the old group?') }}'
                : '{{ lang._('Delete this empty group?') }}',
            '{{ lang._('Delete') }}',
            '{{ lang._('Cancel') }}',
            function () {
                postJson('/api/clientcontrol/groups/del_group/' + uuid, payload).done(function (data) {
                    if (mutationSucceeded(data)) {
                        resetGroupDeletionControls();
                    }
                });
            }
        );
    }

    function prepareGroupDeletion(uuid, memberCount) {
        if (memberCount < 1) {
            deleteGroup(uuid, '');
            return;
        }
        $('#delete-group-source').val(uuid).selectpicker('refresh');
        $('#delete-group-target').val('').selectpicker('refresh');
        setBanner('warning', '{{ lang._('Choose another group for these clients.') }}');
        const controls = document.getElementById('group-delete-transfer');
        if (controls) {
            controls.open = true;
            controls.scrollIntoView({block: 'center'});
        }
    }

    $('#delete-group').click(function () {
        const sourceGroup = $('#delete-group-source').val();
        const targetGroup = $('#delete-group-target').val();
        if (!sourceGroup || !targetGroup || sourceGroup === targetGroup) {
            setBanner('warning', '{{ lang._('Choose another group for these clients.') }}');
            return;
        }
        deleteGroup(sourceGroup, targetGroup);
    });

    $('#client-filter-group, #client-filter-access, #client-filter-sync').change(function () {
        clientGrid.bootgrid('reload');
    });

    function selectedClients() {
        const selected = clientGrid.bootgrid('getSelectedRows');
        if (!selected.length) {
            setBanner('warning', '{{ lang._('Select at least one client.') }}');
        }
        return selected;
    }

    $('#quick-client-form').on('submit', function (event) {
        event.preventDefault();
        const name = $.trim($('#quick-name').val());
        const endpoint = $.trim($('#quick-endpoint').val());
        const group = $('#quick-group').val();
        if (!name || !endpoint || !group) {
            setBanner('warning', '{{ lang._('Enter a client name, choose a group, and provide an IP or MAC address.') }}');
            return;
        }
        postJson('/api/clientcontrol/clients/add_client', {
            revision: state.revision,
            client: {
                enabled: '1',
                name: name,
                group: group,
                endpoints: [{
                    kind: $('#quick-kind').val(),
                    value: endpoint,
                    label: ''
                }]
            }
        }).done(function (data) {
            if (mutationSucceeded(data)) {
                $('#quick-name, #quick-endpoint').val('');
            }
        });
    });

    $('#bulk-move').click(function () {
        const selected = selectedClients();
        if (!selected.length) {
            return;
        }
        postJson('/api/clientcontrol/clients/bulk_move', {
            revision: state.revision,
            client_uuids: selected,
            group_uuid: $('#bulk-group').val()
        }).done(mutationSucceeded);
    });

    $('#bulk-enable, #bulk-disable').click(function () {
        const selected = selectedClients();
        if (!selected.length) {
            return;
        }
        postJson('/api/clientcontrol/clients/bulk_toggle', {
            revision: state.revision,
            client_uuids: selected,
            enabled: this.id === 'bulk-enable' ? '1' : '0'
        }).done(mutationSucceeded);
    });

    function renderPlan(plan) {
        const hasChanges = (plan.operations || []).some(function (operation) {
            return operation.action !== 'noop';
        });
        const resultLabel = plan.status === 'ok' && !hasChanges
            ? '{{ lang._('Settings are already active') }}'
            : translatedLabel(planStatusLabels, plan.status);
        const forecast = plan.forecast || {};
        $('#plan-summary').text(
            '{{ lang._('Settings version') }}: ' + plan.revision + ' · ' +
            '{{ lang._('Result') }}: ' + resultLabel + ' · ' +
            '{{ lang._('Traffic Shaper rules') }}: ' + Number(forecast.shaper_rules || 0)
        );
        const tbody = $('#plan-rows').empty();
        const changes = (plan.operations || []).filter(function (operation) {
            return operation.action !== 'noop';
        });
        changes.slice(0, planChangeLimit).forEach(function (operation) {
            const tr = $('<tr/>');
            tr.append($('<td/>').text(translatedLabel(actionLabels, operation.action)));
            tr.append($('<td/>').text(translatedLabel(coreTypeLabels, operation.core_type)));
            tr.append($('<td/>').text(operation.core_name));
            tr.append($('<td/>').addClass('cc-diff-value').text(renderJsonLimited(operation.before, planDiffCharacterLimit)));
            tr.append($('<td/>').addClass('cc-diff-value').text(renderJsonLimited(operation.after, planDiffCharacterLimit)));
            tbody.append(tr);
        });
        if (changes.length > planChangeLimit) {
            tbody.append($('<tr/>').addClass('warning').append(
                $('<td/>').attr('colspan', 5).text('{{ lang._('The plan table is truncated to protect browser responsiveness.') }}')
            ));
        }
        (plan.conflicts || []).forEach(function (conflict) {
            const tr = $('<tr/>').addClass('danger');
            tr.append($('<td/>').text(translatedLabel(actionLabels, 'conflict')));
            tr.append($('<td/>').text(translatedLabel(coreTypeLabels, conflict.core_type)));
            tr.append($('<td/>').text(conflict.core_name));
            tr.append($('<td/>').attr('colspan', 2).text(conflict.message));
            tbody.append(tr);
        });
        (plan.notices || []).forEach(function (notice) {
            const tr = $('<tr/>').addClass('warning');
            tr.append($('<td/>').text('{{ lang._('Warning') }}'));
            tr.append($('<td/>').attr('colspan', 4).text(notice.message));
            tbody.append(tr);
        });
        if (!tbody.children().length) {
            tbody.append(
                $('<tr/>').append(
                    $('<td/>').attr('colspan', 5).addClass('text-muted').text('{{ lang._('No changes.') }}')
                )
            );
        }
        $('#plan-json').text(renderTechnicalPlan(plan));
    }

    function acceptPlan(data) {
        state.lastPlan = data;
        state.deepCheckRevision = Number(data.revision);
        renderPlan(data);
        const hasChanges = (data.operations || []).some(function (operation) {
            return operation.action !== 'noop';
        });
        $('#apply-plan').prop('disabled', data.status !== 'ok' || !hasChanges);
        const conflicts = data.conflicts || [];
        const notices = data.notices || [];
        const messages = conflicts.concat(notices).map(function (item) {
            return item.message;
        });
        if (conflicts.length) {
            setDeepCheckStatus('danger', messages.join(' | '));
        } else if (notices.length) {
            setDeepCheckStatus('warning', messages.join(' | '));
        } else {
            setDeepCheckStatus('success', '{{ lang._('The latest deep check found no managed-object conflicts.') }}');
        }
    }

    function requestPlan() {
        queryJson('/api/clientcontrol/service/plan', {strategy: $('#plan-strategy').val()}).done(acceptPlan);
    }

    function renderImportPreview(data) {
        const groups = data.groups || [];
        const clients = data.clients || [];
        const addressCount = clients.reduce(function (total, client) {
            return total + (client.endpoints || []).length;
        }, 0);
        const box = $('#import-preview-summary').empty();
        box.append(
            $('<p/>').addClass('cc-summary-counts').text(
                '{{ lang._('Will be imported as disabled') }} — ' +
                '{{ lang._('Groups') }}: ' + groups.length + '; ' +
                '{{ lang._('Clients') }}: ' + clients.length + '; ' +
                '{{ lang._('Addresses') }}: ' + addressCount
            )
        );
        const appendMessages = function (style, title, messages) {
            if (!messages.length) {
                return;
            }
            const alert = $('<div/>').addClass('alert alert-' + style);
            alert.append($('<strong/>').text(title));
            const list = $('<ul/>');
            messages.forEach(function (message) {
                list.append($('<li/>').text(message));
            });
            alert.append(list);
            box.append(alert);
        };
        appendMessages('warning', '{{ lang._('Warnings') }}', data.warnings || []);
        appendMessages(data.can_apply ? 'warning' : 'danger', '{{ lang._('Skipped aliases') }}', data.errors || []);
        if (!(data.warnings || []).length && !(data.errors || []).length) {
            box.append($('<div/>').addClass('alert alert-success').text(
                '{{ lang._('No problems found. You can import the selected aliases.') }}'
            ));
        }
        $('#import-preview-json').text(renderJson(data));
    }

    $('#run-plan, #run-deep-check').click(function () {
        requestPlan();
    });

    $('#apply-plan').click(function () {
        if (!state.lastPlan) {
            setBanner('warning', '{{ lang._('Check the changes first.') }}');
            return;
        }
        const plan = state.lastPlan;
        const payload = {
            revision: state.revision,
            strategy: $('#plan-strategy').val(),
            plan_fingerprint: plan.plan_fingerprint,
            runtime_plan_fingerprint: plan.runtime_plan_fingerprint,
            confirm_enforce: plan.mode === 'enforce' ? plan.runtime_plan_fingerprint : ''
        };
        const prompt = plan.mode === 'enforce'
            ? '{{ lang._('These rules may immediately allow, block, or slow client traffic. Apply the changes?') }}'
            : '{{ lang._('Apply the changes shown below?') }}';
        stdDialogConfirm(
            '{{ lang._('Apply changes') }}',
            prompt,
            '{{ lang._('Apply') }}',
            '{{ lang._('Cancel') }}',
            function () {
                postJson('/api/clientcontrol/service/apply', payload).done(function (data) {
                    if (!data || data.result !== 'applied' || data.verified !== true) {
                        setBanner('danger', (data && (data.errorMessage || data.message)) || '{{ lang._('Request failed.') }}');
                        return;
                    }
                    state.lastPlan = null;
                    state.deepCheckRevision = Number(data.revision);
                    $('#apply-plan').prop('disabled', true);
                    updateAuditLogStatus(data);
                    if (data.audit_log === 'degraded') {
                        setBanner('warning', data.audit_log_message);
                    } else {
                        setBanner('success', '{{ lang._('Changes applied. OPNsense rules were reloaded and checked.') }}');
                    }
                    setDeepCheckStatus('success', '{{ lang._('The latest deep check found no managed-object conflicts.') }}');
                    $('#plan-json').text(renderTechnicalPlan(data));
                    refreshStatus();
                });
            }
        );
    });

    $('#scan-import').click(function () {
        queryJson('/api/clientcontrol/import/scan', {rowCount: -1, current: 1}).done(function (data) {
            const box = $('#import-aliases').empty();
            const rows = data.rows || [];
            if (!rows.length) {
                box.append($('<p/>').addClass('text-muted').text('{{ lang._('No suitable aliases found.') }}'));
                $('#preview-import').prop('disabled', true);
                return;
            }
            rows.forEach(function (alias) {
                const input = $('<input/>', {
                    type: 'checkbox',
                    id: 'cc-import-' + alias.uuid,
                    value: alias.name,
                    disabled: !alias.importable
                });
                const label = $('<label/>').addClass('checkbox-inline').append(input, ' ', alias.name, ' ');
                label.append($('<span/>').addClass('text-muted').text(
                    '(' + translatedLabel(aliasTypeLabels, alias.type) + ', ' + alias.item_count + ')'
                ));
                if (alias.reason) {
                    label.append($('<span/>').addClass('text-warning').text(' — ' + alias.reason));
                }
                box.append(label);
            });
            $('#preview-import').prop('disabled', !rows.some(function (alias) {
                return alias.importable;
            }));
        });
    });

    $('#import-reuse-groups').change(function () {
        state.importPreview = null;
        $('#apply-import').prop('disabled', true);
    });

    $('#preview-import').click(function () {
        const aliases = $('#import-aliases input:checked').map(function () {
            return this.value;
        }).get();
        if (!aliases.length) {
            setBanner('warning', '{{ lang._('Select at least one importable alias.') }}');
            return;
        }
        queryJson('/api/clientcontrol/import/preview', {
            alias_names: aliases,
            reuse_existing_groups: $('#import-reuse-groups').prop('checked') ? '1' : '0'
        }).done(function (data) {
            state.importPreview = data;
            renderImportPreview(data);
            $('#apply-import').prop('disabled', !data.can_apply);
        });
    });

    $('#apply-import').click(function () {
        if (!state.importPreview) {
            return;
        }
        postJson('/api/clientcontrol/import/apply', {
            revision: state.revision,
            alias_names: state.importPreview.selected_aliases,
            reuse_existing_groups: state.importPreview.reuse_existing_groups ? '1' : '0',
            preview_hash: state.importPreview.preview_hash
        }).done(function (data) {
            if (mutationSucceeded(data)) {
                state.importPreview = null;
                $('#apply-import').prop('disabled', true);
                $('#import-preview-summary, #import-preview-json').empty();
                setBanner('success', '{{ lang._('Aliases were imported as disabled clients. Source aliases were not modified.') }}');
            }
        });
    });

    $('#refresh-runtime').click(function () {
        getJson('/api/clientcontrol/diagnostics/runtime').done(function (data) {
            $('#runtime-json').text(renderJson(data));
            const warnings = data.warnings || [];
            const warningLines = warnings.map(function (warning) {
                return warning.client_name + ': ' + warning.endpoint + ' — ' + warning.message;
            });
            if ((data.pf_states || {}).truncated) {
                warningLines.unshift('{{ lang._('Connection counters are truncated at the firewall query limit.') }}');
            }
            $('#runtime-warnings')
                .toggle(warningLines.length > 0)
                .text(warningLines.join('\n'));
            const tbody = $('#runtime-rows').empty();
            (data.clients || []).forEach(function (client) {
                const tr = $('<tr/>');
                tr.append($('<td/>').text(client.name));
                tr.append($('<td/>').append(
                    $('<span/>')
                        .addClass(client.online ? 'label label-success' : 'label label-default')
                        .text(client.online ? '{{ lang._('Online') }}' : '{{ lang._('Offline') }}')
                ));
                tr.append($('<td/>').text(client.state_count_label || client.state_count));
                tr.append($('<td/>').text((client.neighbors || []).length));
                tr.append($('<td/>').text(translatedLabel(stateLabels, client.sync_state)));
                tbody.append(tr);
            });
        });
    });

    $('#refresh-audit').click(function () {
        queryJson('/api/clientcontrol/diagnostics/audit', {
            rowCount: 200,
            current: 1,
            sort: {timestamp: 'desc'}
        }).done(function (data) {
            updateAuditLogStatus(data);
            const tbody = $('#audit-rows').empty();
            (data.rows || []).forEach(function (entry) {
                const tr = $('<tr/>');
                tr.append($('<td/>').text(formatDateTime(entry.timestamp)));
                tr.append($('<td/>').text(entry.username));
                tr.append($('<td/>').text(translatedLabel(operationLabels, entry.operation)));
                tr.append($('<td/>').text(entry.summary));
                tr.append($('<td/>').text(translatedLabel(resultLabels, entry.result)));
                tbody.append(tr);
            });
            const historyWindow = Number(data.history_window || 0);
            $('#audit-window-note')
                .toggle(historyWindow > 0)
                .text(historyWindow > 0
                    ? '{{ lang._('The table is limited to the latest %s records. Full history is available through JSON export.') }}'.replace('%s', String(historyWindow))
                    : '');
        });
    });

    $('#export-audit').click(function () {
        getJson('/api/clientcontrol/diagnostics/audit_export').done(function (data) {
            updateAuditLogStatus(data);
            downloadJson('client-control-audit.json', data);
        });
    });

    let runtimeLoaded = false;
    let auditLoaded = false;
    $('a[href="#cc-runtime"]').on('shown.bs.tab', function () {
        if (!runtimeLoaded) {
            runtimeLoaded = true;
            $('#refresh-runtime').trigger('click');
        }
    });
    $('a[href="#cc-audit"]').on('shown.bs.tab', function () {
        if (!auditLoaded) {
            auditLoaded = true;
            $('#refresh-audit').trigger('click');
        }
    });
    refreshGroupSelectors();
    loadSettings();
});
</script>

<div id="cc-banner" class="alert alert-info" style="display:none"></div>

<div class="cc-status-bar">
    <span class="label label-default">{{ lang._('Settings version') }}: <span id="cc-revision">0</span></span>
    <span class="label label-default">{{ lang._('Applied version') }}: <span id="cc-applied-revision">0</span></span>
    <span id="cc-sync" class="label label-default">{{ lang._('Unknown') }}</span>
    <span id="cc-last-status" class="label label-default">{{ lang._('Not applied yet') }}</span>
    <span class="label label-default" title="{{ lang._('Aliases, firewall rules, and speed-limit objects created by Client Control.') }}">{{ lang._('OPNsense objects') }}: <span id="cc-managed-count">0</span></span>
    <span class="text-muted" id="cc-last-message"></span>
</div>
<div id="cc-platform-warning" class="alert alert-warning" style="display:none"></div>
<div id="cc-audit-warning" class="alert alert-warning" style="display:none"></div>
<div id="cc-deep-check" class="alert alert-warning clearfix" style="display:none">
    <span id="cc-deep-check-message"></span>
    <button id="run-deep-check" type="button" class="btn btn-default btn-xs pull-right"><i class="fa fa-search"></i> {{ lang._('Run deep check') }}</button>
</div>

<ul class="nav nav-tabs" role="tablist">
    <li class="active"><a href="#cc-general" data-toggle="tab">{{ lang._('Settings') }}</a></li>
    <li><a href="#cc-groups" data-toggle="tab">{{ lang._('Groups') }}</a></li>
    <li><a href="#cc-clients" data-toggle="tab">{{ lang._('Clients') }}</a></li>
    <li><a href="#cc-import" data-toggle="tab">{{ lang._('Import') }}</a></li>
    <li><a href="#cc-plan" data-toggle="tab">{{ lang._('Review and apply') }}</a></li>
    <li><a href="#cc-runtime" data-toggle="tab">{{ lang._('Current status') }}</a></li>
    <li><a href="#cc-audit" data-toggle="tab">{{ lang._('History') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="cc-general" class="tab-pane active">
        <div class="alert alert-info">
            <p><strong>{{ lang._('Saving settings does not change client traffic immediately.') }}</strong></p>
            <p>{{ lang._('When the settings are ready, open “Review and apply”, check the list, and apply it.') }}</p>
            <p>{{ lang._('A client identified only by MAC is treated as offline and blocked while OPNsense cannot find its current IP address.') }}</p>
        </div>
        {{ partial('layout_partials/base_form', ['fields': formGeneral, 'id': 'frm_general']) }}
        <div class="cc-panel-actions">
            <button id="save-settings" type="button" class="btn btn-primary"><i class="fa fa-save"></i> {{ lang._('Save changes') }}</button>
        </div>
    </div>

    <div id="cc-groups" class="tab-pane">
        <p class="cc-section-intro">{{ lang._('A group gives several clients the same access and speed settings. Individual exceptions can be set in a client card.') }}</p>
        {{ partial('Volgodon/ClientControl/grid', formGridGroups) }}
        <details id="group-delete-transfer" class="cc-technical">
            <summary>{{ lang._('Delete a group that still has clients') }}</summary>
            <div class="well well-sm">
                <div class="cc-inline-form">
                    <label for="delete-group-source">{{ lang._('Group to delete') }}</label>
                    <select id="delete-group-source" class="form-control selectpicker" data-live-search="true" title="{{ lang._('Group to delete') }}"></select>
                    <i class="fa fa-long-arrow-right" aria-hidden="true"></i>
                    <label for="delete-group-target">{{ lang._('Move its clients to') }}</label>
                    <select id="delete-group-target" class="form-control selectpicker" data-live-search="true" title="{{ lang._('Move its clients to') }}"></select>
                    <button id="delete-group" type="button" class="btn btn-danger"><i class="fa fa-trash"></i> {{ lang._('Move clients and delete group') }}</button>
                </div>
                <p class="help-block">{{ lang._('Clients must be moved to another group so they do not lose their policy.') }}</p>
            </div>
        </details>
    </div>

    <div id="cc-clients" class="tab-pane">
        <form id="quick-client-form" class="well well-sm" autocomplete="off">
            <h4>{{ lang._('Add client') }}</h4>
            <div class="cc-inline-form">
                <label class="sr-only" for="quick-name">{{ lang._('Client name') }}</label>
                <input id="quick-name" class="form-control" type="text" placeholder="{{ lang._('Client name') }}" required>
                <label class="sr-only" for="quick-group">{{ lang._('Group') }}</label>
                <select id="quick-group" class="form-control selectpicker" data-live-search="true" title="{{ lang._('Choose a group') }}" required></select>
                <label class="sr-only" for="quick-kind">{{ lang._('Address type') }}</label>
                <select id="quick-kind" class="form-control selectpicker">
                    <option value="ipv4">IPv4</option>
                    <option value="ipv6">IPv6</option>
                    <option value="mac">MAC</option>
                </select>
                <label class="sr-only" for="quick-endpoint">{{ lang._('IP or MAC address') }}</label>
                <input id="quick-endpoint" class="form-control" type="text" placeholder="{{ lang._('IP or MAC address') }}" required>
                <button type="submit" class="btn btn-primary"><i class="fa fa-plus"></i> {{ lang._('Add client') }}</button>
            </div>
            <p class="help-block">{{ lang._('The client is enabled immediately with this first address. To add more addresses or make an exception to the group settings, open the client row.') }}</p>
        </form>
        <div class="cc-panel-actions cc-inline-form">
            <strong>{{ lang._('Show') }}:</strong>
            <select id="client-filter-group" class="form-control selectpicker" data-live-search="true" title="{{ lang._('Any group') }}"></select>
            <select id="client-filter-access" class="form-control selectpicker" title="{{ lang._('Any access') }}">
                <option value="">{{ lang._('Any access') }}</option>
                <option value="allow">{{ lang._('Allow') }}</option>
                <option value="block">{{ lang._('Block') }}</option>
            </select>
            <select id="client-filter-sync" class="form-control selectpicker" title="{{ lang._('Any rule state') }}">
                <option value="">{{ lang._('Any rule state') }}</option>
                <option value="in_sync">{{ lang._('Rules match settings') }}</option>
                <option value="pending">{{ lang._('Changes not applied') }}</option>
                <option value="conflict">{{ lang._('Changed outside Client Control') }}</option>
                <option value="error">{{ lang._('Error') }}</option>
                <option value="never">{{ lang._('Not applied yet') }}</option>
            </select>
        </div>
        {{ partial('Volgodon/ClientControl/grid', formGridClients) }}
        <div class="cc-panel-actions cc-inline-form">
            <select id="bulk-group" class="form-control selectpicker" data-live-search="true" title="{{ lang._('Move to group') }}"></select>
            <button id="bulk-move" class="btn btn-default"><i class="fa fa-exchange"></i> {{ lang._('Move selected to group') }}</button>
            <button id="bulk-enable" class="btn btn-default"><i class="fa fa-check"></i> {{ lang._('Enable selected') }}</button>
            <button id="bulk-disable" class="btn btn-default"><i class="fa fa-times"></i> {{ lang._('Disable selected') }}</button>
        </div>
        <h4>{{ lang._('Additional client addresses') }}</h4>
        <p class="text-muted">{{ lang._('Add another IP or MAC when the same client uses several network interfaces or addresses.') }}</p>
        {{ partial('Volgodon/ClientControl/grid', formGridEndpoints) }}
    </div>

    <div id="cc-import" class="tab-pane">
        <p class="cc-section-intro">{{ lang._('Use this when clients already exist as OPNsense aliases. Import copies their names and addresses; the original aliases remain unchanged.') }}</p>
        <div class="cc-panel-actions">
            <button id="scan-import" class="btn btn-default"><i class="fa fa-search"></i> {{ lang._('Find aliases') }}</button>
            <button id="preview-import" class="btn btn-info" disabled><i class="fa fa-eye"></i> {{ lang._('Check import') }}</button>
            <button id="apply-import" class="btn btn-primary" disabled><i class="fa fa-download"></i> {{ lang._('Import selected') }}</button>
        </div>
        <label class="checkbox-inline">
            <input id="import-reuse-groups" type="checkbox">
            {{ lang._('Reuse an existing group with the same name without changing its policy') }}
        </label>
        <div id="import-aliases" class="well well-sm"></div>
        <div id="import-preview-summary"></div>
        <details class="cc-technical"><summary>{{ lang._('Technical import details') }}</summary><pre id="import-preview-json" class="cc-console"></pre></details>
    </div>

    <div id="cc-plan" class="tab-pane">
        <div class="cc-risk">
            <p><strong>{{ lang._('Traffic changes only after you apply the checked list below.') }}</strong></p>
            <p>{{ lang._('If OPNsense rules were changed outside Client Control, stop and review the difference before replacing anything.') }}</p>
        </div>
        <div class="cc-panel-actions cc-inline-form">
            <select id="plan-strategy" class="form-control selectpicker">
                <option value="fail">{{ lang._('Stop when outside changes are found') }}</option>
                <option value="restore">{{ lang._('Replace outside changes with these settings') }}</option>
            </select>
            <button id="run-plan" class="btn btn-info"><i class="fa fa-search"></i> {{ lang._('Check changes') }}</button>
            <button id="apply-plan" class="btn btn-danger" disabled><i class="fa fa-check"></i> {{ lang._('Apply changes') }}</button>
        </div>
        <p id="plan-summary" class="text-muted"></p>
        <div class="table-responsive">
            <table class="table table-condensed table-striped cc-diff-table">
                <thead><tr><th>{{ lang._('Change') }}</th><th>{{ lang._('Part') }}</th><th>{{ lang._('Name') }}</th><th>{{ lang._('Current value') }}</th><th>{{ lang._('New value') }}</th></tr></thead>
                <tbody id="plan-rows"><tr><td colspan="5" class="text-muted">{{ lang._('Click “Check changes” to see what will happen.') }}</td></tr></tbody>
            </table>
        </div>
        <details class="cc-technical"><summary>{{ lang._('Technical plan details') }}</summary><pre id="plan-json" class="cc-console"></pre></details>
    </div>

    <div id="cc-runtime" class="tab-pane">
        <p class="cc-section-intro">{{ lang._('This page shows whether clients are visible on the network and whether their rules match the saved settings.') }}</p>
        <div class="cc-panel-actions"><button id="refresh-runtime" class="btn btn-default"><i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button></div>
        <pre id="runtime-warnings" class="alert alert-warning cc-console" style="display:none"></pre>
        <div class="table-responsive">
            <table class="table table-condensed table-striped"><thead><tr><th>{{ lang._('Client') }}</th><th>{{ lang._('Network') }}</th><th>{{ lang._('Open connections') }}</th><th>{{ lang._('Known addresses') }}</th><th>{{ lang._('Rules') }}</th></tr></thead><tbody id="runtime-rows"></tbody></table>
        </div>
        <details class="cc-technical"><summary>{{ lang._('Technical status details') }}</summary><pre id="runtime-json" class="cc-console"></pre></details>
    </div>

    <div id="cc-audit" class="tab-pane">
        <p class="cc-section-intro">{{ lang._('The history records who changed the settings and when rules were applied or rolled back.') }}</p>
        <div class="cc-panel-actions">
            <button id="refresh-audit" class="btn btn-default"><i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button>
            <button id="export-audit" class="btn btn-default"><i class="fa fa-download"></i> {{ lang._('Export JSON') }}</button>
        </div>
        <div class="table-responsive"><table class="table table-condensed table-striped"><thead><tr><th>{{ lang._('Date and time') }}</th><th>{{ lang._('User') }}</th><th>{{ lang._('Action') }}</th><th>{{ lang._('Details') }}</th><th>{{ lang._('Result') }}</th></tr></thead><tbody id="audit-rows"></tbody></table></div>
        <p id="audit-window-note" class="text-muted" style="display:none"></p>
    </div>
</div>

{{ partial('layout_partials/base_dialog', ['fields': formDialogGroup, 'id': formGridGroups['edit_dialog_id'], 'label': lang._('Group settings')]) }}
{{ partial('layout_partials/base_dialog', ['fields': formDialogClient, 'id': formGridClients['edit_dialog_id'], 'label': lang._('Client settings')]) }}
{{ partial('layout_partials/base_dialog', ['fields': formDialogEndpoint, 'id': formGridEndpoints['edit_dialog_id'], 'label': lang._('Client address')]) }}
