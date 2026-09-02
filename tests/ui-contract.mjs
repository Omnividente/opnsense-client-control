import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const viewPath = resolve(
    root,
    'src/opnsense/mvc/app/views/Volgodon/ClientControl/index.volt'
);
const view = readFileSync(viewPath, 'utf8');
const scriptMatch = view.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, 'Client Control view must contain a script block');
const renderedScript = scriptMatch[1].replace(/\{\{[\s\S]*?\}\}/g, 'TEXT');
new Function(renderedScript);

function extractFunction(source, name) {
    const start = source.indexOf(`function ${name}(`);
    assert.notEqual(start, -1, `${name} must exist`);
    const openingBrace = source.indexOf('{', start);
    let depth = 0;
    for (let offset = openingBrace; offset < source.length; offset += 1) {
        if (source[offset] === '{') {
            depth += 1;
        } else if (source[offset] === '}') {
            depth -= 1;
            if (depth === 0) {
                return source.slice(start, offset + 1);
            }
        }
    }
    throw new Error(`${name} has no closing brace`);
}

const state = {
    auditLogDegraded: false,
    auditLogMessage: ''
};
const warning = {
    visible: false,
    text: ''
};
const jquery = (selector) => {
    assert.equal(selector, '#cc-audit-warning');
    return {
        toggle(value) {
            warning.visible = Boolean(value);
            return this;
        },
        text(value) {
            warning.text = String(value);
            return this;
        }
    };
};
const updateAuditLogStatus = new Function(
    'state',
    '$',
    `return (${extractFunction(renderedScript, 'updateAuditLogStatus')});`
)(state, jquery);

assert.equal(updateAuditLogStatus({
    audit_log: 'degraded',
    audit_log_message: 'audit unavailable'
}), true);
assert.equal(warning.visible, true);
assert.equal(warning.text, 'audit unavailable');
assert.equal(updateAuditLogStatus({audit_log: 'ok', audit_log_message: ''}), false);
assert.equal(state.auditLogMessage, '');
assert.equal(warning.visible, false, 'recovered audit status must hide the warning in the same session');
assert.equal(warning.text, '');

assert.match(renderedScript, /const historyWindow = Number\(data\.history_window \|\| 0\);/);
assert.match(renderedScript, /\$\('#audit-window-note'\)[\s\S]*?\.toggle\(historyWindow > 0\)/);
assert.match(view, /id="audit-window-note"/);

const capabilityState = {packetRateSupported: true};
const capabilityFieldsState = {disabled: false, attributes: {}};
const capabilityRowsState = {disabledClass: false, attributes: {}};
const removeAttributes = (attributes, names) => {
    names.split(/\s+/).forEach((name) => delete attributes[name]);
};
const capabilityRows = {
    toggleClass(name, enabled) {
        assert.equal(name, 'cc-capability-disabled');
        capabilityRowsState.disabledClass = Boolean(enabled);
        return this;
    },
    attr(values) {
        Object.assign(capabilityRowsState.attributes, values);
        return this;
    },
    removeAttr(names) {
        removeAttributes(capabilityRowsState.attributes, names);
        return this;
    }
};
const capabilityFields = {
    prop(name, value) {
        assert.equal(name, 'disabled');
        capabilityFieldsState.disabled = Boolean(value);
        return this;
    },
    attr(name, value) {
        capabilityFieldsState.attributes[name] = value;
        return this;
    },
    removeAttr(names) {
        removeAttributes(capabilityFieldsState.attributes, names);
        return this;
    },
    closest(selector) {
        assert.equal(selector, 'tr');
        return capabilityRows;
    }
};
const capabilityJquery = (selector) => {
    assert.equal(selector, '[id="group.packet_rate"], [id="group.packet_rate_seconds"]');
    return capabilityFields;
};
const unavailableMessage = 'packet-count limiting is unavailable';
const setPacketRateCapability = new Function(
    'state',
    '$',
    'packetRateUnavailableMessage',
    `return (${extractFunction(renderedScript, 'setPacketRateCapability')});`
)(capabilityState, capabilityJquery, unavailableMessage);

setPacketRateCapability(false);
assert.equal(capabilityState.packetRateSupported, false);
assert.equal(capabilityFieldsState.disabled, true);
assert.equal(capabilityFieldsState.attributes.title, unavailableMessage);
assert.equal(capabilityRowsState.disabledClass, true);
assert.equal(capabilityRowsState.attributes.tabindex, '0');

setPacketRateCapability(true);
assert.equal(capabilityState.packetRateSupported, true);
assert.equal(capabilityFieldsState.disabled, false);
assert.equal(capabilityRowsState.disabledClass, false);
assert.equal(capabilityFieldsState.attributes.title, undefined);
assert.equal(capabilityRowsState.attributes.title, undefined);

let popupOptions = null;
const BootstrapDialog = {
    TYPE_INFO: 'info',
    show(options) {
        popupOptions = options;
    }
};
const showPacketRateUnavailable = new Function(
    'BootstrapDialog',
    'packetRateUnavailableMessage',
    `return (${extractFunction(renderedScript, 'showPacketRateUnavailable')});`
)(BootstrapDialog, unavailableMessage);
showPacketRateUnavailable();
assert.equal(popupOptions.type, 'info');
assert.equal(popupOptions.message, unavailableMessage);
assert.equal(popupOptions.buttons.length, 1);
let popupClosed = false;
popupOptions.buttons[0].action({close() { popupClosed = true; }});
assert.equal(popupClosed, true);

assert.match(renderedScript, /setPacketRateCapability\(platform\.packet_rate === true\)/);
assert.match(renderedScript, /platform\.transition_pending \? \(platform\.warning \|\| ''\) : ''/);

console.log('ok Client Control UI state contract');
