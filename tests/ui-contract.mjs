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

console.log('ok Client Control UI state contract');
