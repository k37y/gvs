const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');

function setup(initial = '[]', quota = Infinity, unavailable = false) {
	const values = new Map([['gvs-scan-history', initial]]);
	let attempts = 0;
	const context = vm.createContext({
		window: {},
		document: { addEventListener() {} },
		console: { warn() {} },
		localStorage: {
			getItem(key) {
				if (unavailable) throw new Error('Storage disabled');
				return values.get(key) || null;
			},
			setItem(key, value) {
				attempts++;
				if (unavailable) throw new Error('Storage disabled');
				if (value.length > quota) {
					const error = new Error('Storage full');
					error.name = 'QuotaExceededError';
					throw error;
				}
				values.set(key, value);
			}
		}
	});
	vm.runInContext(readFileSync(`${__dirname}/script.js`, 'utf8'), context);
	return { context, history: () => JSON.parse(values.get('gvs-scan-history')), attempts: () => attempts };
}

test('quota recovery removes oldest scans and preserves the newest full result', () => {
	const old = JSON.stringify([{ repo: 'previous', logs: 'x'.repeat(200) }, { repo: 'oldest', logs: 'x'.repeat(200) }]);
	const app = setup(old, 250);
	assert.equal(app.context.saveScanToHistory({ repo: 'new', output: { IsVulnerable: false }, logs: 'complete logs' }), true);
	assert.deepEqual(app.history().map(item => item.repo), ['new']);
	assert.equal(app.history()[0].logs, 'complete logs');
	assert.equal(app.history()[0].output.IsVulnerable, false);
	assert.equal(app.attempts(), 3);
});

test('an oversized new scan leaves existing stored history intact', () => {
	const app = setup('[{"repo":"previous"}]', 100);
	assert.equal(app.context.saveScanToHistory({ repo: 'new', logs: 'x'.repeat(500) }), false);
	assert.deepEqual(app.history(), [{ repo: 'previous' }]);
});

test('disabled storage does not throw or repeatedly retry', () => {
	const app = setup('[]', Infinity, true);
	assert.equal(app.context.saveScanToHistory({ repo: 'new' }), false);
	assert.equal(app.attempts(), 1);
	assert.doesNotThrow(() => vm.runInContext('FormHistoryManager.prototype.saveToHistory.call({storagePrefix: "gvs-history-", maxHistoryItems: 10, getHistory: () => []}, "repo", "new")', app.context));
});

test('invalid history can be replaced by a new scan', () => {
	for (const initial of ['invalid JSON', '{}', 'null', '[null]']) {
		const app = setup(initial);
		assert.equal(app.context.saveScanToHistory({ repo: 'new' }), true);
		assert.deepEqual(app.history().map(item => item.repo), ['new']);
	}
});

test('history stays limited to 50 newest entries', () => {
	const app = setup(JSON.stringify(Array.from({ length: 50 }, (_, i) => ({ repo: `old-${i}` }))));
	assert.equal(app.context.saveScanToHistory({ repo: 'new' }), true);
	assert.equal(app.history().length, 50);
	assert.equal(app.history()[0].repo, 'new');
	assert.equal(app.history().at(-1).repo, 'old-48');
});

test('completion uses full logs once after live, interrupted, or absent streaming', async () => {
	const logs = 'cg version test\r\nRepeated message\nRepeated message\n<done>\n';
	for (const streamed of [logs.split('\n'), ['cg version test'], []]) {
		const app = setup();
		const elements = new Map();
		app.context.document.getElementById = id => {
			if (!elements.has(id)) elements.set(id, {
				value: '', innerHTML: '', style: {}, classList: { add() {}, remove() {} }
			});
			return elements.get(id);
		};
		for (const [id, value] of Object.entries({ repo: 'repo', branchOrCommit: 'main', cve: 'CVE-2026-1234', algo: 'rta' })) {
			app.context.document.getElementById(id).value = value;
		}
		app.context.window.validateCVEInput = () => true;
		app.context.showResultView = () => {};
		let poll;
		app.context.setInterval = callback => { poll = callback; return 1; };
		app.context.clearInterval = () => {};
		let stream;
		app.context.EventSource = class {
			constructor() { stream = this; }
			close() { this.closed = true; }
		};
		app.context.fetch = async url => ({ json: async () => url.endsWith('/status')
			? { status: 'completed', output: {}, logs }
			: { taskId: 'task' } });
		app.context.runScan();
		await new Promise(setImmediate);
		for (const data of ['Cloning repository...', ...streamed]) stream.onmessage({ data });
		poll();
		await new Promise(setImmediate);
		const expected = logs.split(/\r?\n/).filter(Boolean).map(app.context.highlightLog).join('\n') + '\n';
		assert.equal(elements.get('resultProgressContent').innerHTML, expected);
		assert.equal(app.history()[0].logs, expected);
		assert.equal(stream.closed, true);
		stream.onmessage({ data: 'late message' });
		assert.equal(elements.get('resultProgressContent').innerHTML, expected);
	}
});
