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

class LogElement {
	constructor() {
		this.children = [];
		this.html = '';
		this.writes = 0;
		this.value = '';
		this.style = {};
		this.classList = { add() {}, remove() {} };
	}
	get innerHTML() { return this.html + this.children.map(node => `<span>${node.innerHTML}</span>`).join(''); }
	set innerHTML(value) { this.writes++; this.html = value; this.children = []; }
	appendChild(node) { this.insertBefore(node, null); }
	insertBefore(node, before) {
		const index = before === null ? this.children.length : this.children.indexOf(before);
		assert.ok(index >= 0, 'insertion anchor must still be attached');
		this.children.splice(index, 0, node);
	}
	insertAdjacentHTML(position, html) {
		assert.equal(position, 'beforeend');
		const node = new LogElement();
		node.innerHTML = html;
		this.appendChild(node);
	}
}

test('completion preserves setup and existing nodes while recovering missing scanner lines', async () => {
	const logs = 'cg version test\r\nRepeated message\n\nRepeated message\n<done>';
	const finalLines = logs.split(/\r?\n/);
	const cases = [
		{ name: 'full stream', indices: [1, 2, 3, 4, 5] },
		{ name: 'interrupted stream', indices: [1, 2] },
		{ name: 'dropped middle lines', indices: [1, 5] },
		{ name: 'missing beginning and identical messages', indices: [4, 5] },
		{ name: 'duplicate event', indices: [1, 2, 2, 4, 5] },
		{ name: 'absent stream', indices: [] },
		{ name: 'cache hit', indices: [], cached: true },
		{ name: 'no final logs', indices: [1, 2], logs: '' }
	];
	for (const scenario of cases) {
		const app = setup();
		const elements = new Map();
		app.context.document.createElement = () => new LogElement();
		app.context.document.getElementById = id => {
			if (!elements.has(id)) elements.set(id, new LogElement());
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
			? { status: 'completed', output: {}, logs: scenario.logs ?? logs }
			: { taskId: 'task' } });
		app.context.runScan();
		await new Promise(setImmediate);
		const panel = elements.get('resultProgressContent');
		const scanner = panel.children[0];
		const setupLines = scenario.cached ? [] : ['Cloning repository...', 'Running vulnerability analysis (algorithm: rta)...'];
		for (const data of setupLines) stream.onmessage({ data });
		for (const index of scenario.indices) {
			stream.onmessage({ data: finalLines[index - 1], lastEventId: `scanner-${index}` });
		}
		const existing = [...scanner.children];
		const before = panel.innerHTML;
		const writes = panel.writes;
		poll();
		await new Promise(setImmediate);
		assert.equal(panel.writes, writes, scenario.name + ': panel must not be replaced');
		assert.equal(panel.children.at(-1), scanner);
		for (const node of existing) {
			assert.ok(scanner.children.includes(node), scenario.name + ': existing node retained');
			assert.equal(node.writes, 1, scenario.name + ': existing line not rewritten');
		}
		assert.ok(panel.innerHTML.startsWith(app.context.highlightLog('Initializing scan...') + '\n'));
		for (const line of setupLines) assert.ok(panel.innerHTML.includes(app.context.highlightLog(line)));
		const expectedLines = scenario.logs === '' ? ['cg version test', 'Repeated message'] : finalLines.filter(line => line.trim());
		assert.deepEqual(scanner.children.map(node => node.innerHTML), expectedLines.map(line => app.context.highlightLog(line) + '\n'), scenario.name);
		if (scenario.name === 'full stream' || scenario.logs === '') assert.equal(panel.innerHTML, before);
		assert.equal(app.history()[0].logs, panel.innerHTML);
		assert.equal(stream.closed, true);
		const completed = panel.innerHTML;
		stream.onmessage({ data: 'late message', lastEventId: 'scanner-6' });
		assert.equal(panel.innerHTML, completed);
	}
});
