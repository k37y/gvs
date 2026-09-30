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
