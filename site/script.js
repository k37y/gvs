let scanInProgress = false;

// API Configuration
const API_BASE_URL = (window.GVS_CONFIG && window.GVS_CONFIG.API_BASE_URL) || '';

// Form Field History Manager
class FormHistoryManager {
	constructor() {
		this.maxHistoryItems = 10;
		this.storagePrefix = 'gvs-history-';
		this.fields = ['repo', 'branchOrCommit', 'cve', 'library', 'symbol', 'fixversion'];
		this.init();
	}
	
	init() {
		this.setupHistoryForFields();
		this.loadHistoryForFields();
	}
	
	setupHistoryForFields() {
		this.fields.forEach(fieldId => {
			const field = document.getElementById(fieldId);
			if (field) {
				// Create datalist for autocomplete
				const datalistId = `${fieldId}-history`;
				let datalist = document.getElementById(datalistId);
				if (!datalist) {
					datalist = document.createElement('datalist');
					datalist.id = datalistId;
					field.parentNode.appendChild(datalist);
					field.setAttribute('list', datalistId);
				}
				
				// Save to history on blur (when user leaves the field)
				field.addEventListener('blur', () => {
					const value = field.value.trim();
					if (value) {
						this.saveToHistory(fieldId, value);
						this.updateDatalist(fieldId);
					}
				});
			}
		});
	}
	
	saveToHistory(fieldId, value) {
		const storageKey = this.storagePrefix + fieldId;
		let history = this.getHistory(fieldId);
		
		// Remove value if it already exists (to avoid duplicates)
		history = history.filter(item => item !== value);
		
		// Add new value to the beginning
		history.unshift(value);
		
		// Limit history size
		if (history.length > this.maxHistoryItems) {
			history = history.slice(0, this.maxHistoryItems);
		}
		
		localStorage.setItem(storageKey, JSON.stringify(history));
	}
	
	getHistory(fieldId) {
		const storageKey = this.storagePrefix + fieldId;
		try {
			const stored = localStorage.getItem(storageKey);
			return stored ? JSON.parse(stored) : [];
		} catch (e) {
			console.warn('Failed to parse history for field:', fieldId);
			return [];
		}
	}
	
	updateDatalist(fieldId) {
		const datalist = document.getElementById(`${fieldId}-history`);
		const history = this.getHistory(fieldId);
		
		if (datalist) {
			datalist.innerHTML = '';
			history.forEach(value => {
				const option = document.createElement('option');
				option.value = value;
				datalist.appendChild(option);
			});
		}
	}
	
	loadHistoryForFields() {
		this.fields.forEach(fieldId => {
			this.updateDatalist(fieldId);
		});
	}
	
	clearHistory(fieldId = null) {
		if (fieldId) {
			localStorage.removeItem(this.storagePrefix + fieldId);
			this.updateDatalist(fieldId);
		} else {
			// Clear all history
			this.fields.forEach(field => {
				localStorage.removeItem(this.storagePrefix + field);
				this.updateDatalist(field);
			});
		}
	}
}

// Dark Mode Toggle Functionality
class ThemeManager {
	constructor() {
		this.themeToggle = document.getElementById('themeToggle');
		this.themeIcon = document.getElementById('themeIcon');
		this.currentTheme = localStorage.getItem('theme') || 'light';
		
		this.init();
	}
	
	init() {
		this.applyTheme(this.currentTheme);
		this.themeToggle.addEventListener('click', () => this.toggleTheme());
	}
	
	toggleTheme() {
		this.currentTheme = this.currentTheme === 'light' ? 'dark' : 'light';
		this.applyTheme(this.currentTheme);
		localStorage.setItem('theme', this.currentTheme);
	}
	
	applyTheme(theme) {
		document.documentElement.setAttribute('data-theme', theme);
		this.themeIcon.className = theme === 'light' ? 'theme-icon moon' : 'theme-icon sun';
		this.themeToggle.setAttribute('aria-label', 
			theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'
		);
	}
}

// Initialize all components on DOM content loaded
document.addEventListener('DOMContentLoaded', function() {
	// Initialize theme manager
	new ThemeManager();
	
	// Initialize form history manager
	window.formHistory = new FormHistoryManager();
	
	// Add event listener to CVE ID, Library, and Symbol fields
	const cveInput = document.getElementById('cve');
	const libraryInput = document.getElementById('library');
	const symbolInput = document.getElementById('symbol');
	
	window.validateCVEInput = function() {
		const value = cveInput.value.trim();
		if (value === '') {
			cveInput.setCustomValidity('');
			return true;
		}
		
		// Check if input matches CVE ID format (CVE-YYYY-NNNN) or GOCVE ID format (GO-YYYY-NNNN)
		const cvePattern = /^CVE-\d{4}-\d{4,}$/;
		const gocvePattern = /^GO-\d{4}-\d{4,}$/;
		
		if (cvePattern.test(value) || gocvePattern.test(value)) {
			cveInput.setCustomValidity('');
			return true;
		} else {
			cveInput.setCustomValidity('Please enter a valid CVE ID (CVE-YYYY-NNNN) or GOCVE ID (GO-YYYY-NNNN)');
			return false;
		}
	}
	
	// Validate CVE input on change
	cveInput.addEventListener('input', function() {
		window.validateCVEInput();
	});
});

const sustainingQuestions = [
	"If we fix a bug in a legacy system and no one merges it, did we really fix it?",
	"How old does code have to be before it qualifies for retirement benefits?",
	"Is it still called 'tech debt' if the product has outlived the engineer who wrote it?",
	"What came first: the bug or the workaround?",
	"If we backport a bug, does that count as forward progress?",
	"How many layers of legacy before we legally declare it fossilized?",
	"Are we software engineers or digital archaeologists?",
	"If a build fails in an EUS branch and no one’s watching Jenkins, is it really broken?",
	"Can you call it regression testing if the feature never worked to begin with?",
	"Is 'Works on my legacy VM' a valid test result?",
	"Why do all the critical bugs only exist in the versions we no longer support?",
	"Is supporting EUS just time travel with extra logging?",
	"If it’s undocumented and still runs in prod, is it magic or a bug?",
	"If the product is EOL, but still under EUS, are we reviving it or just babysitting it?",
	"Is fixing bugs in legacy code a science, an art, or an exorcism?"
];

function getRandomSustainingQuestion() {
	const question = sustainingQuestions[Math.floor(Math.random() * sustainingQuestions.length)];
	return `This takes a while. Meanwhile, think about:<br><em>"${question}"</em><br>`;
}

function syntaxHighlight(json) {
	json = json.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;");

	json = json.replace(/```(\w+)?\n([\s\S]*?)```/g, (match, lang, code) => {
		const language = lang || "text";
		return `<pre><code class="language-${language}">${code.trim()}</code></pre>`;
	});

	json = json.replace(/\\n/g, "<br>");

	json = json.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");

	json = json.replace(/^##(.*)$/gm, "<strong>$1</strong>");

	json = json.replace(/\\"/g, "&quot;");

	// Convert graph URLs to clickable links BEFORE other highlighting (to preserve URL structure)
	// Matches http/https URLs ending with .svg
	json = json.replace(/"(https?:\/\/[^"]+\.svg)"/g, function(match, url) {
		return '"<a href="' + url + '" target="_blank" rel="noopener noreferrer" class="graph-link">' + url + '</a>"';
	});

	// Apply syntax highlighting, but skip URLs inside <a> tags
	json = json
		.replace(/("(\w+)":)/g, '<span class="highlight-key">$1</span>')
		.replace(/(:\s*")(?![^"]*<a href)([^"]*?)(")/g, ':<span class="highlight-value">"$2"</span>')
		.replace(/(:\s*(\d+))(?![^<]*<\/a>)/g, ':<span class="highlight-value">$2</span>');

	return json;
}

function runScan() {
	if (scanInProgress) return;

	// Validate CVE input before proceeding
	const cveInput = document.getElementById("cve");
	if (!window.validateCVEInput()) {
		cveInput.reportValidity();
		return;
	}

	// Get form values early to validate manual scan fields
	const libraryInput = document.getElementById("library");
	const symbolInput = document.getElementById("symbol");
	const fixversionInput = document.getElementById("fixversion");

	const library = libraryInput.value.trim();
	const symbol = symbolInput.value.trim();
	const fixversion = fixversionInput.value.trim();

	// Validate that library, symbol, and fixversion are all provided together
	const libraryProvided = library !== "";
	const symbolProvided = symbol !== "";
	const fixversionProvided = fixversion !== "";
	const anyManualScanFieldProvided = libraryProvided || symbolProvided || fixversionProvided;

	// Reset validation styling
	libraryInput.style.border = "";
	symbolInput.style.border = "";
	fixversionInput.style.border = "";

	if (anyManualScanFieldProvided) {
		if (!libraryProvided || !symbolProvided || !fixversionProvided) {
			// Highlight missing fields in red
			if (!libraryProvided) libraryInput.style.border = "2px solid red";
			if (!symbolProvided) symbolInput.style.border = "2px solid red";
			if (!fixversionProvided) fixversionInput.style.border = "2px solid red";

			// Focus on the first missing field
			if (!libraryProvided) {
				libraryInput.focus();
			} else if (!symbolProvided) {
				symbolInput.focus();
			} else if (!fixversionProvided) {
				fixversionInput.focus();
			}
			return;
		}
	}

	scanInProgress = true;

	const repo = document.getElementById("repo").value.trim();
	const branchOrCommit = document.getElementById("branchOrCommit").value.trim();
	const cve = document.getElementById("cve").value.trim();
	const algo = document.getElementById("algo").value;
	const graph = (cve || (library && symbol)) ? document.getElementById("graph").value === "true" : false;
	const outputDiv = document.getElementById("output");
	const progressContent = document.getElementById("progressContent");
	const scanButton = document.getElementById("scanButton");

	outputDiv.style.display = "none";
	outputDiv.className = "result-card";
	outputDiv.innerHTML = "";
	
	// Clear previous progress output and initialize new scan
	const timestamp = new Date().toLocaleTimeString();
	progressContent.innerHTML = `Scan Started at ${timestamp}\nInitializing scan...\n`;
	// Auto-expand progress card when scan starts
	expandProgressCard();
	
	scanButton.disabled = true;
	scanButton.innerText = "Scanning...";
	
	// Save form values to history when scan starts
	if (repo) {
		window.formHistory?.saveToHistory('repo', repo);
		window.formHistory?.updateDatalist('repo');
	}
	if (branchOrCommit) {
		window.formHistory?.saveToHistory('branchOrCommit', branchOrCommit);
		window.formHistory?.updateDatalist('branchOrCommit');
	}
	if (cve) {
		window.formHistory?.saveToHistory('cve', cve);
		window.formHistory?.updateDatalist('cve');
	}
	if (library) {
		window.formHistory?.saveToHistory('library', library);
		window.formHistory?.updateDatalist('library');
	}
	if (symbol) {
		window.formHistory?.saveToHistory('symbol', symbol);
		window.formHistory?.updateDatalist('symbol');
	}
	if (fixversion) {
		window.formHistory?.saveToHistory('fixversion', fixversion);
		window.formHistory?.updateDatalist('fixversion');
	}

	// Use callgraph endpoint if CVE is provided, or if library and symbol are provided for direct scanning
	if (repo && branchOrCommit && (cve || (library && symbol))) {
		const hostUrl = `${location.protocol}//${location.host}`;
		outputDiv.innerHTML = getRandomSustainingQuestion();
		outputDiv.classList.add("alert-warning");
		outputDiv.style.display = "block";

		fetch(`${API_BASE_URL}/callgraph`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json"
			},
			body: JSON.stringify({ repo, branchOrCommit, cve, library, symbol, fixversion, algo, graph, showProgress: true })
		})
			.then(response => response.json())
			.then(data => {
				if (data.error) {
					outputDiv.innerHTML = "";
					outputDiv.innerHTML = `<strong>Error:</strong> ${data.error}<br>`;
					outputDiv.classList.add("alert-danger");
					
					// Add error message to progress output
					progressContent.innerHTML += `Error: ${data.error}\n`;
					progressContent.scrollTop = progressContent.scrollHeight;
					
					cleanup()
					return;
				}

				const taskId = data.taskId;
				pollStatus(taskId, true);
			})
			.catch(err => {
				outputDiv.innerHTML += `<strong>Network Error:</strong> ${err.message}<br>`;
				outputDiv.classList.add("alert-danger");
				
				// Add error message to progress output
				progressContent.innerHTML += `Network Error: ${err.message}\n`;
				progressContent.scrollTop = progressContent.scrollHeight;
			});

	} else {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 360000);

		outputDiv.innerHTML = getRandomSustainingQuestion();
		outputDiv.classList.remove("alert-success", "alert-danger", "alert-warning");
		outputDiv.classList.add("alert-warning");
		outputDiv.style.display = "block";

		fetch(`${API_BASE_URL}/scan`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ repo, branchOrCommit, showProgress: true }),
			signal: controller.signal,
		})
			.then(response => response.json())
			.then(data => {
				if (data.error) {
					outputDiv.innerHTML = "";
					outputDiv.innerHTML = `<strong>Error:</strong> ${data.error}<br>`;
					outputDiv.classList.add("alert-danger");
					
					// Add error message to progress output
					progressContent.innerHTML += `Error: ${data.error}\n`;
					progressContent.scrollTop = progressContent.scrollHeight;
					
					cleanup()
					return;
				}

				const taskId = data.taskId;
				pollStatus(taskId, true);
			})
			.catch(error => {
				const errMsg = error.name === "AbortError"
					? "Request timed out (360 sec)"
					: error.message || error;
				outputDiv.innerHTML = `<strong>Error:</strong> ${errMsg}`;
				outputDiv.classList.add("alert-danger");
				outputDiv.style.display = "block";
				
				// Add error message to progress output
				progressContent.innerHTML += `Network Error: ${errMsg}\n`;
				progressContent.scrollTop = progressContent.scrollHeight;
			})
			.finally(() => {
				clearTimeout(timeoutId);
			});
	}

	function pollStatus(taskId, showProgress) {
		const pollInterval = 3000;
		const progressContent = document.getElementById("progressContent");
		
		// Always start progress streaming
		startProgressStream(taskId);
		
		const intervalId = setInterval(() => {
			fetch(`${API_BASE_URL}/status`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json"
				},
				body: JSON.stringify({ taskId })
			})
				.then(response => response.json())
				.then(statusData => {
					if (statusData.error) {
						outputDiv.innerHTML = "";
						outputDiv.innerHTML = `<strong>Error:</strong> ${statusData.error}<br>`;
						outputDiv.classList.add("alert-danger");
						
						// Add error message to progress output
						const progressContent = document.getElementById("progressContent");
						const timestamp = new Date().toLocaleTimeString();
						progressContent.innerHTML += `Scan Failed at ${timestamp}: ${statusData.error}\n`;
						progressContent.scrollTop = progressContent.scrollHeight;
						
						clearInterval(intervalId);
						cleanup();
						return;
					}

					if (statusData.status === "completed") {
						outputDiv.innerHTML = "";
						outputDiv.innerHTML = `<pre>${syntaxHighlight(JSON.stringify(statusData.output, null, 2))}</pre>`;
						outputDiv.classList.remove("alert-warning");
						outputDiv.classList.add("alert-success");
						clearInterval(intervalId);
						
						// Add completion message to progress output
						const progressContent = document.getElementById("progressContent");
						const timestamp = new Date().toLocaleTimeString();
						progressContent.innerHTML += `Scan Completed Successfully at ${timestamp}\n`;
						progressContent.scrollTop = progressContent.scrollHeight;
						
						// Close progress stream if active
						if (window.currentProgressStream) {
							window.currentProgressStream.close();
							window.currentProgressStream = null;
						}
						
						cleanup();
					}

					outputDiv.scrollTop = outputDiv.scrollHeight;
				})
				.catch(err => {
					outputDiv.innerHTML = "";
					outputDiv.innerHTML = `<br><strong>Error polling status:</strong> ${err.message}<br>`;
					outputDiv.classList.add("alert-danger");
					
					// Add error message to progress output
					const progressContent = document.getElementById("progressContent");
					progressContent.innerHTML += `Network Error: ${err.message}\n`;
					progressContent.scrollTop = progressContent.scrollHeight;
					
					clearInterval(intervalId);
					cleanup();
				});
		}, pollInterval);
	}

	function cleanup() {
		scanButton.disabled = false;
		scanButton.innerText = "Run Scan";
		scanInProgress = false;
		
		// Close progress stream if active
		if (window.currentProgressStream) {
			window.currentProgressStream.close();
			window.currentProgressStream = null;
		}
		
		// Keep progress output visible after scan completion
		// Don't reset the progress card here
	}
}

function startProgressStream(taskId) {
	const progressContent = document.getElementById("progressContent");

	// Use Server-Sent Events for real-time progress updates
	const eventSource = new EventSource(`${API_BASE_URL}/progress/${taskId}`);
	
	eventSource.onmessage = function(event) {
		const data = event.data;
		if (data && data.trim()) {
			progressContent.innerHTML += data + '\n';
			progressContent.scrollTop = progressContent.scrollHeight;
		}
	};
	
	eventSource.onerror = function(event) {
		console.log('Progress stream error:', event);
		eventSource.close();
	};
	
	// Store reference to close later
	window.currentProgressStream = eventSource;
}

function handleCardClick(event) {
	// Prevent expansion when clicking on form elements
	const clickableElements = ['INPUT', 'SELECT', 'BUTTON', 'LABEL', 'SPAN'];
	const isFormElement = clickableElements.includes(event.target.tagName);
	const isTooltip = event.target.hasAttribute('data-bs-toggle');
	
	if (isFormElement || isTooltip) {
		return;
	}
	
	toggleProgressExpansion();
}

function toggleProgressExpansion() {
	const progressContent = document.getElementById("progressContent");
	
	if (progressContent.classList.contains("collapsed")) {
		expandProgressCard();
	} else {
		collapseProgressCard();
	}
}

function expandProgressCard() {
	const progressContent = document.getElementById("progressContent");
	progressContent.classList.remove("collapsed");
}

function collapseProgressCard() {
	const progressContent = document.getElementById("progressContent");
	progressContent.classList.add("collapsed");
}

function resetProgressCard() {
	const progressContent = document.getElementById("progressContent");
	
	// Reset to collapsed state with placeholder (only used on page load)
	collapseProgressCard();
	progressContent.innerHTML = '<div class="progress-placeholder">Server progress will appear here during scans. Progress from previous scans is preserved until the next scan starts.</div>';
}
