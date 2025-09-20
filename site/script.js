let scanInProgress = false;

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
	
	// Add event listener to CVE ID field to automatically set Run Fix to "No" and disable when empty
	const cveInput = document.getElementById('cve');
	const fixSelect = document.getElementById('fix');
	
	function updateRunFixState() {
		if (cveInput.value.trim() === '') {
			fixSelect.value = 'false';
			fixSelect.disabled = true;
		} else {
			fixSelect.disabled = false;
		}
	}
	
	// Initialize Run Fix state on page load
	updateRunFixState();
	
	// Update Run Fix state whenever CVE input changes
	cveInput.addEventListener('input', updateRunFixState);
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

		json = json
		.replace(/("(\w+)":)/g, '<span class="highlight-key">$1</span>')
		.replace(/(:\s*")([^"]*?)(")/g, ': <span class="highlight-value">"$2"</span>')
			.replace(/(:\s*(\d+))/g, ': <span class="highlight-value">$2</span>');

			return json;
		}

function runScan() {
	if (scanInProgress) return;
	scanInProgress = true;

	const repo = document.getElementById("repo").value.trim();
	const branchOrCommit = document.getElementById("branchOrCommit").value.trim();
	const cve = document.getElementById("cve").value.trim();
	// Automatically set fix to false if CVE ID is empty
	const fix = cve ? document.getElementById("fix").value === "true" : false;
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

	if (repo && branchOrCommit && cve) {
		const hostUrl = `${location.protocol}//${location.host}`;
		outputDiv.innerHTML = getRandomSustainingQuestion();
		outputDiv.classList.add("alert-warning");
		outputDiv.style.display = "block";

		fetch("/callgraph", {
			method: "POST",
			headers: {
				"Content-Type": "application/json"
			},
			body: JSON.stringify({ repo, branchOrCommit, cve, fix: fix, showProgress: true })
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

		fetch("/scan", {
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
			fetch("/status", {
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
	const eventSource = new EventSource(`/progress/${taskId}`);
	
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
