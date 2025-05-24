let scanInProgress = false;

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

	json = json.replace(/`([^`]+)`/g, "<code>$1</code>");

    json = json.replace(/\\n/g, "<br>");

    json = json.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");

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
	const branch = document.getElementById("branch").value.trim();
	const cve = document.getElementById("cve").value.trim();
	const outputDiv = document.getElementById("output");
	const scanButton = document.getElementById("scanButton");

	outputDiv.style.display = "none";
	outputDiv.className = "result-card";
	outputDiv.innerHTML = "";
	scanButton.disabled = true;
	scanButton.innerText = "Scanning...";

	if (repo && branch && cve) {
		const hostUrl = `${location.protocol}//${location.host}`;
	outputDiv.innerHTML = getRandomSustainingQuestion();
	outputDiv.classList.add("alert-warning");
	outputDiv.style.display = "block";

	fetch("/callgraph", {
		method: "POST",
		headers: {
			"Content-Type": "application/json"
		},
		body: JSON.stringify({ repo, branch, cve })
	})
		.then(response => response.json())
		.then(data => {
			if (data.error) {
				outputDiv.innerHTML = "";
				outputDiv.innerHTML = `<strong>Error:</strong> ${data.error}<br>`;
				outputDiv.classList.add("alert-danger");
				cleanup()
				return;
			}

			const taskId = data.taskId;
			pollStatus(taskId);
		})
		.catch(err => {
			outputDiv.innerHTML += `<strong>Network Error:</strong> ${err.message}<br>`;
			outputDiv.classList.add("alert-danger");
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
		body: JSON.stringify({ repo, branch }),
		signal: controller.signal,
	})
		.then(response => response.json())
		.then(data => {
			let message = "";

			if (data.error === "Another scan is in progress. Please wait.") {
				message = `<strong>${data.error}</strong>`;
				alertClass = "alert-warning";
			} else if (data.exit_code === 1) {
				message = `<strong>Error:</strong> ${data.error || "Unknown error occurred."}`;
				alertClass = "alert-danger";
			} else {
				message = `<pre class='text-break'>${syntaxHighlight(JSON.stringify(data, null, 2))}</pre>`;
			}

			outputDiv.innerHTML = message;
			outputDiv.classList.remove("alert-success", "alert-danger", "alert-warning");
			outputDiv.classList.add("alert-success");
			outputDiv.style.display = "block";
		})
		.catch(error => {
			const errMsg = error.name === "AbortError"
				? "Request timed out (360 sec)"
				: error.message || error;
			outputDiv.innerHTML = `<strong>Error:</strong> ${errMsg}`;
			outputDiv.classList.add("alert-danger");
			outputDiv.style.display = "block";
		})
		.finally(() => {
			clearTimeout(timeoutId);
			cleanup();
		});
}

function pollStatus(taskId) {
	const pollInterval = 3000;
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
					cleanup();
				}

				outputDiv.scrollTop = outputDiv.scrollHeight;
			})
			.catch(err => {
				outputDiv.innerHTML = "";
				outputDiv.innerHTML = `<br><strong>Error polling status:</strong> ${err.message}<br>`;
				outputDiv.classList.add("alert-danger");
				clearInterval(intervalId);
				cleanup();
			});
	}, pollInterval);
}

function cleanup() {
	scanButton.disabled = false;
	scanButton.innerText = "Run Scan";
	scanInProgress = false;
}
}
