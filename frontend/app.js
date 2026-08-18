const messageInput = document.getElementById("message");
const urlInput = document.getElementById("url");
const analyzeButton = document.getElementById("analyze-button");

const messageCount = document.getElementById("message-count");
const errorBox = document.getElementById("error");
const results = document.getElementById("results");

const overallScore = document.getElementById("overall-score");
const overallLevel = document.getElementById("overall-level");

const messageRiskScore =
    document.getElementById("message-risk-score");

const messageRiskLevel =
    document.getElementById("message-risk-level");

const urlRiskScore =
    document.getElementById("url-risk-score");

const urlRiskLevel =
    document.getElementById("url-risk-level");

const attackPatterns =
    document.getElementById("attack-patterns");

const indicators =
    document.getElementById("indicators");

const explanations =
    document.getElementById("explanations");

const recommendations =
    document.getElementById("recommendations");

const priorityActions =
    document.getElementById("priority-actions");


messageInput.addEventListener("input", () => {
    messageCount.textContent =
        `${messageInput.value.length} / 5000`;
});


function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
}


function clearError() {
    errorBox.textContent = "";
    errorBox.classList.add("hidden");
}


function renderList(container, items) {
    container.innerHTML = "";

    if (!items || items.length === 0) {
        container.innerHTML =
            '<div class="result-item">None detected</div>';
        return;
    }

    items.forEach(item => {
        const div = document.createElement("div");
        div.className = "result-item";
        div.textContent = item;
        container.appendChild(div);
    });
}


function renderFindings(container, findings) {
    container.innerHTML = "";

    if (!findings || findings.length === 0) {
        container.innerHTML =
            '<div class="result-item">None detected</div>';
        return;
    }

    findings.forEach(finding => {
        const div = document.createElement("div");
        div.className = "result-item";
        div.textContent = finding.category;
        container.appendChild(div);
    });
}


function renderResults(data) {
    overallScore.textContent =
        `${data.overall_risk.score} / 100`;

    overallLevel.textContent =
        data.overall_risk.level;

    messageRiskScore.textContent =
        `${data.message_risk.score} / 100`;

    messageRiskLevel.textContent =
        data.message_risk.level;

    urlRiskScore.textContent =
        `${data.url_risk.score} / 100`;

    urlRiskLevel.textContent =
        data.url_risk.level;

    renderList(
        attackPatterns,
        data.attack_patterns
    );

    renderFindings(
        indicators,
        [
            ...data.message_findings,
            ...data.url_findings
        ]
    );

    renderList(
        explanations,
        data.recommendations.explanations
    );

    renderList(
        recommendations,
        data.recommendations.recommendations
    );

    renderList(
        priorityActions,
        data.recommendations.priority_actions
    );

    results.classList.remove("hidden");
}


analyzeButton.addEventListener("click", async () => {

    clearError();

    const message = messageInput.value;
    const url = urlInput.value.trim();

    if (!message.trim()) {
        showError("Please enter a message to analyze.");
        return;
    }

    analyzeButton.disabled = true;
    analyzeButton.textContent = "ANALYZING...";

    try {

        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message,
                url: url || null
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail ||
                "The analysis request failed."
            );
        }

        renderResults(data);

    } catch (error) {
        showError(error.message);
    } finally {
        analyzeButton.disabled = false;
        analyzeButton.textContent = "ANALYZE";
    }
});
