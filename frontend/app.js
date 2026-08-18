const messageInput = document.getElementById("message");
const urlInput = document.getElementById("url");
const analyzeButton = document.getElementById("analyze-button");
const resetButton = document.getElementById("reset-button");

const buttonText = document.querySelector(".button-text");
const buttonLoader = document.querySelector(".button-loader");

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


function formatPattern(value) {
    return value
        .replaceAll("_", " ")
        .replace(/\b\w/g, character => character.toUpperCase());
}


function renderList(container, items) {
    container.innerHTML = "";

    if (!items || items.length === 0) {
        const empty = document.createElement("div");
        empty.className = "result-item";
        empty.textContent = "None detected";
        container.appendChild(empty);
        return;
    }

    items.forEach(item => {
        const div = document.createElement("div");
        div.className = "result-item";
        div.textContent = item;
        container.appendChild(div);
    });
}


function renderTags(container, items) {
    container.innerHTML = "";

    if (!items || items.length === 0) {
        const empty = document.createElement("div");
        empty.className = "result-item";
        empty.textContent = "None detected";
        container.appendChild(empty);
        return;
    }

    items.forEach(item => {
        const tag = document.createElement("span");
        tag.className = "tag";
        tag.textContent = formatPattern(item);
        container.appendChild(tag);
    });
}


function renderFindings(container, findings) {
    container.innerHTML = "";

    if (!findings || findings.length === 0) {
        const empty = document.createElement("div");
        empty.className = "result-item";
        empty.textContent = "None detected";
        container.appendChild(empty);
        return;
    }

    findings.forEach(finding => {
        const div = document.createElement("div");
        div.className = "result-item";
        div.textContent = formatPattern(finding.category);
        container.appendChild(div);
    });
}


function applyRiskState(element, level) {
    element.dataset.level = level;

    const levels = {
        MINIMAL: "var(--success)",
        LOW: "var(--success)",
        MODERATE: "var(--warning)",
        HIGH: "var(--danger)",
        CRITICAL: "var(--danger)"
    };

    const selectedColor =
        levels[level] || "var(--muted)";

    element.style.color = selectedColor;
    element.style.borderColor = selectedColor;
}


function renderResults(data) {

    overallScore.textContent =
        `${data.overall_risk.score} / 100`;

    overallLevel.textContent =
        data.overall_risk.level;

    applyRiskState(
        overallLevel,
        data.overall_risk.level
    );


    messageRiskScore.textContent =
        `${data.message_risk.score} / 100`;

    messageRiskLevel.textContent =
        data.message_risk.level;

    applyRiskState(
        messageRiskLevel,
        data.message_risk.level
    );


    urlRiskScore.textContent =
        `${data.url_risk.score} / 100`;

    urlRiskLevel.textContent =
        data.url_risk.level;

    applyRiskState(
        urlRiskLevel,
        data.url_risk.level
    );


    renderTags(
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

    results.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


function resetDashboard() {
    messageInput.value = "";
    urlInput.value = "";
    messageCount.textContent = "0 / 5000";

    clearError();

    results.classList.add("hidden");

    overallScore.textContent = "-- / 100";
    overallLevel.textContent = "--";

    messageRiskScore.textContent = "-- / 100";
    messageRiskLevel.textContent = "--";

    urlRiskScore.textContent = "-- / 100";
    urlRiskLevel.textContent = "--";

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });

    messageInput.focus();
}


analyzeButton.addEventListener("click", async () => {

    clearError();

    const message = messageInput.value;
    const url = urlInput.value.trim();

    if (!message.trim()) {
        showError(
            "Please enter a message to analyze."
        );

        messageInput.focus();
        return;
    }


    analyzeButton.disabled = true;
    buttonText.textContent = "ANALYZING";
    buttonLoader.classList.remove("hidden");


    try {

        const response = await fetch(
            "/analyze",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message,
                    url: url || null
                })
            }
        );


        const data = await response.json();


        if (!response.ok) {
            throw new Error(
                data.detail ||
                "The analysis request failed."
            );
        }


        renderResults(data);

    } catch (error) {

        showError(
            error.message ||
            "Unable to complete the analysis."
        );

    } finally {

        analyzeButton.disabled = false;
        buttonText.textContent = "ANALYZE THREAT";
        buttonLoader.classList.add("hidden");
    }
});


resetButton.addEventListener(
    "click",
    resetDashboard
);
