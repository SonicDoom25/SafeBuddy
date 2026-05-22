async function checkURL() {

    const url =
        document.getElementById("urlInput").value;

    if (!url) {

        alert("Please enter a URL");
        return;
    }

    document
        .getElementById("loadingBox")
        .classList.remove("hidden");

    try {

        const response = await fetch('/check-url', {

            method: 'POST',

            headers: {
                'Content-Type': 'application/json'
            },

            body: JSON.stringify({ url })

        });

        const data = await response.json();

        localStorage.setItem(
            "safebuddyResult",
            JSON.stringify(data)
        );

        window.location.href = "/result";

    } catch (error) {

        console.error(error);

        alert(
            "Unable to analyze URL right now."
        );
    }
}

/* ================= RESULT PAGE ================= */

window.onload = function () {

    const resultCard =
        document.getElementById("resultCard");

    if (!resultCard) return;

    const data =
        JSON.parse(
            localStorage.getItem("safebuddyResult")
        );

    if (!data) return;

    // SAFE

    if (data.safe) {

        resultCard.innerHTML = `

            <div class="result-icon safe-glow">
                🟢
            </div>

            <h1>
                This Website Appears Safe
            </h1>

            <p class="result-text">

                No phishing, malware,
                or suspicious threat patterns
                were detected.

            </p>

            <div class="severity low">
                LOW RISK
            </div>

            <div class="url-box">
                ${data.url}
            </div>

            <button class="primary-btn"
                    onclick="window.location.href='/'">

                Check Another URL

            </button>

        `;
    }

    // UNSAFE

    else {

        resultCard.innerHTML = `

            <div class="result-icon danger-glow">
                ⚠️
            </div>

            <h1>
                Potential Threat Detected
            </h1>

            <p class="result-text">

                This website shows patterns
                commonly associated with
                phishing or malicious behavior.

            </p>

            <div class="severity high">
                HIGH RISK
            </div>

            <div class="url-box">
                ${data.url}
            </div>

            <div class="threat-title">
                Detected Threats
            </div>

            <div class="threat-list">

                ${data.threats.map(
                    t => `
                        <div class="threat-card">
                            ${formatThreat(t)}
                        </div>
                    `
                ).join('')}

            </div>

            <div class="result-buttons">

                <button class="primary-btn"
                        onclick="window.location.href='unsafe_reason.html'">

                    Learn Why This Is Risky

                </button>

                <button class="secondary-btn"
                        onclick="window.location.href='/'">

                    Go Back Safely

                </button>

            </div>

        `;
    }
}

/* ================= THREAT FORMAT ================= */

function formatThreat(threat){

    switch(threat){

        case "SOCIAL_ENGINEERING":
            return "Phishing Attempt";

        case "MALWARE":
            return "Malware Risk";

        case "UNWANTED_SOFTWARE":
            return "Unwanted Software";

        case "POTENTIALLY_HARMFUL_APPLICATION":
            return "Potentially Harmful App";

        default:
            return threat;
    }
}