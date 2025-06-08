document.addEventListener('DOMContentLoaded', () => {
    const scanButton = document.getElementById('scanButton');
    const progressContainer = document.getElementById('progressContainer');

    const socket = io();

    // Track current progress
    let currentProgress = 0;
    let progressInterval;

    // Handle socket connection
    socket.on('connect', () => {
        console.log('Connected via WebSocket:', socket.id);
    });

    // Step-to-percentage mapping
    const stepProgress = {
        "Validating URL": 5,
        "Checking SSL Certificate": 15,
        "Checking Domain Age": 25,
        "Checking for Suspicious Keywords": 35,
        "Checking Redirects": 45,
        "Checking Threat Databases": 60,
        "Checking IP Reputation": 75,
        "Checking DNS Records": 85,
        "Calculating Risk Score": 95,
        "Scan Complete": 100
    };

    // Receive real-time scan progress from server
    socket.on('scan_progress', data => {
        console.log(`Progress update: ${data.step} (${data.detail})`);
        const newProgress = stepProgress[data.step] || currentProgress;
        clearInterval(progressInterval);

        // Force show progress bar
        progressContainer.classList.remove('hidden');
        progressContainer.classList.add('visible');

        updateProgressText(`${data.step} - ${data.detail}`);
        updateProgressBar(newProgress);

        progressInterval = setInterval(() => {
            if (currentProgress < newProgress) {
                currentProgress += 1;
                updateProgressBar(currentProgress);
            } else {
                clearInterval(progressInterval);
            }
        }, 30);
    });


    scanButton.addEventListener('click', async () => {
        const rawUrl = document.getElementById('scanInput').value.trim();

        if (!rawUrl) {
            alert('Please enter a valid URL.');
            return;
        }

        let scanUrl;
        try {
            let fixedUrl = rawUrl;
            if (!/^https?:\/\//i.test(fixedUrl)) {
                fixedUrl = 'http://' + fixedUrl;
            }
            new URL(fixedUrl); // Validate
            scanUrl = fixedUrl;
        } catch (error) {
            alert('Invalid URL format.');
            return;
        }


        // Reset progress UI
        currentProgress = 0;
        updateProgressBar(0);
        updateProgressText('Starting scan...');
        progressContainer.classList.remove('hidden');
        progressContainer.classList.add('visible');

        // UI: Start loading
        scanButton.classList.add('button-loading');
        scanButton.querySelector('.spinner').classList.remove('hidden');
        scanButton.disabled = true;

        try {
            const response = await fetch(`/scan-url?sid=${socket.id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: rawUrl }),
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server error: ${errorText}`);
            }

            const result = await response.json();
            updateProgressBar(100);
            updateProgressText('Scan complete.');

            setTimeout(() => {
                progressContainer.classList.add('hidden');
                progressContainer.classList.remove('visible');
                updateProgressBar(0);
                updateProgressText('0%');
            }, 1000);

            // Animate result sections
            ['riskAssessment', 'keyIndicators', 'databaseComparison', 'technicalReport'].forEach((id, index) => {
                const element = document.getElementById(id);
                if (element) {
                    element.classList.remove('hidden');
                    setTimeout(() => {
                        element.classList.add('visible');
                    }, 200 * index);
                }
            });

            const communityReportsSection = document.getElementById('communityReports');
            if (communityReportsSection) {
                communityReportsSection.classList.remove('hidden');
                setTimeout(() => {
                    communityReportsSection.classList.add('visible');
                }, 1400);
            }

            // Render scan result data
            updateRiskScore(result.risk_score);
            updateRiskTexts(result.risk_score);

            document.querySelector('.ssl .indicator-status').textContent =
                result.ssl_certificate.valid ? 'Valid' : 'Invalid';
            document.querySelector('.ssl .indicator-text').textContent =
                result.ssl_certificate.details || 'No issues detected';

            document.querySelector('.domain .indicator-status').textContent =
                result.domain_age.status;
            document.querySelector('.domain .indicator-text').textContent =
                `Domain age: ${result.domain_age.age_days} days`;

            document.querySelector('.keywords .indicator-status').textContent =
                result.keywords.detected ? 'Detected' : 'Not Detected';
            document.querySelector('.keywords .indicator-text').textContent =
                result.keywords.keywords_found.join(', ') || 'No suspicious keywords found';

            const dbGrid = document.querySelector('.database-grid');
            dbGrid.innerHTML = '';
            result.threat_databases.forEach((db) => {
                const dbItem = document.createElement('div');
                dbItem.classList.add('database-item');
                dbItem.innerHTML = `
                    <img src="/static/images/${
                        db.name.toLowerCase().includes('google') ? 'google-safe.svg' : 'phishtank-logo.svg'
                    }" alt="${db.name}" class="db-logo">
                    <div class="db-status ${db.status === 'Reported' ? 'reported' : 'clean'}">${db.status}</div>
                    <div class="db-update">Last checked: Just now</div>
                `;
                dbGrid.appendChild(dbItem);
            });

            const techDetails = result.ip_reputation;
            document.querySelector('.tech-value.ip-address').textContent = techDetails.ip_address || 'Unknown';
            document.querySelector('.tech-value.isp').textContent = techDetails.isp || 'Unknown';
            document.querySelector('.tech-value.usage-type').textContent = techDetails.usage_type || 'Unknown';
            document.querySelector('.tech-value.asn').textContent = techDetails.asn || 'Unknown';
            document.querySelector('.tech-value.domain-name').textContent = techDetails.domain_name || 'Unknown';
            document.querySelector('.tech-value.country').textContent = techDetails.country || 'Unknown';
            document.querySelector('.tech-value.city').textContent = techDetails.city || 'Unknown';
            document.querySelector('.tech-value.abuse-confidence-score').textContent =
                `${techDetails.abuse_confidence_score}%`;

            if (window.refreshDashboard) {
                window.refreshDashboard();
            }

        } catch (error) {
            console.error('Error during scan:', error.message);
            alert('An unexpected error occurred. Please try again.');
        } finally {
            scanButton.classList.remove('button-loading');
            scanButton.querySelector('.spinner').classList.add('hidden');
            scanButton.disabled = false;
        }
    });

    function updateProgressBar(percent) {
        const progressBar = document.getElementById('progressBar');
        if (progressBar) {
            progressBar.style.width = `${percent}%`;
        }
        const progressPercentText = document.getElementById('progressPercentText');
        if (progressPercentText) {
            progressPercentText.textContent = `${Math.round(percent)}%`;
        }
    }

    function updateProgressText(message) {
        const el = document.getElementById('progressStepText');
        if (el) {
            el.textContent = message;
            el.style.display = 'inline-block'; // force rendering
        }
    }



    function updateRiskTexts(score) {
        const riskTitle = document.querySelector('.risk-title');
        const riskText = document.querySelector('.risk-text');

        if (score >= 70) {
            riskTitle.textContent = 'High Risk Detected';
            riskText.textContent = 'This URL shows multiple phishing indicators';
        } else if (score >= 40) {
            riskTitle.textContent = 'Moderate Risk Detected';
            riskText.textContent = 'This URL shows some phishing indicators';
        } else {
            riskTitle.textContent = 'Low Risk Detected';
            riskText.textContent = 'No significant phishing indicators found';
        }
    }
});

// Animate risk meter
function updateRiskScore(score) {
    const riskCircle = document.querySelector('.risk-circle');
    const percentage = Math.min(Math.max(score, 0), 100);

    riskCircle.style.background = `conic-gradient(
        #ef4444 0% ${percentage}%,
        #e5e7eb ${percentage}% 100%
    )`;

    gsap.to('.risk-score', {
        innerHTML: `${percentage}%`,
        duration: 1.5,
        ease: "power4.out",
        snap: { innerHTML: 1 }
    });
}
