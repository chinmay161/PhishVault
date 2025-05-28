document.addEventListener('DOMContentLoaded', () => {
    const scanButton = document.getElementById('scanButton');
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const socket = io();

    // Handle socket connection
    socket.on('connect', () => {
        console.log('Connected via WebSocket:', socket.id);
    });

    // Receive real-time scan progress from server
    socket.on('scan_progress', data => {
        updateProgressText(`${data.step} - ${data.detail}`);
    });

    scanButton.addEventListener('click', async () => {
        const rawUrl = document.getElementById('scanInput').value.trim();

        if (!rawUrl) {
            alert('Please enter a valid URL.');
            return;
        }

        try {
            new URL(rawUrl); // validate URL
        } catch (error) {
            alert('Please enter a valid URL format.');
            return;
        }

        // UI: Start loading
        scanButton.classList.add('button-loading');
        scanButton.querySelector('.spinner').classList.remove('hidden');
        scanButton.disabled = true;
        progressContainer.classList.remove('hidden');
        progressContainer.classList.add('visible');
        updateProgressBar(0);
        updateProgressText('Starting scan...');

        try {
            const response = await fetch(`/scan-url?sid=${socket.id}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: rawUrl }),
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server error: ${errorText}`);
            }

            const result = await response.json();
            updateProgressText('Scan complete.');

            // Simulate 100% progress
            updateProgressBar(100);
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

            // Update dashboard if function available
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
        progressBar.style.width = `${percent}%`;
        progressText.textContent = `${Math.round(percent)}%`;
    }

    function updateProgressText(message) {
        const container = document.getElementById('progressText');
        if (container) container.textContent = message;
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
