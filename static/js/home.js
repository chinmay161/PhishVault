document.addEventListener('DOMContentLoaded', () => {
    // Attach event listener for the Scan button
    const scanButton = document.getElementById('scanButton');
    scanButton.addEventListener('click', async () => {
        const rawUrl = document.getElementById('scanInput').value;

        // Validate the URL using the URL constructor
        try {
            new URL(rawUrl); // Throws an error if the URL is invalid
        } catch (error) {
            alert('Please enter a valid URL.');
            return;
        }

        try {
            // Show loading indicator
            scanButton.disabled = true;
            document.querySelector('.button-text').textContent = 'Scanning...';

            // Make the API call to your Flask endpoint
            const response = await fetch('/scan-url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: rawUrl }),
            });

            // Check if the response is JSON
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server error: ${errorText}`);
            }

            const result = await response.json();

            // Unhide various result sections
            document.getElementById('riskAssessment').classList.remove('hidden');
            document.getElementById('keyIndicators').classList.remove('hidden');
            document.getElementById('databaseComparison').classList.remove('hidden');
            document.getElementById('technicalReport').classList.remove('hidden');
            document.getElementById('communityReports').classList.remove('hidden');

            // Update the risk meter with animation
            updateRiskScore(result.risk_score);

            // Update risk-related texts
            document.querySelector('.risk-title').textContent =
                result.risk_score > 70 ? 'High Risk Detected' : 'Low Risk Detected';
            document.querySelector('.risk-text').textContent =
                result.risk_score > 70
                    ? 'This URL shows multiple phishing indicators'
                    : 'No significant phishing indicators found';

            // Update SSL certificate indicator
            document.querySelector('.ssl .indicator-status').textContent =
                result.ssl_certificate.valid ? 'Valid' : 'Invalid';
            document.querySelector('.ssl .indicator-text').textContent =
                result.ssl_certificate.details || 'No issues detected';

            // Update domain age indicator
            document.querySelector('.domain .indicator-status').textContent =
                result.domain_age.status;
            document.querySelector('.domain .indicator-text').textContent =
                `Domain age: ${result.domain_age.age_days} days`;

            // Update keywords indicator
            document.querySelector('.keywords .indicator-status').textContent =
                result.keywords.detected ? 'Detected' : 'Not Detected';
            document.querySelector('.keywords .indicator-text').textContent =
                result.keywords.keywords_found.join(', ') || 'No suspicious keywords found';

            // Update the threat databases grid dynamically
            const dbGrid = document.querySelector('.database-grid');
            dbGrid.innerHTML = ''; // Clear any previous content
            result.threat_databases.forEach((db) => {
                const dbItem = document.createElement('div');
                dbItem.classList.add('database-item');
                dbItem.innerHTML = `
                    <img src="/static/images/${
                        db.name.toLowerCase().includes('google')
                            ? 'google-safe.svg'
                            : 'phishtank-logo.svg'
                    }" alt="${db.name}" class="db-logo">
                    <div class="db-status ${db.status === 'Reported' ? 'reported' : 'clean'}">
                        ${db.status}
                    </div>
                    <div class="db-update">Last checked: Just now</div>
                `;
                dbGrid.appendChild(dbItem);
            });

            // Update Technical Analysis Section
            console.log("Full API response:", result);
            const techDetails = result.ip_reputation;
            console.log("IP Reputation Data:", techDetails);
            document.querySelector('.tech-value.ip-address').textContent = techDetails.ip_address || 'Unknown';
            document.querySelector('.tech-value.isp').textContent = techDetails.isp || 'Unknown';
            document.querySelector('.tech-value.usage-type').textContent = techDetails.usage_type || 'Unknown';
            document.querySelector('.tech-value.asn').textContent = techDetails.asn || 'Unknown';
            document.querySelector('.tech-value.domain-name').textContent = techDetails.domain_name || 'Unknown';
            document.querySelector('.tech-value.country').textContent = techDetails.country || 'Unknown';
            document.querySelector('.tech-value.city').textContent = techDetails.city || 'Unknown';
            document.querySelector('.tech-value.abuse-confidence-score').textContent =
                `${techDetails.abuse_confidence_score}%`;
        } catch (error) {
            console.error('Error during scan:', error.message);
            alert('An unexpected error occurred. Please try again.');
        } finally {
            // Reset the Scan button state
            scanButton.disabled = false;
            document.querySelector('.button-text').textContent = 'Scan Now';
        }
    });
});

// Function to update the risk meter with animation using GSAP
function updateRiskScore(score) {
    const riskCircle = document.querySelector('.risk-circle');
    const percentage = Math.min(Math.max(score, 0), 100);
    // Update the visual risk meter using a conic gradient
    riskCircle.style.background = `conic-gradient(
        #ef4444 0% ${percentage}%,
        #e5e7eb ${percentage}% 100%
    )`;
    // Animate the risk score text using GSAP
    gsap.to('.risk-score', {
        innerHTML: `${percentage}%`,
        duration: 1.5,
        ease: "power4.out",
        snap: { innerHTML: 1 }
    });
}