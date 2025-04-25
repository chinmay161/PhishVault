document.addEventListener("DOMContentLoaded", () => {
  const totalScansEl = document.getElementById("total-scans");
  const safeCountEl = document.getElementById("safe-count");
  const phishingCountEl = document.getElementById("phishing-count");
  const scanList = document.getElementById("recent-scans-container");
  const riskChartCtx = document.getElementById("riskChart").getContext("2d");
  let chart = null;

  // Moved loadPage outside updateDashboard
  const loadPage = (page) => {
    fetch(`/dashboard/data?page=${page}`)
      .then(response => response.json())
      .then(updateDashboard)
      .catch(console.error);
  };

  const updateDashboard = (data) => {
    // Update stats
    totalScansEl.textContent = data.stats.total_scans;
    safeCountEl.textContent = data.stats.safe_count;
    phishingCountEl.textContent = data.stats.phishing_count;

    // Update recent scans
    scanList.innerHTML = "";
    data.scans.forEach(scan => {
      scanList.insertAdjacentHTML("beforeend", `
        <div class="scan-item">
          <span>${scan.url}</span>
          <span class="status" style="color: ${scan.status === 'malicious' ? 'red' : 'green'}">
            ${scan.status}
          </span>
        </div>
      `);
    });

    // Update chart
    if (chart) chart.destroy();
    chart = new Chart(riskChartCtx, {
      type: 'line',
      data: {
        labels: data.risk_trend.map(entry => entry.month),
        datasets: [{
          label: 'Malicious URLs',
          data: data.risk_trend.map(entry => entry.malicious),
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.2)',
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true } }
      }
    });

    // Update pagination
    const paginationContainer = document.getElementById("pagination-container");
    paginationContainer.innerHTML = "";

    // Add Previous button
    if (data.has_prev) {
      const prevButton = document.createElement("button");
      prevButton.textContent = "← Previous";
      prevButton.onclick = () => loadPage(data.current_page - 1);
      paginationContainer.appendChild(prevButton);
    }

    // Add page numbers
    const startPage = Math.max(1, data.current_page - 2);
    const endPage = Math.min(startPage + 4, data.total_pages);

    for (let i = startPage; i <= endPage; i++) {
      const pageButton = document.createElement("button");
      pageButton.textContent = i;
      pageButton.className = i === data.current_page ? "active" : "";
      pageButton.onclick = () => loadPage(i);
      paginationContainer.appendChild(pageButton);
    }

    // Add Next button
    if (data.has_next) {
      const nextButton = document.createElement("button");
      nextButton.textContent = "Next →";
      nextButton.onclick = () => loadPage(data.current_page + 1);
      paginationContainer.appendChild(nextButton);
    }
  }; // End of updateDashboard

  // Initial load
  fetch("/dashboard/data")
    .then(response => {
      if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
      return response.json();
    })
    .then(updateDashboard)
    .catch(error => {
      console.error("Failed to load dashboard data:", error);
      alert("Failed to load dashboard. Check the console for details.");
    });

  // Global refresh function
  window.refreshDashboard = () => {
    fetch("/dashboard/data")
      .then(response => response.json())
      .then(updateDashboard)
      .catch(console.error);
  };
});