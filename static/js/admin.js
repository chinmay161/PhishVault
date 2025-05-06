// static/js/admin.js
document.addEventListener('DOMContentLoaded', () => {
    // Initialize Chart.js
    initCharts();
    
    // Setup event listeners
    setupEventListeners();
    
    // Initialize CKEditor if needed
    initEditor();
});

function getCSRFToken() {
    return document.querySelector('meta[name="csrf-token"]').content;
}

function initCharts() {
    // Safety check for Chart.js
    if (typeof Chart === 'undefined') {
        console.warn('Chart.js not loaded - skipping chart initialization');
        return;
    }

    // Check if chart elements exist
    const trendChartEl = document.getElementById('scanTrendChart');
    const statusChartEl = document.getElementById('scanStatusChart');

    // Initialize Trend Chart only if element exists
    if (trendChartEl) {
        new Chart(trendChartEl, {
            type: 'line',
            data: {
                labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                datasets: [{
                    label: 'Scans',
                    data: [120, 190, 300, 250],
                    borderColor: '#820c9f',
                    tension: 0.4
                }]
            }
        });
    }

    // Initialize Status Chart only if element exists
    if (statusChartEl) {
        fetch('/admin/chart-data')
            .then(res => res.json())
            .then(data => {
                const safeScans = data.total_scans - data.malicious_scans;
                new Chart(statusChartEl, {
                    type: 'doughnut',
                    data: {
                        labels: ['Safe', 'Malicious'],
                        datasets: [{
                            data: [safeScans, data.malicious_scans],
                            backgroundColor: ['#22c55e', '#ef4444']
                        }]
                    }
                });
            });
    }
}

function setupEventListeners() {
    // Add Link Button
    document.getElementById('addLinkButton')?.addEventListener('click', showAddLinkModal);
    
    // Close Modal
    document.querySelector('.modal .close')?.addEventListener('click', closeModal);
    
    // Form Submission
    document.getElementById('linkForm')?.addEventListener('submit', handleLinkSubmit);
    
    // Toggle Switches
    document.querySelectorAll('.switch input[type="checkbox"]').forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            toggleLink(this.dataset.linkId);
        });
    });
    
    // Search Input
    document.getElementById('searchInput')?.addEventListener('input', function(e) {
        const searchTerm = e.target.value.toLowerCase();
        document.querySelectorAll('.user-table tbody tr').forEach(row => {
            const email = row.children[0].textContent.toLowerCase();
            row.style.display = email.includes(searchTerm) ? '' : 'none';
        });
    });
}

function initEditor() {
    if (typeof CKEDITOR !== 'undefined') {
        CKEDITOR.replace('editor', {
            toolbar: [
                ['Bold', 'Italic', 'Underline'],
                ['NumberedList', 'BulletedList'],
                ['Link', 'Unlink'],
                ['Source']
            ]
        });
    }
}

// Core Functions
function toggleLink(linkId) {
    fetch(`/admin/link/${linkId}/toggle`, {
        method: 'POST',
        headers: {
            'X-CSRF-Token': getCSRFToken()
        }
    })
    .then(response => {
        if (!response.ok) throw new Error('Network response was not ok');
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // Update UI without reload
            const checkbox = document.querySelector(`input[data-link-id="${linkId}"]`);
            if (checkbox) checkbox.checked = data.is_visible;
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to update link visibility');
    });
}

function showAddLinkModal() {
    document.getElementById('linkModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('linkModal').style.display = 'none';
}

function handleLinkSubmit(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    
    // Add loading state
    const submitButton = form.querySelector('button[type="submit"]');
    submitButton.disabled = true;
    submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';

    fetch('/admin/links', {
        method: 'POST',
        body: formData,
        headers: {
            // Add CSRF token header if using Flask-WTF
            'X-CSRF-Token': getCSRFToken()
        }
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return response.json();
    })
    .then(data => {
        if (data.success) {
            alert('Link saved successfully!');
            closeModal();
            window.location.reload();
        } else {
            throw new Error(data.error || 'Unknown error occurred');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert(`Failed to save link: ${error.message}`);
    })
    .finally(() => {
        submitButton.disabled = false;
        submitButton.textContent = 'Save Link';
    });
}

// Export function
window.exportUsers = function() {
    window.location.href = '/admin/export/users.csv';
}

// Delete handler
document.querySelectorAll('.delete-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      const linkId = this.dataset.linkId;
      if (confirm('Are you sure you want to delete this link?')) {
        fetch(`/admin/link/${linkId}/delete`, {
          method: 'DELETE',
          headers: {
            'X-CSRF-Token': getCSRFToken()
          }
        })
        .then(response => {
            if (response.ok) {
              document.querySelector(`tr[data-link-id="${linkId}"]`).remove()
              window.location.reload(); // Force refresh to update footer
            }
        })
      }
    })
  })