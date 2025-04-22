// ======================
// 🌓 Theme Management
// ======================
function initializeTheme() {
  const themeToggles = document.querySelectorAll('.theme-toggle');
  const htmlEl = document.documentElement;

  // Load saved theme or default to light
  const savedTheme = localStorage.getItem('theme') || 'light';
  htmlEl.setAttribute('data-theme', savedTheme);
  updateThemeIcons(savedTheme);

  // Toggle theme on button click
  themeToggles.forEach(toggle => {
    toggle.addEventListener('click', () => {
      const currentTheme = htmlEl.getAttribute('data-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      htmlEl.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);
      updateThemeIcons(newTheme);
    });
  });
}

// Update theme toggle icons
function updateThemeIcons(theme) {
  document.querySelectorAll('.theme-toggle').forEach(toggle => {
    const darkIcon = toggle.querySelector('.dark-icon');
    const lightIcon = toggle.querySelector('.light-icon');
    if (darkIcon && lightIcon) {
      darkIcon.style.display = theme === 'light' ? 'inline' : 'none';
      lightIcon.style.display = theme === 'dark' ? 'inline' : 'none';
    }
  });
}

// ======================
// ☰ Mobile Menu Toggle
// ======================
function initializeMobileMenu() {
  const mobileMenuBtn = document.querySelector(".mobile-menu-btn");
  const mobileNav = document.querySelector(".mobile-nav");
  const mobileCloseBtn = document.querySelector(".mobile-close-btn");

  function toggleMobileMenu() {
    mobileNav?.classList.toggle("active");
  }

  mobileMenuBtn?.addEventListener("click", toggleMobileMenu);
  mobileCloseBtn?.addEventListener("click", toggleMobileMenu);

  // Close menu when clicking outside
  document.addEventListener("click", (e) => {
    if (
      mobileNav?.classList.contains("active") &&
      !mobileNav.contains(e.target) &&
      !mobileMenuBtn.contains(e.target)
    ) {
      mobileNav.classList.remove("active");
    }
  });
}

// ======================
// 🧠 Footer Features
// ======================
function initializeFooterFeatures() {
  // Newsletter Form
  document.getElementById('newsletterForm')?.addEventListener('submit', function(e) {
    e.preventDefault();
    const email = this.querySelector('input').value;
    alert(`Thanks for subscribing! We've sent a confirmation to ${email}`);
    this.reset();
  });

  // Live Chat
  document.getElementById('liveChat')?.addEventListener('click', function() {
    alert('Connecting you to a security expert...');
  });

  // Set current year
  const currentYearEl = document.getElementById('currentYear');
  if (currentYearEl) {
    currentYearEl.textContent = new Date().getFullYear();
  }
}

// ======================
// 🚀 Initialize Everything
// ======================
document.addEventListener('DOMContentLoaded', () => {
  initializeTheme();
  initializeMobileMenu();
  initializeFooterFeatures();
});
