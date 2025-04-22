function setupEventListeners() {
    // Navigation buttons
    document.getElementById('showSignup')?.addEventListener('click', e => {
        e.preventDefault();
        window.location.href = '/auth/signup';
    });

    document.getElementById('showLogin')?.addEventListener('click', e => {
        e.preventDefault();
        window.location.href = '/auth/login';
    });

    // Password toggle buttons
    const toggles = document.querySelectorAll(".password-toggle");
    toggles.forEach(toggle => {
        toggle.addEventListener("click", () => {
            const inputGroup = toggle.closest(".input-group");
            const input = inputGroup?.querySelector("input[type='password'], input[type='text']");
            const iconEye = toggle.querySelector(".icon-eye");
            const iconEyeOff = toggle.querySelector(".icon-eye-off");

            if (!input) return;

            if (input.type === "password") {
                input.type = "text";
                iconEye?.classList.add("hidden");
                iconEyeOff?.classList.remove("hidden");
            } else {
                input.type = "password";
                iconEye?.classList.remove("hidden");
                iconEyeOff?.classList.add("hidden");
            }
        });
    });

    // Password strength & match
    const passwordInput = document.getElementById('signupPassword');
    const confirmInput = document.getElementById('confirmPassword');

    passwordInput?.addEventListener('input', updatePasswordStrength);
    confirmInput?.addEventListener('input', checkPasswordMatch);

    // Signup form
    document.getElementById('signup')?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const password = passwordInput.value;
        const confirm = confirmInput.value;
        if (password !== confirm) {
            alert('Passwords do not match!');
            return;
        }

        const email = document.getElementById('signupEmail').value;
        const submitButton = document.querySelector('.auth-button');
        submitButton.disabled = true;
        submitButton.textContent = 'Signing Up...';

        try {
            const response = await fetch('/auth/signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `signupEmail=${encodeURIComponent(email)}&signupPassword=${encodeURIComponent(password)}&confirmPassword=${encodeURIComponent(confirm)}`
            });

            const result = await response.json();
            if (!response.ok) {
                alert(result.error || 'Signup error');
                return;
            }

            alert('Signup successful! Please verify your email.');
            window.location.href = '/auth/login';
        } catch (err) {
            console.error(err);
            alert('Unexpected error. Please try again.');
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = 'Sign Up →';
        }
    });

    // Login form
    document.getElementById('login')?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;

        try {
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `loginEmail=${encodeURIComponent(email)}&loginPassword=${encodeURIComponent(password)}`
            });

            const result = await response.json();
            if (!response.ok) {
                document.getElementById('error-message').textContent = result.error || 'Login error';
                return;
            }

            localStorage.setItem('isLoggedIn', 'true');
            localStorage.setItem('userEmail', email);
            alert('Login successful!');
            updateAuthState();
            window.location.href = '/dashboard';
        } catch (err) {
            console.error(err);
            document.getElementById('error-message').textContent = 'Unexpected login error.';
        }
    });

    // Logout
    document.addEventListener("click", async (event) => {
        if (event.target.id === "logoutButton" || event.target.id === "mobileLogoutButton") {
            try {
                const response = await fetch('/auth/logout', {
                    method: 'GET',
                    credentials: 'same-origin'
                });

                if (response.ok) {
                    localStorage.removeItem('isLoggedIn');
                    localStorage.removeItem('userEmail');
                    updateAuthState();
                    window.location.href = '/';
                } else {
                    console.error('Logout failed');
                }
            } catch (err) {
                console.error('Logout error:', err);
            }
        }
    });

    // Forgot password
    document.getElementById('forgot-password-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('email').value;
        const errorMessage = document.getElementById('error-message');
        errorMessage.textContent = '';

        try {
            const response = await fetch('/auth/forgot-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `email=${encodeURIComponent(email)}`
            });

            const result = await response.json();
            if (!response.ok) {
                errorMessage.textContent = result.error || 'Error occurred.';
                return;
            }

            alert(result.message || 'Reset link sent (if email exists).');
        } catch (err) {
            console.error('Forgot password error:', err);
            errorMessage.textContent = 'Unexpected error. Try again.';
        }
    });

    // Reset password
    document.getElementById('reset-password-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const token = new URLSearchParams(window.location.search).get('token');
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        const errorMessage = document.getElementById('error-message');

        if (!token) {
            errorMessage.textContent = 'Missing token.';
            return;
        }

        if (newPassword !== confirmPassword) {
            errorMessage.textContent = 'Passwords do not match.';
            return;
        }

        try {
            const response = await fetch(`/auth/reset-password/${token}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `newPassword=${encodeURIComponent(newPassword)}&confirmPassword=${encodeURIComponent(confirmPassword)}`
            });

            const result = await response.json();
            if (!response.ok) {
                errorMessage.textContent = result.error || 'Reset error.';
                return;
            }

            alert(result.message || 'Password reset successful!');
            window.location.href = '/auth/login';
        } catch (err) {
            console.error('Reset password error:', err);
            errorMessage.textContent = 'Unexpected error.';
        }
    });
}

// Password strength helper
function updatePasswordStrength() {
    const password = document.getElementById('signupPassword').value;
    const strengthMeter = document.querySelector('.strength-meter');
    const strengthText = document.querySelector('.strength-text span');
    const strength = calculatePasswordStrength(password);

    strengthMeter.style.width = `${strength.percentage}%`;
    strengthMeter.style.backgroundColor = strength.color;
    strengthText.textContent = strength.text;
    strengthText.style.color = strength.color;
}

function checkPasswordMatch() {
    const password = document.getElementById('signupPassword').value;
    const confirm = document.getElementById('confirmPassword').value;
    const matchText = document.querySelector('.password-match');

    const match = password === confirm;
    matchText.textContent = match ? '✓ Passwords match' : '✗ Passwords do not match';
    matchText.style.color = match ? '#22c55e' : '#ef4444';
}

function calculatePasswordStrength(password) {
    let strength = { percentage: 0, color: '#ef4444', text: 'Weak' };
    if (password.length >= 8) strength.percentage += 30;
    if (/[a-z]/.test(password)) strength.percentage += 20;
    if (/[A-Z]/.test(password)) strength.percentage += 20;
    if (/\d/.test(password)) strength.percentage += 20;
    if (/[@$!%*?&]/.test(password)) strength.percentage += 10;

    if (strength.percentage >= 80) {
        strength.color = '#22c55e';
        strength.text = 'Strong';
    } else if (strength.percentage >= 50) {
        strength.color = '#eab308';
        strength.text = 'Medium';
    }
    return strength;
}

// 🛠️ UPDATE HEADER BASED ON LOGIN STATE
function updateAuthState() {
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';

    const loginBtn = document.getElementById('showLogin');
    const signupBtn = document.getElementById('showSignup');
    const logoutBtn = document.getElementById('logoutButton');
    const mobileLogout = document.getElementById('mobileLogoutButton');

    if (isLoggedIn) {
        loginBtn?.classList.add('hidden');
        signupBtn?.classList.add('hidden');
        logoutBtn?.classList.remove('hidden');
        mobileLogout?.classList.remove('hidden');
    } else {
        loginBtn?.classList.remove('hidden');
        signupBtn?.classList.remove('hidden');
        logoutBtn?.classList.add('hidden');
        mobileLogout?.classList.add('hidden');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    updateAuthState(); // Update header state on page load
});
