const loginForm = document.getElementById('login-form');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const togglePassBtn = document.getElementById('toggle-pass-btn');
const eyeOpenIcon = document.getElementById('eye-open-icon');
const eyeClosedIcon = document.getElementById('eye-closed-icon');
const paramUserVal = document.getElementById('param-user-val');
const paramPassVal = document.getElementById('param-pass-val');
const sqlPreparedTemplate = document.getElementById('sql-prepared-template');

if (sqlPreparedTemplate) {
    sqlPreparedTemplate.textContent = 'SELECT * FROM users WHERE username = ? AND password = ?';
}

function updatePreparedParamsPreview() {
    if (paramUserVal) {
        paramUserVal.textContent = JSON.stringify(usernameInput.value);
    }
    if (paramPassVal) {
        paramPassVal.textContent = JSON.stringify(passwordInput.value);
    }
}

function setPasswordVisible(visible) {
    passwordInput.type = visible ? 'text' : 'password';
    if (eyeOpenIcon && eyeClosedIcon) {
        eyeOpenIcon.classList.toggle('is-hidden', visible);
        eyeOpenIcon.hidden = visible;
        eyeClosedIcon.classList.toggle('is-hidden', !visible);
        eyeClosedIcon.hidden = !visible;
    }
    if (togglePassBtn) {
        const label = visible ? 'Ẩn mật khẩu' : 'Hiện mật khẩu';
        togglePassBtn.setAttribute('aria-label', label);
        togglePassBtn.title = label;
    }
}

function updatePasswordToggleVisibility() {
    const hasValue = passwordInput && passwordInput.value.length > 0;
    if (togglePassBtn) {
        togglePassBtn.classList.toggle('is-hidden', !hasValue);
    }
    if (!hasValue && passwordInput && passwordInput.type !== 'password') {
        setPasswordVisible(false);
    }
}

if (togglePassBtn) {
    togglePassBtn.addEventListener('click', () => {
        setPasswordVisible(passwordInput.type === 'password');
    });
}

document.querySelectorAll('.btn-fill').forEach((button) => {
    button.addEventListener('click', () => {
        usernameInput.value = button.dataset.username;
        passwordInput.value = button.dataset.password;
        updatePasswordToggleVisibility();
        if (button.dataset.username && button.dataset.username.includes("'")) {
            setPasswordVisible(true);
        }
        updatePreparedParamsPreview();
        if (button.dataset.autosubmit === 'true' && loginForm) {
            loginForm.submit();
        }
    });
});

if (usernameInput && passwordInput) {
    usernameInput.addEventListener('input', updatePreparedParamsPreview);
    passwordInput.addEventListener('input', () => {
        updatePasswordToggleVisibility();
        updatePreparedParamsPreview();
    });
    updatePasswordToggleVisibility();
    updatePreparedParamsPreview();
}

function toggleSimPanel() {
    const p = document.getElementById('simulation-panel');
    const lbl = document.getElementById('toggle-sim-label');
    if (!p) return;
    const isHidden = p.classList.toggle('is-hidden');
    if (lbl) {
        lbl.textContent = isHidden ? 'Bấm xem Mô phỏng 5 bước PreparedStatement bảo vệ hệ thống' : 'Thu gọn mô phỏng luồng thực thi';
    }
}
