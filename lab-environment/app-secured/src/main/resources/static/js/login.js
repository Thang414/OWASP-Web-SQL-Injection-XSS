const loginForm = document.getElementById('login-form');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const togglePassBtn = document.getElementById('toggle-pass-btn');
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
    if (togglePassBtn) {
        togglePassBtn.textContent = visible ? '🙈 Ẩn' : '👁️ Hiện';
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
    passwordInput.addEventListener('input', updatePreparedParamsPreview);
    updatePreparedParamsPreview();
}
