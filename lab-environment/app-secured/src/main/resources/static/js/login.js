const loginForm = document.getElementById('login-form');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');

document.querySelectorAll('.btn-fill').forEach((button) => {
    button.addEventListener('click', () => {
        usernameInput.value = button.dataset.username;
        passwordInput.value = button.dataset.password;
        if (button.dataset.autosubmit === 'true' && loginForm) {
            loginForm.submit();
        }
    });
});
