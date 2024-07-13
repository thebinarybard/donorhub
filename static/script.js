//set dark mode

function SetDarkmode() {

    const themeBtn = document.getElementById('theme-btn');
    const root = document.documentElement;
    const tables = document.querySelectorAll('table');
    root.classList.add('dark-mode');
    themeBtn.classList.add('dark-mode');
    tables.forEach(table => {
        table.classList.add('text-black');
        table.classList.add('table-dark');
    });
}

// Function to set dark mode based on localStorage
function setDarkModeFromStorage() {
    const isDarkMode = localStorage.getItem('darkMode') === 'true';
    if (isDarkMode) {
        SetDarkmode()
    }
}


document.addEventListener('DOMContentLoaded', function () {
    document.body.classList.remove('no-transition');
});




// Document ready function
$(document).ready(function () {
    // Navbar custom CSS for toggled navbar
    $('.navbar-toggler').click(function () {
        $('#navbarNav').toggleClass('show');
        if ($('#navbarNav').hasClass('show')) {
            $('#navbarNav').addClass('navbar-border');
        } else {
            $('#navbarNav').removeClass('navbar-border');
        }
    });

    // Alert Remover
    var alerts = document.getElementById('alert');
    if (alerts) {
        document.getElementById('alert-btn').addEventListener('click', function () {
            alerts.style.display = "none";
        });
    }

    // Dark and Light Mode Toggler
    const themeBtn = document.getElementById('theme-btn');
    const root = document.documentElement;
    const tables = document.querySelectorAll('table');

    if (themeBtn) {
        themeBtn.addEventListener('click', function () {
            root.classList.toggle('dark-mode');
            themeBtn.classList.toggle('dark-mode');
            tables.forEach(table => {
                table.classList.toggle('text-black');
                table.classList.toggle('table-dark');
            });
            const isDarkMode = root.classList.contains('dark-mode');
            localStorage.setItem('darkMode', isDarkMode);
        });



    }
})
// Password Toggler
document.querySelectorAll('.toggle-password').forEach(function (toggle) {
    toggle.addEventListener('click', function () {
        const passwordField = this.previousElementSibling; // Assuming the password field is just before the toggle icon
        const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordField.setAttribute('type', type);
        this.classList.toggle('fa-eye');
        this.classList.toggle('fa-eye-slash');
    });
});