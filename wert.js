// Switch between forms
function showRegister() {
    document.getElementById("loginForm").classList.add("hidden");
    document.getElementById("registerForm").classList.remove("hidden");
}

function showLogin() {
    document.getElementById("registerForm").classList.add("hidden");
    document.getElementById("loginForm").classList.remove("hidden");
}

// Register User
function register() {
    let username = document.getElementById("regUsername").value.trim();
    let email = document.getElementById("regEmail").value.trim();
    let password = document.getElementById("regPassword").value.trim();

    if (username === "" || email === "" || password === "") {
        alert("Please fill in all fields!");
        return;
    }

    // Save to LocalStorage
    let user = {
        username: username,
        email: email,
        password: password
    };

    localStorage.setItem(username, JSON.stringify(user));
    alert("Registration successful! You can now login.");

    // Switch to login
    showLogin();
}

// Login User
function login() {
    let username = document.getElementById("loginUsername").value.trim();
    let password = document.getElementById("loginPassword").value.trim();
    let remember = document.getElementById("rememberMe").checked;

    let storedUser = localStorage.getItem(username);

    if (!storedUser) {
        alert("User not found! Please register first.");
        return;
    }

    let user = JSON.parse(storedUser);

    if (user.password === password) {
        alert("Login successful! Redirecting to Home page...");

        // Save session
        if (remember) {
            localStorage.setItem("loggedInUser", username);
        } else {
            sessionStorage.setItem("loggedInUser", username);
        }

        window.location.href = "index.html"; // Redirect to homepage
    } else {
        alert("Incorrect password!");
    }
}

// Auto-login if user selected "Remember Me"
window.onload = function () {
    let rememberedUser = localStorage.getItem("loggedInUser") || sessionStorage.getItem("loggedInUser");

    if (rememberedUser) {
        window.location.href = "index.html"; // Redirect automatically
    }
};

// Logout function (to be used in index.html)
// Logout functionality
document.getElementById("btnLogout").addEventListener("click", () => {
    // Clear the session completely
    localStorage.removeItem("hms-demo-db");

    alert("You have been logged out!");
    window.location.href = "start.html"; // Redirect to login page
});
