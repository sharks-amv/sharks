// Simple Login Validation
document.getElementById("loginForm")?.addEventListener("submit", function (e) {
    e.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    if (username === "patient" && password === "1234") {
        window.location.href = "home.html"; // Redirect after login
    } else {
        document.getElementById("error").innerText = "Invalid username or password!";
    }
});
// Switch between Login and Signup
function showSignup() {
    document.getElementById("loginBox").classList.add("hidden");
    document.getElementById("signupBox").classList.remove("hidden");
}

function showLogin() {
    document.getElementById("signupBox").classList.add("hidden");
    document.getElementById("loginBox").classList.remove("hidden");
}

// Handle Login
document.getElementById("loginForm")?.addEventListener("submit", function (e) {
    e.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    // Example: only these work
    if (username === "patient" && password === "1234") {
        window.location.href = "home.html";
    } else {
        document.getElementById("error").innerText = "Invalid username or password!";
    }
});

// Handle Signup
document.getElementById("signupForm")?.addEventListener("submit", function (e) {
    e.preventDefault();

    const newUsername = document.getElementById("newUsername").value;
    const newPassword = document.getElementById("newPassword").value;
    const newEmail = document.getElementById("newEmail").value;

    alert("Account created successfully for " + newUsername + " (" + newEmail + ")");
    showLogin();
});
