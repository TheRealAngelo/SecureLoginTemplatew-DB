<?php
session_start();
require 'config.php';

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!isset($_POST["csrf_token"]) || $_POST["csrf_token"] !== $_SESSION["csrf_token"]) {
        die("CSRF validation failed.");
    }

    $username = trim($_POST["username"]);
    $password = $_POST["password"];

    if (empty($username) || empty($password)) {
        die("Please enter both username and password.");
    }

    $stmt = $pdo->prepare("SELECT id, username, password, failed_attempts, locked_until FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user) {
        if ($user["locked_until"] && strtotime($user["locked_until"]) > time()) {
            die("Account locked. Try again later.");
        }

        if (password_verify($password, $user["password"])) {
            $_SESSION["user_id"] = $user["id"];
            $_SESSION["username"] = $user["username"];

            $pdo->prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?")->execute([$user["id"]]);
            header("Location: dashboard.php");
            exit;
        } else {
            $failed_attempts = $user["failed_attempts"] + 1;
            $locked_until = ($failed_attempts >= 5) ? date("Y-m-d H:i:s", strtotime("+15 minutes")) : NULL;

            $pdo->prepare("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?")
                ->execute([$failed_attempts, $locked_until, $user["id"]]);
            die("Invalid credentials.");
        }
    } else {
        die("Invalid credentials.");
    }
}

$_SESSION["csrf_token"] = bin2hex(random_bytes(32));
?>

<!DOCTYPE html>
<html>
<head>
    <title>Secure Login</title>
</head>
<body>
<style>
        html{
            height: 100%;
            margin: 0;
            padding: 0;
            background-image: url('https://img.freepik.com/premium-vector/padlock-with-keyhole-icon-personal-data-security-illustrates-cyber-data-information-privacy-idea-blue-color-abstract-hi-speed-internet-technology_542466-600.jpg');
            background-size: cover;
            background-repeat: no-repeat;
            background-position: center center;
        }
        body{
            background-color: transparent;
        }
        .login-container img {
    width: 150px;
    margin-bottom: 20px;
}

.login-container input[type="text"],
.login-container input[type="password"] {
    display: block;
    border-radius: 4px;
    height: 2rem;
    width: 20rem;
    margin-bottom: 0.5rem;
}

.login-container form {
    padding-top: 1rem;
    display: flex;
    flex-direction: column;
    align-items: center;

}

.login-container button {
    width: max-content;
    padding-left: 0.5rem;
    padding-right: 0.5rem;
    padding-top: 0.25rem;
    padding-bottom: 0.25rem;

    margin-left: auto;
    margin-right: auto;
    margin-top: 1rem;

    border-radius: 12px;
    background-color: #C4DAD2;
    color: #091d1a;
    box-shadow: 2px 2px 1.5px rgb(38, 38, 38);

    font-family: 'Mont-HeavyDemo';
    transition: 0.2s ease-in-out;

    width: 320px;
}

.login-container button:hover {
    background-color: #ddd;
}
    </style>
    <div class="login-container">
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <label>Username:</label>
        <input type="text" placeholder="Username" name="username" required>
        <label>Password:</label>
        <input type="password" placeholder="Password" name="password" required>
        <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
