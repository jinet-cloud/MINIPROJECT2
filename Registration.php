<?php
session_start();

// Database configuration
$servername = "localhost";
$username = "root";
$password = ""; // Your database password
$dbname = "miniproject";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$first_name = $last_name = $gender = $contact_number = $email = $password = $confirm_password = "";
$errors = [];

// Check if form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $first_name = trim($_POST['first_name']);
    $last_name = trim($_POST['last_name']);
    $gender = $_POST['gender'];
    $contact_number = trim($_POST['contact_number']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Validate inputs
    if (empty($first_name) || strlen($first_name) > 25) {
        $errors['first_name'] = "First name is required and should not exceed 25 characters.";
    }
    if (empty($last_name) || strlen($last_name) > 25) {
        $errors['last_name'] = "Last name is required and should not exceed 25 characters.";
    }
    if (empty($contact_number) || !preg_match("/^\d{10,11}$/", $contact_number)) {
        $errors['contact_number'] = "Contact number is required and must be 10 or 11 digits.";
    }
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = "Valid email address is required.";
    }
    if (empty($password) || strlen($password) < 8 || !preg_match("/[A-Za-z]/", $password) || !preg_match("/\d/", $password) || !preg_match("/\W/", $password)) {
        $errors['password'] = "Password must be at least 8 characters long and include letters, numbers, and special characters.";
    }
    if ($password !== $confirm_password) {
        $errors['confirm_password'] = "Passwords do not match.";
    }

    // Process registration if no errors
    if (empty($errors)) {
        // Hash the password
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Check if email already exists
        $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $errors['email'] = "Email already registered.";
        } else {
            $stmt->close();
            $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, gender, contact_number, email, password_hash) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("ssssss", $first_name, $last_name, $gender, $contact_number, $email, $hashed_password);

            if ($stmt->execute()) {
                header("Location: login_user.php");
                exit();
            } else {
                $errors['database'] = "Error: " . $stmt->error;
            }
            $stmt->close();
        }
    }

    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Care Shelter User Registration</title>
    <link rel="stylesheet" href="registration.css">
</head>
<body>
    <div class="container">
        <h2>User Registration</h2>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <label for="first_name">First Name:</label>
            <input type="text" id="first_name" name="first_name" maxlength="25" value="<?php echo htmlspecialchars($first_name); ?>" required>
            <?php if (isset($errors['first_name'])): ?>
                <span style="color: red;"><?php echo $errors['first_name']; ?></span>
            <?php endif; ?><br>

            <label for="last_name">Last Name:</label>
            <input type="text" id="last_name" name="last_name" maxlength="25" value="<?php echo htmlspecialchars($last_name); ?>" required>
            <?php if (isset($errors['last_name'])): ?>
                <span style="color: red;"><?php echo $errors['last_name']; ?></span>
            <?php endif; ?><br>

            <label for="gender">Gender:</label>
            <select id="gender" name="gender" required>
                <option value="" disabled selected>Select your gender</option>
                <option value="male" <?php if ($gender == "male") echo "selected"; ?>>Male</option>
                <option value="female" <?php if ($gender == "female") echo "selected"; ?>>Female</option>
                <option value="other" <?php if ($gender == "other") echo "selected"; ?>>Other</option>
            </select><br>

            <label for="contact_number">Contact Number:</label>
            <input type="text" id="contact_number" name="contact_number" pattern="\d{10,11}" value="<?php echo htmlspecialchars($contact_number); ?>" title="Contact number must be 10 or 11 digits" required>
            <?php if (isset($errors['contact_number'])): ?>
                <span style="color: red;"><?php echo $errors['contact_number']; ?></span>
            <?php endif; ?><br>

            <label for="email">Email Address:</label>
            <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($email); ?>" required>
            <?php if (isset($errors['email'])): ?>
                <span style="color: red;"><?php echo $errors['email']; ?></span>
            <?php endif; ?><br>

            <label for="password">Password:</label>
            <input type="password" id="password" name="password" minlength="8" required>
            <?php if (isset($errors['password'])): ?>
                <span style="color: red;"><?php echo $errors['password']; ?></span>
            <?php endif; ?><br>

            <label for="confirm_password">Confirm Password:</label>
            <input type="password" id="confirm_password" name="confirm_password" minlength="8" required>
            <?php if (isset($errors['confirm_password'])): ?>
                <span style="color: red;"><?php echo $errors['confirm_password']; ?></span>
            <?php endif; ?><br>

            <button type="submit">Register</button>
        </form>
        <p>Already have an account? <a href="Homepage2.php">Login here</a></p>
    </div>
</body>
</html>
