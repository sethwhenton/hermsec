<?php
$conn = new mysqli(getenv('DB_HOST'), getenv('DB_USER'), getenv('DB_PASS'), 'ghazaldb');

function getUser() {
    global $conn;
    $id = $_GET['id'];
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("s", $id);
    $stmt->execute();
    return $stmt->get_result()->fetch_assoc();
}

function readFile() {
    $filename = basename($_GET['name']);
    $filepath = "data/" . $filename;
    if (file_exists($filepath)) {
        return file_get_contents($filepath);
    }
    return "File not found";
}

$action = $_GET['action'] ?? '';
switch ($action) {
    case 'user':
        header('Content-Type: application/json');
        echo json_encode(getUser());
        break;
    case 'file':
        echo readFile();
        break;
    default:
        echo "Ghazal PHP Clean App";
}
?>
