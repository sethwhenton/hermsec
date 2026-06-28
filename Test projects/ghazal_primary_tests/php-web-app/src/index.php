<?php
// VULN 1: Hardcoded database credentials (CWE-798)
$DB_HOST = 'localhost';
$DB_USER = 'admin';
$DB_PASS = 'ghazal_php_db_pass!@#';

// VULN 2: Hardcoded API key (CWE-798)
$API_KEY = 'ghazal-php-api-key-REPLACE_WITH_API_KEY';

$conn = new mysqli($DB_HOST, $DB_USER, $DB_PASS, 'ghazaldb');

// VULN 3: SQL Injection via string concatenation (CWE-89)
function getUser() {
    global $conn;
    $id = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id = '" . $id . "'";
    $result = $conn->query($sql);
    return $result->fetch_assoc();
}

// VULN 4: SQL Injection via variable interpolation (CWE-89)
function searchUsers() {
    global $conn;
    $name = $_GET['name'];
    $sql = "SELECT * FROM users WHERE name LIKE '%$name%'";
    $result = $conn->query($sql);
    return $result->fetch_all(MYSQLI_ASSOC);
}

// VULN 5: Command Injection via exec (CWE-78)
function pingHost() {
    $host = $_GET['host'];
    exec("ping -c 4 " . $host, $output);
    return implode("\n", $output);
}

// VULN 6: Command Injection via shell_exec (CWE-78)
function runCommand() {
    $cmd = $_POST['command'];
    $output = shell_exec($cmd);
    return $output;
}

// VULN 7: Command Injection via system (CWE-78)
function systemCommand() {
    $cmd = $_GET['cmd'];
    system($cmd);
}

// VULN 8: Path Traversal (CWE-22)
function readFile() {
    $filename = $_GET['name'];
    $filepath = "data/" . $filename;
    return file_get_contents($filepath);
}

// VULN 9: Path Traversal via include (CWE-22)
function includeFile() {
    $page = $_GET['page'];
    include("pages/" . $page . ".php");
}

// VULN 10: XSS via echo (CWE-79)
function searchPage() {
    $query = $_GET['q'];
    echo "<html><body><h1>Search: " . $query . "</h1></body></html>";
}

// VULN 11: Unsafe deserialization (CWE-502)
function loadData() {
    $data = $_COOKIE['data'];
    return unserialize($data);
}

// VULN 12: Information exposure (CWE-209)
function handleError() {
    $err = error_get_last();
    echo "Error: " . $err['message'] . " in " . $err['file'] . " on line " . $err['line'];
}

// Route handling
$action = $_GET['action'] ?? '';
switch ($action) {
    case 'user':
        header('Content-Type: application/json');
        echo json_encode(getUser());
        break;
    case 'search':
        header('Content-Type: application/json');
        echo json_encode(searchUsers());
        break;
    case 'ping':
        echo pingHost();
        break;
    case 'run':
        echo runCommand();
        break;
    case 'system':
        systemCommand();
        break;
    case 'file':
        echo readFile();
        break;
    case 'include':
        includeFile();
        break;
    case 'search-page':
        searchPage();
        break;
    case 'load':
        header('Content-Type: application/json');
        echo json_encode(loadData());
        break;
    case 'error':
        handleError();
        break;
    default:
        echo "Ghazal PHP Vulnerable App";
}
?>
