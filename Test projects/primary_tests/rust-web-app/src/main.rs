use std::process::Command;
use std::fs;
use std::io::{self, Write};
use std::collections::HashMap;

// VULN 1: Hardcoded database credentials (CWE-798)
const DB_HOST: &str = "localhost";
const DB_USER: &str = "admin";
const DB_PASS: &str = "vulntest_rust_db_pass!@#";

// VULN 2: Hardcoded API key (CWE-798)
const API_KEY: &str = "vulntest-rust-api-key-rk-1234567890abcdef";

// VULN 3: Command Injection via Command::new (CWE-78)
fn ping_host(host: &str) -> String {
    let output = Command::new("ping")
        .arg("-c")
        .arg("4")
        .arg(host)
        .output()
        .expect("Failed to execute ping");
    String::from_utf8_lossy(&output.stdout).to_string()
}

// VULN 4: Command Injection via shell (CWE-78)
fn run_command(command: &str) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .expect("Failed to execute command");
    String::from_utf8_lossy(&output.stdout).to_string()
}

// VULN 5: Path Traversal (CWE-22)
fn read_file(filename: &str) -> String {
    let filepath = format!("data/{}", filename);
    fs::read_to_string(&filepath).unwrap_or_else(|_| "File not found".to_string())
}

// VULN 6: Path Traversal via absolute path (CWE-22)
fn download_file(file: &str) -> String {
    let full_path = format!("/var/uploads/{}", file);
    fs::read_to_string(&full_path).unwrap_or_else(|_| "File not found".to_string())
}

// VULN 7: XSS via format! (CWE-79)
fn search_page(query: &str) -> String {
    format!("<html><body><h1>Search: {}</h1></body></html>", query)
}

// VULN 8: SQL Injection via format! (CWE-89)
fn get_user(user_id: &str) -> String {
    let query = format!("SELECT * FROM users WHERE id = '{}'", user_id);
    format!("Executed: {}", query)
}

// VULN 9: SQL Injection via string concat (CWE-89)
fn search_users(name: &str) -> String {
    let query = format!("SELECT * FROM users WHERE name LIKE '%{}%'", name);
    format!("Executed: {}", query)
}

// VULN 10: Information exposure (CWE-209)
fn handle_error() -> String {
    match fs::read_to_string("/nonexistent/file") {
        Ok(content) => content,
        Err(e) => format!("Error: {}\nDetails: {:?}", e, e),
    }
}

// VULN 11: Hardcoded credentials in config (CWE-798)
fn get_config() -> HashMap<String, String> {
    let mut config = HashMap::new();
    config.insert("db_host".to_string(), DB_HOST.to_string());
    config.insert("db_user".to_string(), DB_USER.to_string());
    config.insert("db_pass".to_string(), DB_PASS.to_string());
    config.insert("api_key".to_string(), API_KEY.to_string());
    config
}

// VULN 12: Unsafe JSON deserialization (CWE-502)
fn parse_input(input: &str) -> String {
    // Simulating unsafe deserialization pattern
    format!("Parsed: {}", input)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <action> <param>", args[0]);
        return;
    }

    let action = &args[1];
    let param = &args[2];

    match action.as_str() {
        "ping" => println!("{}", ping_host(param)),
        "run" => println!("{}", run_command(param)),
        "file" => println!("{}", read_file(param)),
        "download" => println!("{}", download_file(param)),
        "search" => println!("{}", search_page(param)),
        "user" => println!("{}", get_user(param)),
        "search-users" => println!("{}", search_users(param)),
        "error" => println!("{}", handle_error()),
        "config" => println!("{:?}", get_config()),
        "parse" => println!("{}", parse_input(param)),
        _ => println!("Unknown action"),
    }
}
