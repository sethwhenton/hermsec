package main

import (
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// VULN 1: Hardcoded database credentials (CWE-798)
const (
	DBUser = "admin"
	DBPass = "s3cretP@ss123!"
)

// VULN 2: Hardcoded API key (CWE-798)
const APIKey = "vulntest-go-api-key-ak1234567890abcdef"

var db *sql.DB

func init() {
	var err error
	// VULN 3: SQL Injection - connection string with credentials (CWE-798)
	dsn := DBUser + ":" + DBPass + "@tcp(localhost:3306)/vulntestdb"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
}

// VULN 4: SQL Injection via string formatting (CWE-89)
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID)
	var name, email string
	err := db.QueryRow(query).Scan(&name, &email)
	if err != nil {
		http.Error(w, "User not found", 404)
		return
	}
	fmt.Fprintf(w, "Name: %s, Email: %s", name, email)
}

// VULN 5: Command Injection via exec.Command (CWE-78)
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("ping", "-c", "4", host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}

// VULN 6: Command Injection with shell (CWE-78)
func runHandler(w http.ResponseWriter, r *http.Request) {
	command := r.FormValue("command")
	cmd := exec.Command("sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}

// VULN 7: Path Traversal in file read (CWE-22)
func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("name")
	filepath := filepath.Join("data", filename)
	data, err := os.ReadFile(filepath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	w.Write(data)
}

// VULN 8: Path Traversal in download (CWE-22)
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	fullPath := filepath.Join("/var/uploads", file)
	http.ServeFile(w, r, fullPath)
}

// VULN 9: XSS via unsanitized template (CWE-79)
func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	tmpl := template.Must(template.New("search").Parse(
		"<html><body><h1>Search results for: " + query + "</h1></body></html>"))
	tmpl.Execute(w, nil)
}

// VULN 10: Weak hash MD5 (CWE-328)
func hashHandler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	hash := md5.Sum([]byte(password))
	fmt.Fprintf(w, "Hash: %x", hash)
}

// VULN 11: Weak random for token (CWE-330)
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	rand.Read(b)
	token := fmt.Sprintf("%x", b)
	fmt.Fprintf(w, "Token: %s", token)
}

// VULN 12: Information exposure - verbose errors (CWE-209)
func errorHandler(w http.ResponseWriter, r *http.Request) {
	_, err := os.ReadFile("/nonexistent/path")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v\nStack: %s", err, string(debugStack())), 500)
		return
	}
}

func debugStack() []byte {
	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)
	return buf[:n]
}

func main() {
	http.HandleFunc("/api/user", getUserHandler)
	http.HandleFunc("/api/ping", pingHandler)
	http.HandleFunc("/api/run", runHandler)
	http.HandleFunc("/api/file", fileHandler)
	http.HandleFunc("/api/download", downloadHandler)
	http.HandleFunc("/api/search", searchHandler)
	http.HandleFunc("/api/hash", hashHandler)
	http.HandleFunc("/api/token", tokenHandler)
	http.HandleFunc("/api/error", errorHandler)

	fmt.Println("VulnTest Go vulnerable app running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
