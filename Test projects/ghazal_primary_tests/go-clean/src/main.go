package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func init() {
	var err error
	dsn := os.Getenv("DB_DSN")
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	var name, email string
	err := db.QueryRow("SELECT name, email FROM users WHERE id = ?", userID).Scan(&name, &email)
	if err != nil {
		http.Error(w, "User not found", 404)
		return
	}
	fmt.Fprintf(w, "Name: %s, Email: %s", name, email)
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("name")
	clean := filepath.Clean(filename)
	filepath := filepath.Join("data", clean)
	data, err := os.ReadFile(filepath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	w.Write(data)
}

func main() {
	http.HandleFunc("/api/user", getUserHandler)
	http.HandleFunc("/api/file", fileHandler)
	fmt.Println("Ghazal Go clean app running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
