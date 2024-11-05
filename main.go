package main

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"

	"github.com/joho/godotenv"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	envErr := godotenv.Load()
	if envErr != nil {
		log.Fatal("Error loading .env file")
		return
	}
	sqlDsn, ok := os.LookupEnv("MASON_DATABASE_DSN")
	if !ok {
		log.Fatal("[Mason] Couldn't connect to database: Missing MASON_DATABASE_DSN.")
		return
	}

	_, err := sql.Open("mysql", sqlDsn)
	if err != nil {
		log.Fatal("[mason] Couldn't connect to database: Is it active?", err)
		return
	}

	http.Handle("/public/", http.FileServer(http.Dir("public")))

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		tmpl, tmpl_err := template.ParseFiles(filepath.Join("templates", "login_page.html"))
		if tmpl_err != nil {
			log.Println(tmpl_err)
			return
		}
		err := tmpl.Execute(w, "no data needed")
		if err != nil {
			return
		}

	})
	log.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
