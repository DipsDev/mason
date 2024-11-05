package main

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"
)

func main() {

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
