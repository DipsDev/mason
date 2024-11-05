package main

import (
	"github.com/DipsDev/mason/controllers"
	"github.com/joho/godotenv"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
)

func loadTemplates() *template.Template {
	dirs := []string{
		"templates/*.html",
		"templates/frames/*.html",
	}
	var files []string
	for _, dir := range dirs {
		ff, err := filepath.Glob(dir)
		if err != nil {
			panic(err)
		}
		files = append(files, ff...)
	}
	t, err := template.ParseFiles(files...)
	if err != nil {
		panic(err)
	}
	return t
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("[Mason] Error loading .env file")
		return
	}

	templates := loadTemplates()

	http.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("public"))))
	http.HandleFunc("GET /login", controllers.HandleGETLogin(templates))
	http.HandleFunc("POST /login", controllers.HandlePOSTLogin(templates))

	log.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
