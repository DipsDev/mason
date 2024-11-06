package main

import (
	"github.com/DipsDev/mason/controllers"
	"github.com/DipsDev/mason/db"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("[Mason] Error loading .env file")
		return
	}

	db.Init(os.Getenv("MASON_DATABASE_DSN"))
	defer db.Close()

	router := http.NewServeMux()

	router.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("public"))))

	// Auth
	router.HandleFunc("/login", controllers.ShowLogin)
	router.HandleFunc("POST /login", controllers.CreateLogin)
	router.HandleFunc("/logout", controllers.HandleLogout)

	// Panel
	router.HandleFunc("/panel", controllers.ShowPanelFrame)
	router.HandleFunc("/panel/overview", controllers.ShowPanelOverview)
	router.HandleFunc("/panel/settings", controllers.ShowPanelSettings)

	server := &http.Server{Addr: ":8080", Handler: router}

	log.Println("Server is running on http://localhost:8080")
	server.ListenAndServe()
}
