package main

import (
	"github.com/DipsDev/mason/common"
	"github.com/DipsDev/mason/controllers"
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

	common.Init(os.Getenv("MASON_DATABASE_DSN"))
	defer common.Close()

	router := http.NewServeMux()

	router.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("public"))))

	// Auth
	router.HandleFunc("/login/", controllers.ShowLogin)
	router.HandleFunc("POST /login/", controllers.CreateLogin)
	router.HandleFunc("/logout/", controllers.HandleLogout)

	// Panel
	router.Handle("/panel/", common.WithSession(controllers.ShowPanelFrame))
	router.Handle("/panel/overview/", common.WithSession(controllers.ShowPanelOverview))
	router.Handle("/panel/settings/", common.WithSession(controllers.ShowPanelSettings))
	router.Handle("/panel/pages/", common.WithSession(controllers.ShowPanelPages))

	// users
	router.Handle("/panel/users/", common.WithSession(controllers.ShowUsers))
	router.Handle("/panel/users/new", common.WithSession(controllers.CreateUsers))

	server := &http.Server{Addr: ":8080", Handler: router}

	log.Println("Server is running on http://localhost:8080")
	server.ListenAndServe()
}
