package controllers

import (
	"github.com/DipsDev/mason/common"
	"github.com/DipsDev/mason/templates/components"
	"github.com/DipsDev/mason/templates/pages"
	"net/http"
)

func CreateUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method == "" {
		pages.Panel("Add New User", components.CreateUsers()).Render(r.Context(), w)
		return
	}
}

func ShowUsers(w http.ResponseWriter, r *http.Request) {
	stmtOut, err := common.DB.Prepare("SELECT id, email, username, role FROM users")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	rows, err := stmtOut.Query()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	users := make([]common.User, 0)

	for rows.Next() {
		var cur common.User
		err = rows.Scan(&cur.Id, &cur.Email, &cur.Username, &cur.Role)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		users = append(users, cur)
	}
	pages.Panel("Users", components.ShowUsers(users, len(users))).Render(r.Context(), w)
}
