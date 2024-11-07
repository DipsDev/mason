package controllers

import (
	"github.com/DipsDev/mason/common"
	"github.com/DipsDev/mason/templates/components"
	"github.com/DipsDev/mason/templates/pages"
	"net/http"
)

func ShowPanelUsers(w http.ResponseWriter, r *http.Request) {
	stmtOut, err := common.DB.Prepare("SELECT id, email FROM users")
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
		err = rows.Scan(&cur.Id, &cur.Email)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		users = append(users, cur)
	}
	pages.Panel("Users", components.ShowUsers(users, len(users))).Render(r.Context(), w)

}
