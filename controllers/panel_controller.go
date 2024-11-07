package controllers

import (
	"github.com/DipsDev/mason/common"
	"github.com/DipsDev/mason/templates/pages"
	"net/http"
)

func ShowPanelFrame(w http.ResponseWriter, r *http.Request) {
	pages.Panel("Panel", pages.EmptyPanel()).Render(r.Context(), w)

}

func ShowPanelOverview(w http.ResponseWriter, r *http.Request) {
	pages.Panel("Overview", pages.Overview()).Render(r.Context(), w)

}

func ShowPanelSettings(w http.ResponseWriter, r *http.Request) {
	pages.Panel("Panel Settings", pages.Settings()).Render(r.Context(), w)
}

func ShowPanelPages(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "" {
		pages.Panel("Pages", pages.Pages()).Render(r.Context(), w)
		return
	}
	pages.Pages().Render(r.Context(), w)
}

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

	pages.Panel("Users", pages.Users(users)).Render(r.Context(), w)

}
