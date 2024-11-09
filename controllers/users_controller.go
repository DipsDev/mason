package controllers

import (
	"database/sql"
	"github.com/DipsDev/mason/common"
	"github.com/DipsDev/mason/templates/pages"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strconv"
)

type createFormData struct {
	username  string
	email     string
	password  string
	roleCode  string
	csrfToken string
}

func CreateUsers(w http.ResponseWriter, r *http.Request) {
	session, ok := common.GetSession(r.Context())

	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method == "" || r.Method == "GET" {
		pages.CreateUsers(session.CsrfToken).Render(r.Context(), w)
		return
	}

	user := common.GetSessionUser(r.Context())

	if user == nil || user.Role != common.Administrator {
		http.Redirect(w, r, "/panel", http.StatusFound)
		return
	}
	formData := createFormData{}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// load form data
	formData.roleCode = r.Form.Get("role")
	formData.username = r.Form.Get("username")
	formData.password = r.Form.Get("password")
	formData.email = r.Form.Get("email")
	formData.csrfToken = r.Form.Get("csrf-token")

	// validate csrf
	if formData.csrfToken != session.CsrfToken {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if formData.username == "" || formData.password == "" || formData.email == "" || formData.roleCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	role, err := strconv.Atoi(formData.roleCode)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if role >= int(common.END) || role < 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	stmtOut, err := common.DB.Prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer stmtOut.Close()

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(formData.password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = stmtOut.Exec(formData.username, formData.email, hashedPass, role)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/panel/users", http.StatusFound)
}

func ShowUsers(w http.ResponseWriter, r *http.Request) {

	q := r.URL.Query().Get("q")
	var rows *sql.Rows
	if q != "" {
		stmtOut, err := common.DB.Prepare("SELECT id, email, username, role FROM users where username LIKE ?")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		rows, err = stmtOut.Query("%" + q + "%")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

	} else {
		stmtOut, err := common.DB.Prepare("SELECT id, email, username, role FROM users")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		rows, err = stmtOut.Query()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	users := make([]common.User, 0)

	for rows.Next() {
		var cur common.User
		err := rows.Scan(&cur.Id, &cur.Email, &cur.Username, &cur.Role)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		users = append(users, cur)
	}
	pages.ShowUsers(users, len(users), q).Render(r.Context(), w)
}
