package controllers

import (
	"database/sql"
	"github.com/DipsDev/mason/common"
	"github.com/DipsDev/mason/templates/pages"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strconv"
	"strings"
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

	user := common.GetSessionUser(r.Context())

	if user == nil || user.Role != common.Administrator {
		http.Redirect(w, r, "/panel", http.StatusFound)
		return
	}

	if r.Method == "" || r.Method == "GET" {
		pages.CreateUsers("").Render(r.Context(), w)
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

	if strings.TrimSpace(formData.username) == "" || strings.TrimSpace(formData.password) == "" ||
		strings.TrimSpace(formData.email) == "" || strings.TrimSpace(formData.roleCode) == "" {
		pages.CreateUsers("One of the given values is empty.").Render(r.Context(), w)
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
		pages.CreateUsers("There was an error trying to execute.").Render(r.Context(), w)
		return
	}
	defer stmtOut.Close()

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(formData.password), bcrypt.DefaultCost)
	if err != nil {
		pages.CreateUsers("There was an error trying to execute.").Render(r.Context(), w)
		return
	}

	_, err = stmtOut.Exec(formData.username, formData.email, hashedPass, role)
	if err != nil {
		pages.CreateUsers("There was an error trying to execute.").Render(r.Context(), w)
		return
	}
	http.Redirect(w, r, "/panel/users", http.StatusFound)
}

func DeleteUsers(w http.ResponseWriter, r *http.Request) {
	user := common.GetSessionUser(r.Context())
	if user == nil || user.Role != common.Administrator {
		http.Redirect(w, r, "/panel", http.StatusFound)
		return
	}

	deleteId := r.PathValue("user_id")

	if deleteId == "" || deleteId == user.Id {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	stmtOut, err := common.DB.Prepare("DELETE FROM users WHERE id = ?")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer stmtOut.Close()
	_, err = stmtOut.Exec(deleteId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("HX-Redirect", "/panel/users")
		return
	}
	http.Redirect(w, r, "/panel/users", http.StatusFound)
}

type showUsersViewModel struct {
	users   []common.User
	numRows int
	query   string

	errorMessage string
	statusCode   int
}

func ShowUsers(w http.ResponseWriter, r *http.Request) {
	result := showUsers(w, r)
	pages.ShowUsers(result.users, result.numRows, result.query, result.errorMessage).Render(r.Context(), w)

}

func showUsers(w http.ResponseWriter, r *http.Request) showUsersViewModel {

	q := r.URL.Query().Get("q")
	var rows *sql.Rows
	var err error
	if q != "" {
		rows, err = common.DB.Query("SELECT id, email, username, role, COUNT(*) FROM users where username LIKE ?", "%"+q+"%")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return showUsersViewModel{
				users:   []common.User{},
				numRows: 0,
				query:   q,

				errorMessage: "An unexpected error occurred.",
				statusCode:   http.StatusInternalServerError,
			}
		}

	} else {
		rows, err = common.DB.Query("SELECT id, email, username, role FROM users")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return showUsersViewModel{
				users:   []common.User{},
				numRows: 0,
				query:   q,

				errorMessage: "An unexpected error occurred.",
				statusCode:   http.StatusInternalServerError,
			}
		}
	}
	defer rows.Close()

	users := make([]common.User, 0)

	for rows.Next() {
		var cur common.User
		if err := rows.Scan(&cur.Id, &cur.Email, &cur.Username, &cur.Role); err != nil {
			return showUsersViewModel{
				users:   []common.User{},
				numRows: 0,
				query:   q,

				errorMessage: "An unexpected error occurred.",
				statusCode:   http.StatusInternalServerError,
			}
		}

		users = append(users, cur)
	}
	return showUsersViewModel{
		users:   users,
		numRows: len(users),
		query:   q,

		errorMessage: "",
		statusCode:   http.StatusOK,
	}
}

func EditUsers(w http.ResponseWriter, r *http.Request) {
	userId := r.PathValue("user_id")
	currentUser := common.GetSessionUser(r.Context())

	if currentUser.Role != common.Administrator || currentUser.Id == userId {
		http.Redirect(w, r, "/panel", http.StatusFound)
	}

	if r.Method == "" || r.Method == "GET" {
		stmtOut, err := common.DB.Prepare("SELECT id, username, email, role from users where id = ?")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer stmtOut.Close()

		var user common.User
		err = stmtOut.QueryRow(userId).Scan(&user.Id, &user.Username, &user.Email, &user.Role)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		pages.EditUsers(&user, "").Render(r.Context(), w)
		return
	}

	if r.Method == "DELETE" {
		DeleteUsers(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	newUsername := r.Form.Get("username")
	newRole := r.Form.Get("role")

	role, err := strconv.Atoi(newRole)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if role >= int(common.END) || role < 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(newUsername) == "" || strings.TrimSpace(newRole) == "" {
		pages.EditUsers(&common.User{Id: userId, Username: newUsername}, "").Render(r.Context(), w)
		return
	}

	stmtOut, err := common.DB.Prepare("UPDATE users SET username = ?, role = ? WHERE id = ?")
	if err != nil {
		pages.EditUsers(&common.User{Id: userId, Username: newUsername}, "There was a error trying to execute the command. make sure the username is unique.").Render(r.Context(), w)
		return
	}
	defer stmtOut.Close()

	_, err = stmtOut.Exec(newUsername, newRole, userId)
	if err != nil {
		pages.EditUsers(&common.User{Id: userId, Username: newUsername}, "There was a error trying to execute the command. make sure the username is unique.").Render(r.Context(), w)
		return
	}

	http.Redirect(w, r, "/panel/users", http.StatusFound)

}
