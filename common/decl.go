package common

type userRole int

const (
	Viewer userRole = iota
	Editor
	Administrator
	END
)

func TranslateRole(role userRole) string {
	switch role {
	case Viewer:
		return "Viewer"
	case Editor:
		return "Editor"
	case Administrator:
		return "Administrator"
	default:
		panic("unhandled default case")
	}
}

type User struct {
	Id       string
	Email    string
	Username string
	Role     userRole
	// add more as project grows
}
