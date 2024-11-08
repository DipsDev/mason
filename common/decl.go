package common

type userRole int

const (
	Viewer userRole = iota
	Editor
	Administrator
)

func TranslateRole(role userRole) string {
	switch role {
	case Viewer:
		return "Viewer"
	case Editor:
		return "Editor"
	case Administrator:
		return "Administrator"
	}
	return "should not happen"
}

type User struct {
	Id       string
	Email    string
	Username string
	Role     userRole
	// add more as project grows
}
