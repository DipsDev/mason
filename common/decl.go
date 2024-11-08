package common

type User struct {
	Id       string
	Email    string
	Username string
	// add more as project grows
}

type Role int

const (
	Viewer Role = iota
	Editor
	Administrator
)
