package common

import (
	"database/sql"
	"log"
)

var DB *sql.DB

func InitDatabase(dsn string) {
	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("[Mason] Couldn't connect to database. is it on?")
		return
	}
	err = DB.Ping()
	if err != nil {
		log.Fatalf("[Mason] Couldn't connect to database. is it on?\n %d", err.Error())
		return
	}
}

func CloseDatabase() {
	DB.Close()
}
