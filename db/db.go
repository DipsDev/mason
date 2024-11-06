package db

import (
	"database/sql"
	"log"
)

var DB *sql.DB

func Init(dsn string) {
	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("[Mason] Couldn't connect to database. is it on?")
		return
	}
	err = DB.Ping()
	if err != nil {
		log.Fatal("[Mason] Couldn't connect to database. is it on?")
		return
	}
}

func Close() {
	DB.Close()
}
