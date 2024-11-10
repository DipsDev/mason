package common

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"log"
)

var DB *sql.DB

func InitDatabase(dsn string) {
	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("[Mason] Couldn't connect to database. is it on?\n %s", err.Error())
		return
	}
	err = DB.Ping()
	if err != nil {
		log.Fatalf("[Mason] Couldn't connect to database. is it on?\n %s", err.Error())
		return
	}
}

func CloseDatabase() {
	DB.Close()
}
