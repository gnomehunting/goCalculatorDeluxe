package main

import (
	"database/sql"
	"log"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var dbMutex sync.Mutex

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "database.db")
	if err != nil {
		log.Fatal(err)
	}

	// Установка максимального числа открытых соединений
	db.SetMaxOpenConns(10)
}

func insertUser(username string, password string) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	_, err := db.Exec("INSERT INTO User (USERNAME, PASSWORD) VALUES (?, ?)", username, password)
	if err != nil {
		log.Println(err)
	}
}

func selectUsers() {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	rows, err := db.Query("SELECT ID, USERNAME FROM User")
	if err != nil {
		log.Println(err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var username string
		err := rows.Scan(&id, &username)
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("User ID: %d, Username: %s\n", id, username)
	}
}

func main() {
	initDB()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		insertUser("john_doe", "password123")
	}()

	go func() {
		defer wg.Done()
		selectUsers()
	}()

	wg.Wait()
}
