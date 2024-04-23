package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func createDB() {
	db, err := sql.Open("sqlite3", "database/database.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Создание таблицы User
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS User (
  ID INTEGER PRIMARY KEY,
  USERNAME TEXT,
  PASSWORD TEXT,
  PLUS_TIMING INTEGER,
  MINUS_TIMING INTEGER,
  MULTIPLY_TIMING INTEGER,
  DIVIDE_TIMING INTEGER,
  TOSHOW_TIMING INTEGER
 )`)
	if err != nil {
		log.Fatal(err)
	}

	// Создание таблицы Expression
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS Expression (
  EXPRESSION_ID INTEGER PRIMARY KEY,
  EXPRESSION_TEXT TEXT,
  STATUS TEXT,
  USER_NAME TEXT,
  EXPRESSION_RESULT TEXT
 )`)
	if err != nil {
		log.Fatal(err)
	}

	// Создание таблицы Agent
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS Agent (
  AGENT_ID INTEGER PRIMARY KEY,
  STATUS TEXT,
  PORT TEXT,
  NOT_RESPONDED_FOR INTEGER
 )`)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Database created successfully")
}
