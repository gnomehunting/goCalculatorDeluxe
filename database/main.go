package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

type User struct {
	ID             int    `db:"ID"`
	JWT            string `db:"JWT"`
	Login          string `db:"LOGIN"`
	Password       string `db:"PASSWORD"`
	PlusTiming     int    `db:"PLUS_TIMING"`
	MinusTiming    int    `db:"MINUS_TIMING"`
	MultiplyTiming int    `db:"MULTIPLY_TIMING"`
	DivideTiming   int    `db:"DIVIDE_TIMING"`
	ToShowTiming   int    `db:"TOSHOW_TIMING"`
}

type Expression struct {
	ExpressionID   int    `db:"EXPRESSION_ID"`
	ExpressionText string `db:"EXPRESSION_TEXT"`
	Status         string `db:"STATUS"`
	UserId         int    `db:"USER_ID"`
}

type Agent struct {
	AgentID             int    `db:"AGENT_ID"`
	Status              string `db:"STATUS"`
	Port                string `db:"PORT"`
	CurrentExpressionID int    `db:"CURRENT_EXPRESSION_ID"`
	NotRespondedFor     int    `db:"NOT_RESPONDED_FOR"`
}

// Database connection
var db *sql.DB

// Function to initialize the database and create tables
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./database/database.db") // Change path if needed
	if err != nil {
		log.Fatal(err)
	}

	// Create tables
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS USERS (
	ID INTEGER PRIMARY KEY AUTOINCREMENT,
	JWT TEXT,
	LOGIN TEXT UNIQUE,
	PASSWORD TEXT,
	PLUS_TIMING INTEGER,
	MINUS_TIMING INTEGER,
	MULTIPLY_TIMING INTEGER,
	DIVIDE_TIMING INTEGER,
	TOSHOW_TIMING INTEGER 
	);
  
	CREATE TABLE IF NOT EXISTS EXPRESSIONS (
   	EXPRESSION_ID INTEGER PRIMARY KEY AUTOINCREMENT,
   	EXPRESSION_TEXT TEXT,
   	STATUS TEXT,
   	USER_ID INTEGER REFERENCES USERS(ID)
  	);
  
  	CREATE TABLE IF NOT EXISTS AGENTS (
   	AGENT_ID INTEGER PRIMARY KEY AUTOINCREMENT,
   	STATUS TEXT,
   	PORT TEXT,
	CURRENT_EXPRESSION_ID INTEGER
   	NOT_RESPONDED_FOR INTEGER
  	);
 `)
	if err != nil {
		log.Fatal(err)
	}
}

// ---------------------
// USERS Table Functions
// ---------------------

func addUser(jwt, login, password string, plusTiming, minusTiming, multiplyTiming, divideTiming, toShowTiming int) {
	_, err := db.Exec("INSERT INTO USERS (JWT, LOGIN, PASSWORD, PLUS_TIMING, MINUS_TIMING, MULTIPLY_TIMING, DIVIDE_TIMING, TOSHOW_TIMING) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		jwt, login, password, plusTiming, minusTiming, multiplyTiming, divideTiming, toShowTiming)
	if err != nil {
		log.Fatal(err)
	}
}

func deleteUser(id int) {
	_, err := db.Exec("DELETE FROM USERS WHERE ID = ?", id)
	if err != nil {
		log.Fatal(err)
	}
}

func updateUserJWT(id int, newJWT string) {
	_, err := db.Exec("UPDATE USERS SET JWT = ? WHERE ID = ?",
		newJWT, id)
	if err != nil {
		log.Fatal(err)
	}
}

func updateUserTimings(id int, plusTiming, minusTiming, multiplyTiming, divideTiming, toShowTiming int) {
	_, err := db.Exec("UPDATE USERS SET (PLUS_TIMING, MINUS_TIMING, MULTIPLY_TIMING, DIVIDE_TIMING, TOSHOW_TIMING) VALUES (?, ?, ?, ?, ?) WHERE ID = ?",
		plusTiming, minusTiming, multiplyTiming, divideTiming, toShowTiming, id)
	if err != nil {
		log.Fatal(err)
	}
}

func getUserByID(id int) (User, error) {
	var user User
	row := db.QueryRow("SELECT * FROM USERS WHERE ID = ?", id)
	err := row.Scan(&user.ID, &user.JWT, &user.Login, &user.Password,
		&user.PlusTiming, &user.MinusTiming, &user.MultiplyTiming, &user.DivideTiming, &user.ToShowTiming)
	if err != nil {
		return User{}, err // Return empty User and error
	}
	return user, nil
}
func getUserIDByLogin(db *sql.DB, loginParam string) (int, error) {
	var userID int
	err := db.QueryRow("SELECT ID FROM USERS WHERE LOGIN = ?", loginParam).Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

// -------------------------
// EXPRESSIONS Table Functions
// -------------------------

func addExpression(expressionText string, status string, userId int) {
	_, err := db.Exec("INSERT INTO EXPRESSIONS (EXPRESSION_TEXT, STATUS, USER_ID) VALUES (?, ?, ?)",
		expressionText, status, userId)
	if err != nil {
		log.Fatal(err)
	}
}

func deleteExpression(expressionId int) {
	_, err := db.Exec("DELETE FROM EXPRESSIONS WHERE EXPRESSION_ID = ?", expressionId)
	if err != nil {
		log.Fatal(err)
	}
}

func updateExpressionStatus(expressionId int, newStatus string) {
	_, err := db.Exec("UPDATE EXPRESSIONS SET (STATUS) VALUES (?) WHERE EXPRESSION_ID = ?",
		newStatus, expressionId)
	if err != nil {
		log.Fatal(err)
	}
}

func getExpressionByID(expressionId int) (Expression, error) {
	var expression Expression
	row := db.QueryRow("SELECT * FROM EXPRESSIONS WHERE EXPRESSION_ID = ?", expressionId)
	err := row.Scan(&expression.ExpressionID, &expression.ExpressionText, &expression.Status, &expression.UserId)
	if err != nil {
		return Expression{}, err // Return empty Expression and error
	}
	return expression, nil
}

// ---------------------
// AGENTS Table Functions
// ---------------------

func addAgent(status string, port string, CurrentExpressionID, notRespondedFor int) {
	_, err := db.Exec("INSERT INTO AGENTS (STATUS, PORT, CURRENT_EXPRESSION_ID, NOT_RESPONDED_FOR) VALUES (?, ?, ?, ?)",
		status, port, CurrentExpressionID, notRespondedFor)
	if err != nil {
		log.Fatal(err)
	}
}

func deleteAgent(agentId int) {
	_, err := db.Exec("DELETE FROM AGENTS WHERE AGENT_ID = ?", agentId)
	if err != nil {
		log.Fatal(err)
	}
}

func updateAgentStatus(agentId int, newStatus string) {
	_, err := db.Exec("UPDATE AGENTS SET (STATUS) VALUES (?) WHERE AGENT_ID = ?",
		newStatus, agentId)
	if err != nil {
		log.Fatal(err)
	}
}

func updateAgentPort(agentId int, newPort int) {
	_, err := db.Exec("UPDATE AGENTS SET (PORT) VALUES (?) WHERE AGENT_ID = ?",
		newPort, agentId)
	if err != nil {
		log.Fatal(err)
	}
}

func updateAgentNotRespondedFor(agentId int, notRespondedFor int) {
	_, err := db.Exec("UPDATE AGENTS SET (NOT_RESPONDED_FOR) VALUES (?) WHERE AGENT_ID = ?",
		notRespondedFor, agentId)
	if err != nil {
		log.Fatal(err)
	}
}

func updateAgentCurrentExpressionId(agentId int, CurrentExpressionID int) {
	_, err := db.Exec("UPDATE AGENTS SET (CURRENT_EXPRESSION_ID) VALUES (?) WHERE AGENT_ID = ?",
		CurrentExpressionID, agentId)
	if err != nil {
		log.Fatal(err)
	}
}

func getAgentByID(agentId int) (Agent, error) {
	var agent Agent
	row := db.QueryRow("SELECT * FROM AGENTS WHERE AGENT_ID = ?", agentId)
	err := row.Scan(&agent.AgentID, &agent.Status, &agent.Port, &agent.CurrentExpressionID, &agent.NotRespondedFor)
	if err != nil {
		return Agent{}, err // Return empty Agent and error
	}
	return agent, nil
}

func main() {
	initDB()
	defer db.Close()
	fmt.Println(getUserByID(1))
}
