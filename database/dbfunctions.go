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

// Function to initialize the database and create tables
func initDB(db *sql.DB) {
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
	CURRENT_EXPRESSION_ID INTEGER,
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

func addUser(db *sql.DB, jwt, login, password string, plusTiming, minusTiming, multiplyTiming, divideTiming, toShowTiming int) {
	_, err := db.Exec("INSERT INTO USERS (JWT, LOGIN, PASSWORD, PLUS_TIMING, MINUS_TIMING, MULTIPLY_TIMING, DIVIDE_TIMING, TOSHOW_TIMING) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		jwt, login, password, plusTiming, minusTiming, multiplyTiming, divideTiming, toShowTiming)
	if err != nil {
		log.Fatal(err)
	}
}

func deleteUser(db *sql.DB, id int) {
	_, err := db.Exec("DELETE FROM USERS WHERE ID = ?", id)
	if err != nil {
		log.Fatal(err)
	}
}

func updateUserJWT(db *sql.DB, id int, newJWT string) {
	_, err := db.Exec("UPDATE USERS SET JWT = ? WHERE ID = ?",
		newJWT, id)
	if err != nil {
		log.Fatal(err)
	}
}

func updateUserTimings(db *sql.DB, id int, plusTiming, minusTiming, multiplyTiming, divideTiming, toShowTiming int) {
	_, err := db.Exec("UPDATE USERS SET (PLUS_TIMING, MINUS_TIMING, MULTIPLY_TIMING, DIVIDE_TIMING, TOSHOW_TIMING) VALUES (?, ?, ?, ?, ?) WHERE ID = ?",
		plusTiming, minusTiming, multiplyTiming, divideTiming, toShowTiming, id)
	if err != nil {
		log.Fatal(err)
	}
}

func getUserByID(db *sql.DB, id int) (User, error) {
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

func addExpression(db *sql.DB, expressionText string, status string, userId int) {
	_, err := db.Exec("INSERT INTO EXPRESSIONS (EXPRESSION_TEXT, STATUS, USER_ID) VALUES (?, ?, ?)",
		expressionText, status, userId)
	if err != nil {
		log.Fatal(err)
	}
}

func deleteExpression(db *sql.DB, expressionId int) {
	_, err := db.Exec("DELETE FROM EXPRESSIONS WHERE EXPRESSION_ID = ?", expressionId)
	if err != nil {
		log.Fatal(err)
	}
}

func updateExpressionStatus(db *sql.DB, expressionId int, newStatus string) {
	_, err := db.Exec("UPDATE EXPRESSIONS SET (STATUS) VALUES (?) WHERE EXPRESSION_ID = ?",
		newStatus, expressionId)
	if err != nil {
		log.Fatal(err)
	}
}

func getExpressionByID(db *sql.DB, expressionId int) (Expression, error) {
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

func addAgent(db *sql.DB, status string, port string, CurrentExpressionID, notRespondedFor int) {
	_, err := db.Exec("INSERT INTO AGENTS (STATUS, PORT, CURRENT_EXPRESSION_ID, NOT_RESPONDED_FOR) VALUES (?, ?, ?, ?)",
		status, port, CurrentExpressionID, notRespondedFor)
	if err != nil {
		log.Fatal(err)
	}
}

func deleteAgent(db *sql.DB, agentId int) {
	_, err := db.Exec("DELETE FROM AGENTS WHERE AGENT_ID = ?", agentId)
	if err != nil {
		log.Fatal(err)
	}
}

func updateAgentStatus(db *sql.DB, agentId int, newStatus string) {
	_, err := db.Exec("UPDATE AGENTS SET (STATUS) VALUES (?) WHERE AGENT_ID = ?",
		newStatus, agentId)
	if err != nil {
		log.Fatal(err)
	}
}

func updateAgentPort(db *sql.DB, agentId int, newPort int) {
	_, err := db.Exec("UPDATE AGENTS SET (PORT) VALUES (?) WHERE AGENT_ID = ?",
		newPort, agentId)
	if err != nil {
		log.Fatal(err)
	}
}

func updateAgentNotRespondedFor(db *sql.DB, agentId int, notRespondedFor int) {
	_, err := db.Exec("UPDATE AGENTS SET (NOT_RESPONDED_FOR) VALUES (?) WHERE AGENT_ID = ?",
		notRespondedFor, agentId)
	if err != nil {
		log.Fatal(err)
	}
}

func updateAgentCurrentExpressionId(db *sql.DB, agentId int, CurrentExpressionID int) {
	_, err := db.Exec("UPDATE AGENTS SET (CURRENT_EXPRESSION_ID) VALUES (?) WHERE AGENT_ID = ?",
		CurrentExpressionID, agentId)
	if err != nil {
		log.Fatal(err)
	}
}

func getAgentByID(db *sql.DB, agentId int) (Agent, error) {
	var agent Agent
	row := db.QueryRow("SELECT * FROM AGENTS WHERE AGENT_ID = ?", agentId)
	err := row.Scan(&agent.AgentID, &agent.Status, &agent.Port, &agent.CurrentExpressionID, &agent.NotRespondedFor)
	if err != nil {
		return Agent{}, err // Return empty Agent and error
	}
	return agent, nil
}

// FetchUsers fetches all users from the database and returns a list of User structs.
func FetchUsers(db *sql.DB) ([]User, error) {
	rows, err := db.Query("SELECT * FROM USERS")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.JWT, &user.Login, &user.Password, &user.PlusTiming, &user.MinusTiming,
			&user.MultiplyTiming, &user.DivideTiming, &user.ToShowTiming)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// FetchExpressions fetches all expressions from the database and returns a list of Expression structs.
func FetchExpressions(db *sql.DB) ([]Expression, error) {
	rows, err := db.Query("SELECT * FROM EXPRESSIONS")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var expressions []Expression
	for rows.Next() {
		var expression Expression
		err := rows.Scan(&expression.ExpressionID, &expression.ExpressionText, &expression.Status, &expression.UserId)
		if err != nil {
			return nil, err
		}
		expressions = append(expressions, expression)
	}
	return expressions, nil
}

// FetchAgents fetches all agents from the database and returns a list of Agent structs.
func FetchAgents(db *sql.DB) ([]Agent, error) {
	rows, err := db.Query("SELECT * FROM AGENTS")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var agent Agent
		err := rows.Scan(&agent.AgentID, &agent.Status, &agent.Port, &agent.CurrentExpressionID, &agent.NotRespondedFor)
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	return agents, nil
}

func main() {
	db := &sql.DB{}
	initDB(db)
	defer db.Close()
	//addUser("asd", "Biba", "lul", 10, 10, 10, 10, 10)
	//addUser("asd", "Boba", "lul", 10, 10, 10, 10, 10)
	//addUser("asd", "Idiot", "lul", 10, 10, 10, 10, 10)
	//addAgent("online", "8082", -1, 0)
	//addAgent("online", "8083", -1, 0)
	//addAgent("online", "8084", -1, 0)
	//addAgent("online", "8085", -1, 0)
	//addAgent("online", "8086", -1, 0)
	//addExpression("2+2", "unsolved", 1)
	//addExpression("2+3", "unsolved", 1)
	//addExpression("2+4", "unsolved", 1)
	//addExpression("2+5", "unsolved", 1)
	fmt.Println(FetchAgents(db))
	fmt.Println(FetchUsers(db))
	fmt.Println(FetchExpressions(db))
}
