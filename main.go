package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", loginPage)
	http.HandleFunc("/calculator", calculatorPage)
	http.ListenAndServe(":8080", nil)
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "login.html")
}

func calculatorPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if isValidCredentials(username, password) {
		fmt.Fprintf(w, "<h1>Welcome, %s!</h1>", username)
		// You can proceed to serve the calculator page here
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

func isValidCredentials(username, password string) bool {
	// Replace this with your actual validation logic
	// For example, you can check against a database
	validUsername := "user"
	validPassword := "password"
	return username == validUsername && password == validPassword
}
