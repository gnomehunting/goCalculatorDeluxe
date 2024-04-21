package main

import (
	"fmt"
	"net/http"
)

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/eblan", http.StatusSeeOther)
}

func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set JWT token cookie here
		token := "example_jwt_token"
		cookie := http.Cookie{
			Name:  "jwt_token",
			Value: token,
		}
		http.SetCookie(w, &cookie)

		next.ServeHTTP(w, r)
	})
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "eblan")
}
func main() {
	http.HandleFunc("/", redirectHandler)
	http.HandleFunc("/eblan", handler)
	http.ListenAndServe(":8080", jwtMiddleware(http.DefaultServeMux))
}
