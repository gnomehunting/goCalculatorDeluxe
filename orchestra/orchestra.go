package main

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type User struct {
	ID             int    `db:"ID"`
	JWT            string `db:"JWT"`
	UserName       string `db:"USERNAME"`
	Password       string `db:"PASSWORD"`
	PlusTiming     int    `db:"PLUS_TIMING"`
	MinusTiming    int    `db:"MINUS_TIMING"`
	MultiplyTiming int    `db:"MULTIPLY_TIMING"`
	DivideTiming   int    `db:"DIVIDE_TIMING"`
	ToShowTiming   int    `db:"TOSHOW_TIMING"`
}

type Expression struct {
	ExpressionID     int    `db:"EXPRESSION_ID"`
	ExpressionText   string `db:"EXPRESSION_TEXT"`
	Status           string `db:"STATUS"`
	UserName         string `db:"USER_NAME"`
	ExpressionResult int    `db:EXPRESSION_RESULT`
}

type Agent struct {
	AgentID         int    `db:"AGENT_ID"`
	Status          string `db:"STATUS"`
	Port            string `db:"PORT"`
	NotRespondedFor int    `db:"NOT_RESPONDED_FOR"`
}
type TemplateAgentData struct {
	List     []Agent
	Username string
}

type TemplateExpressionsData struct {
	List     []Expression
	Username string
}

type TemplateUserData struct {
	List     []User
	Username string
}

var (
	secretkey             = []byte("supersecretkey")
	validCookies          = []string{}
	EXAMPLEagentList      = []Agent{{1, "online", "8085", 0}, {2, "online", "8085", 0}, {3, "online", "8085", 0}}
	EXAMPLEexpressionList = []Expression{{1, "2+2", "notsolved", "lilbobby", 0}, {2, "2+3", "notsolved", "freakyBob", 0}, {3, "2+4", "notsolved", "freakyBob", 0}}
	EXAMPLEuserList       = []User{{1, "jwt", "FreakyBob", "password", 10, 10, 10, 10, 10}, {1, "jwt", "BillyBalls", "password", 20, 20, 20, 20, 20}}
)

///////////////////////////////////////////
//INSTRUMENTARY FUNCTIONS
///////////////////////////////////////////

func isValidExpression(expression string) bool { // функция, которая проверяет выражение на правильность (скобки/знаки/цифры)
	re := regexp.MustCompile(`^\d+([\+\-\*\/]\d+)+$`)
	withoutcommas := expression
	withoutcommas = strings.ReplaceAll(withoutcommas, "(", "")
	withoutcommas = strings.ReplaceAll(withoutcommas, ")", "")

	ismatching := re.MatchString(withoutcommas)

	stack := []rune{}

	for _, char := range expression {
		if char == '(' {
			stack = append(stack, '(')
		} else if char == ')' {
			if len(stack) == 0 {
				return false
			}
			stack = stack[:len(stack)-1]
		}
	}

	return len(stack) == 0 && ismatching
}

func extractUsernameFromCookie(jwtCookie string) (string, error) { // функция, которая извлекает логин из jwt токена
	var username string
	secretKey := secretkey
	token, err := jwt.Parse(jwtCookie, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username = claims["username"].(string)
	} else {
		return "", fmt.Errorf("Invalid token claims")
	}

	return username, nil
}
func generateJWTToken(username, password string) (string, error) {
	// Создаем новый токен
	token := jwt.New(jwt.SigningMethodHS256)

	// Устанавливаем клеймы (полезную нагрузку) для токена
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["password"] = password
	claims["exp"] = time.Now().Add(time.Hour).Unix()

	// Подписываем токен с секретным ключом
	tokenString, err := token.SignedString(secretkey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

///////////////////////////////////////////
//REGISTRATION & LOGIN
///////////////////////////////////////////

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("html/login.html"))
	tmpl.Execute(w, nil)

}

//func RegistrationHandler(w http.ResponseWriter, r *http.Request) {
//	tmpl := template.Must(template.ParseFiles("html/registration.html"))
//	tmpl.Execute(w, nil)
//}

func SetCookieAndRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		SetCookieMiddleware(w, username, password)
		http.Redirect(w, r, "/calculator/", http.StatusSeeOther)
	}
}

func SetCookieMiddleware(w http.ResponseWriter, username, password string) {
	jwtToken, _ := generateJWTToken(username, password)
	validCookies = append(validCookies, jwtToken) //!!!!!!!!!!!!!!!! ПЕРЕДЕЛАТЬ ДОБАВЛЕНИЕ В ДБ, ВОЗМОЖНО ПОНАДРОБИТСЯ ФУНКЦИЯ

	// Создаем cookie для jwt_token
	jwtCookie := &http.Cookie{
		Name:   "jwt_token",
		Value:  jwtToken,
		Path:   "/",
		Domain: "localhost",
	}
	http.SetCookie(w, jwtCookie)

	// Создаем cookie для username
	usernameCookie := &http.Cookie{
		Name:   "username",
		Value:  username,
		Path:   "/",
		Domain: "localhost",
	}
	http.SetCookie(w, usernameCookie)
}

// http.HandleFunc("/<youraddr>", CheckCookieMiddleware(<yourfunc>, validCookies))
func CheckCookieMiddleware(next http.HandlerFunc, validCookies *[]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt_token")
		if err != nil || !slices.Contains(*validCookies, cookie.Value) {
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}
		username, err := r.Cookie("username")
		if err != nil || !slices.Contains(*validCookies, cookie.Value) {
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), "username", username.Value)
		next(w, r.WithContext(ctx))
	}
}

func main() {
	//http.HandleFunc("/registration", RegistrationHandler)
	http.HandleFunc("/login/", LoginHandler)

	http.HandleFunc("/submit/", SetCookieAndRedirect)
	http.HandleFunc("/agents/", CheckCookieMiddleware(AgentsPage, &validCookies))
	http.HandleFunc("/calculator/", CheckCookieMiddleware(CalculatorPage, &validCookies))
	http.HandleFunc("/timings/", CheckCookieMiddleware(TimingsPage, &validCookies))
	http.ListenAndServe(":8080", nil)
}

///////////////////////////////////////////
//CALCULATOR
///////////////////////////////////////////

func ReceiveResult(w http.ResponseWriter, r *http.Request) {
	// агент отправляет сюда номер выражения которое он решал и его результат
}

func AddExpression(w http.ResponseWriter, r *http.Request) {
	// добавляется выражение в дб, которое пользователь отправил
}

func CalculatorPage(w http.ResponseWriter, r *http.Request) { // /calculator/ отрисовка страницы калькулятор, в темплейт передаётся мапа выражений
	tmpl := template.Must(template.ParseFiles("html/calculator.html"))
	username := r.Context().Value("username").(string)
	data := TemplateExpressionsData{
		List:     EXAMPLEexpressionList,
		Username: username,
	}
	tmpl.Execute(w, data)
	//делается запрос в дб, он требует выражения, у которых username == cookie.username, и список с ними отправляется в темплейт
}

func ChangeTimings(w http.ResponseWriter, r *http.Request) {
	//пользователь отправыляет сюда новые тайминги и они меняются в бд
}

func TimingsPage(w http.ResponseWriter, r *http.Request) { // /timings/ отрисовка страницы с таймингами, в темплейт передаются тайминги
	tmpl := template.Must(template.ParseFiles("html/timings.html"))
	tmpl.Execute(w, EXAMPLEuserList)
	username := r.Context().Value("username").(string)
	data := TemplateUserData{
		List:     EXAMPLEuserList,
		Username: username,
	}
	tmpl.Execute(w, data)
	//делается запрос в дб, он требует пользователей, у которых username == cookie.username, его тайминги
}

func AddAgent(w http.ResponseWriter, r *http.Request) {
	//добавляется агент в дб(юзер вводит порт)
}

func AgentsPage(w http.ResponseWriter, r *http.Request) { // /agents/ отрисовка страницы с агентами, в темплейт передаётся список агентов
	tmpl := template.Must(template.ParseFiles("html/agents.html"))
	tmpl.Execute(w, EXAMPLEagentList)
	username := r.Context().Value("username").(string)
	data := TemplateAgentData{
		List:     EXAMPLEagentList,
		Username: username,
	}
	tmpl.Execute(w, data)
}

func heartbeat() {
	//всем подключенным агентам отправляется хартбит через цикл фор, те, кто не принял - not responding

}
func ResetAgent() {
	//обнуляем агента
}
func dbPuller() {

} //берём всё из дб, раскидываем по спискам, всем агентам присылаем приказ обнулиться

func solver() {
	//пробегаемся по выражениям и раскидываем их по свободным агентам
}
