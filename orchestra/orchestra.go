package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type User struct {
	ID             int    `db:"ID"`
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
	ExpressionResult string `db:"EXPRESSION_RESULT"`
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
	ShowFor  int
}

type TemplateExpressionsData struct {
	List     []Expression
	Username string
}

type TemplateUserData struct {
	List     []User
	Username string
}

type UserCredentials struct {
	Username string
	Password string
}

var (
	secretkey             = []byte("supersecretkey")
	validCookies          = []string{}
	EXAMPLEagentList      = []Agent{}
	EXAMPLEexpressionList = []Expression{}
	EXAMPLEuserList       = []User{}
	OrchestraPort         = ""
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

func extractDataFromCookie(jwtCookie string) (username, password string, err error) { // функция, которая извлекает логин и пароль из jwt токена
	secretKey := secretkey
	token, err := jwt.Parse(jwtCookie, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username = claims["username"].(string)
		password = claims["password"].(string)
	} else {
		return "", "", fmt.Errorf("invalid token claims")
	}

	return username, password, nil
}
func generateJWTToken(username, password string) (string, error) { //создание jwt токена
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
func getTimingsByExpression(expr Expression) (plus, minus, mu, div, toshow string) { //достаёт тайминги из юзера с помошью поля UserName у выражения
	for _, user := range EXAMPLEuserList {
		if user.UserName == expr.UserName {
			plus, minus, mu, div, toshow = strconv.Itoa(user.PlusTiming), strconv.Itoa(user.MinusTiming), strconv.Itoa(user.MultiplyTiming), strconv.Itoa(user.DivideTiming), strconv.Itoa(user.ToShowTiming)
			break
		}
	}
	return plus, minus, mu, div, toshow
}

///////////////////////////////////////////
//REGISTRATION & LOGIN
///////////////////////////////////////////

func LoginHandler(w http.ResponseWriter, r *http.Request) { // отрисовка страницы с логином
	tmpl := template.Must(template.ParseFiles("html/login.html"))
	tmpl.Execute(w, nil)

}

func RegistrationHandler(w http.ResponseWriter, r *http.Request) { // отрисовка страницы с регистрацией
	tmpl := template.Must(template.ParseFiles("html/registration.html"))
	tmpl.Execute(w, nil)
}

func RegisterUser(w http.ResponseWriter, r *http.Request) { //регистрация пользователя, проверяется, ненулевые ли поля, есть ли такой юзер, если всё нормально - создаёт нового пользователя
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		doneedtoadd := true

		// Проверка на пустые поля username и password
		if username == "" || password == "" {
			doneedtoadd = false
			http.Redirect(w, r, "/register/", http.StatusSeeOther)
			return
		}

		for _, user := range EXAMPLEuserList {
			if user.UserName == username {
				doneedtoadd = false
				http.Redirect(w, r, "/register/", http.StatusSeeOther)
				return
			}
		}
		if doneedtoadd {
			EXAMPLEuserList = append(EXAMPLEuserList, User{len(EXAMPLEuserList), username, password, 10, 10, 10, 10, 10})
		}
		http.Redirect(w, r, "/login/", http.StatusSeeOther)
	}
}

func LoginUser(w http.ResponseWriter, r *http.Request) { //логин пользователя, проверяет, есть ли такой пользователь, если да - даёт ему кики с jwt токеном на час
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		for _, user := range EXAMPLEuserList {
			if user.UserName == username && user.Password == password {
				SetCookieMiddleware(w, username, password)
				http.Redirect(w, r, "/calculator/", http.StatusSeeOther)
			}
		}

		http.Redirect(w, r, "/login/", http.StatusSeeOther)
	}
}

func SetCookieMiddleware(w http.ResponseWriter, username, password string) { //создаёт jwt токен ввышеописанной функцией и добавляет его в куки пользователю
	jwtToken, _ := generateJWTToken(username, password)
	validCookies = append(validCookies, jwtToken)

	// Создаем cookie для jwt_token
	jwtCookie := &http.Cookie{
		Name:   "jwt_token",
		Value:  jwtToken,
		Path:   "/",
		Domain: "localhost",
	}
	http.SetCookie(w, jwtCookie)

}

func CheckCookieMiddleware(next http.HandlerFunc, validCookies *[]string) http.HandlerFunc { // middleware, которое проверяет, есть ли у пользователя jwt, проверяет его на правильность и кладёт структуру с данными о юзере в контекст
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt_token")
		if err != nil || !slices.Contains(*validCookies, cookie.Value) {
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}
		username, password, err := extractDataFromCookie(cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}
		userData := User{}
		for _, user := range EXAMPLEuserList {
			if user.UserName == username && user.Password == password {
				userData = user
				break
			}
		}

		ctx := context.WithValue(r.Context(), "user", userData)
		next(w, r.WithContext(ctx))
	}
}

///////////////////////////////////////////
//CALCULATOR
///////////////////////////////////////////

func ReceiveResult(w http.ResponseWriter, r *http.Request) { //получение результата от агента
	result := r.URL.Query().Get("Result")
	id := r.URL.Query().Get("Id")
	port := r.URL.Query().Get("AgentPort")
	intid, _ := strconv.Atoi(id)
	fmt.Println(result, intid)

	for i := 0; i < len(EXAMPLEexpressionList); i++ {
		if EXAMPLEexpressionList[i].ExpressionID == intid {
			if EXAMPLEexpressionList[i].Status == "solving" {
				EXAMPLEexpressionList[i].ExpressionResult = result
				EXAMPLEexpressionList[i].Status = "solved"
				break
			}

		}

	}

	for i, agent := range EXAMPLEagentList {
		if agent.Port == port {
			EXAMPLEagentList[i].Status = "online"
			break
		}

	}
}

func AddExpression(w http.ResponseWriter, r *http.Request) { //добавление введённого юзером выражения, выражения могут повторяться, но только у разных юзеров
	user := r.Context().Value("user").(User)
	txt := r.FormValue("item")
	needtoadd := true
	needtoaddsameforanotheruser := false
	thisexpression := Expression{}
	username := user.UserName
	//этот фор может быть сомнителен
	for i := range EXAMPLEexpressionList {
		if EXAMPLEexpressionList[i].ExpressionText == txt {
			if EXAMPLEexpressionList[i].UserName == username {
				needtoadd = false
			} else {
				needtoaddsameforanotheruser = true
				thisexpression = EXAMPLEexpressionList[i]
			}
			break
		}
	}
	if needtoadd {
		if needtoaddsameforanotheruser {
			EXAMPLEexpressionList = append(EXAMPLEexpressionList, Expression{ExpressionText: thisexpression.ExpressionText, ExpressionID: len(EXAMPLEexpressionList), ExpressionResult: thisexpression.ExpressionResult, Status: thisexpression.Status, UserName: username})
		} else if isValidExpression(txt) {
			EXAMPLEexpressionList = append(EXAMPLEexpressionList, Expression{ExpressionText: txt, ExpressionID: len(EXAMPLEexpressionList), ExpressionResult: "0", Status: "unsolved", UserName: username})
		} else {
			EXAMPLEexpressionList = append(EXAMPLEexpressionList, Expression{ExpressionText: txt, ExpressionID: len(EXAMPLEexpressionList), ExpressionResult: "0", Status: "invalid", UserName: username})
		}
	}
	fmt.Println(EXAMPLEexpressionList)
	http.Redirect(w, r, "/calculator/", http.StatusSeeOther)
}

func CalculatorPage(w http.ResponseWriter, r *http.Request) { // отрисовка страницы калькулятор, в темплейт передаётся список выражений и пользователь, под чьим логином произведён вход
	tmpl := template.Must(template.ParseFiles("html/calculator.html"))
	user := r.Context().Value("user").(User)
	data := TemplateExpressionsData{
		List:     EXAMPLEexpressionList,
		Username: user.UserName,
	}
	tmpl.Execute(w, data)
}

func ChangeTimings(w http.ResponseWriter, r *http.Request) { //меняет тайминги у юзера
	user := r.Context().Value("user").(User)
	username := user.UserName
	plus, err1 := strconv.Atoi(r.FormValue("plu"))
	minus, err2 := strconv.Atoi(r.FormValue("min"))
	multiply, err3 := strconv.Atoi(r.FormValue("mul"))
	divide, err4 := strconv.Atoi(r.FormValue("div"))
	toshow, err5 := strconv.Atoi(r.FormValue("whb"))
	for i, user := range EXAMPLEuserList {
		if user.UserName == username {
			if err1 == nil {
				EXAMPLEuserList[i].PlusTiming = plus
			}
			if err2 == nil {
				EXAMPLEuserList[i].MinusTiming = minus
			}
			if err3 == nil {
				EXAMPLEuserList[i].MultiplyTiming = multiply
			}
			if err4 == nil {
				EXAMPLEuserList[i].DivideTiming = divide
			}
			if err5 == nil {
				EXAMPLEuserList[i].ToShowTiming = toshow
			}
			break
		}
	}

	http.Redirect(w, r, "/timings/", http.StatusSeeOther)
}

func TimingsPage(w http.ResponseWriter, r *http.Request) { // /timings/ отрисовка страницы с таймингами, в темплейт передаётся список юзеров и пользователь, под чьим логином произведён вход
	tmpl := template.Must(template.ParseFiles("html/timings.html"))
	tmpl.Execute(w, EXAMPLEuserList)
	user := r.Context().Value("user").(User)
	data := TemplateUserData{
		List:     EXAMPLEuserList,
		Username: user.UserName,
	}
	tmpl.Execute(w, data)
	//делается запрос в дб, он требует пользователей, у которых username == cookie.username, его тайминги
}

func AddAgent(w http.ResponseWriter, r *http.Request) { //добавление нового агента пользователем
	port := r.FormValue("agentport")
	doneedtoadd := true
	_, err := strconv.Atoi(port)
	for _, agent := range EXAMPLEagentList {
		if agent.Port == port {
			doneedtoadd = false
		}
	}
	if err != nil || !doneedtoadd {
		fmt.Println(err)
		http.Redirect(w, r, "/agents/", http.StatusSeeOther)
	} else {
		addr := fmt.Sprintf("http://localhost:%s/connect/?HostPort=%s", port, OrchestraPort)
		_, _ = http.Get(addr)
		EXAMPLEagentList = append(EXAMPLEagentList, Agent{Port: port, Status: "notresponding", NotRespondedFor: 0, AgentID: len(EXAMPLEagentList)})
		http.Redirect(w, r, "/agents/", http.StatusSeeOther)
	}
	//добавляется агент в дб(юзер вводит порт)
}

func AgentsPage(w http.ResponseWriter, r *http.Request) { // /agents/ отрисовка страницы с агентами, в темплейт передаётся список агентов и пользователь, под чьим логином произведён вход
	tmpl := template.Must(template.ParseFiles("html/agents.html"))
	tmpl.Execute(w, EXAMPLEagentList)
	user := r.Context().Value("user").(User)
	data := TemplateAgentData{
		List:     EXAMPLEagentList,
		Username: user.UserName,
		ShowFor:  user.ToShowTiming,
	}
	tmpl.Execute(w, data)
}

func heartbeat() {
	//всем подключенным агентам отправляется хартбит через цикл фор, те, кто не принял - not responding
	for {
		if len(EXAMPLEagentList) != 0 {
			for i, agent := range EXAMPLEagentList {
				if EXAMPLEagentList[i].NotRespondedFor >= 1 {
					EXAMPLEagentList[i].Status = "notresponding"
				}
				if EXAMPLEagentList[i].NotRespondedFor >= 60 {
					EXAMPLEagentList[i].Status = "dead"
				}
				if EXAMPLEagentList[i].Status != "dead" {
					heartbeataddr := fmt.Sprintf("http://localhost:%s/heartbeat/?HostPort=%s", agent.Port, OrchestraPort)
					_, err := http.Get(heartbeataddr)
					if err != nil {
						EXAMPLEagentList[i].NotRespondedFor++
						continue
					} else {
						if EXAMPLEagentList[i].Status != "busy" {
							EXAMPLEagentList[i].NotRespondedFor = 0
							EXAMPLEagentList[i].Status = "online"
						}
					}
				}
			}
			time.Sleep(time.Second)
		}
	}

}

func solver() { //пробегается по агентам и выражениям, если есть свободные и нерешённые - отправляет агентам выражения
	for {
		time.Sleep(time.Second)
		if len(EXAMPLEexpressionList) != 0 && len(EXAMPLEagentList) != 0 {
			for i := 0; i < len(EXAMPLEexpressionList); i++ {
				if EXAMPLEexpressionList[i].Status == "unsolved" {
					for j := range EXAMPLEagentList {
						if EXAMPLEagentList[j].Status == "online" && EXAMPLEexpressionList[i].Status == "unsolved" {
							textwithreplacements := EXAMPLEexpressionList[i].ExpressionText
							textwithreplacements = strings.ReplaceAll(textwithreplacements, "+", "%2B")
							textwithreplacements = strings.ReplaceAll(textwithreplacements, "/", "%2F")
							stringid := strconv.Itoa(EXAMPLEexpressionList[i].ExpressionID)
							plus, minus, mul, div, _ := getTimingsByExpression(EXAMPLEexpressionList[i])
							addr := fmt.Sprintf("http://localhost:%s/solve/?Expression=%s&Id=%s&ExecutionTimings=%s!%s!%s!%s", EXAMPLEagentList[j].Port, textwithreplacements, stringid, plus, minus, mul, div)
							fmt.Println(addr)
							_, err := http.Get(addr)
							if err != nil {
								fmt.Println(err)
							} else {
								EXAMPLEexpressionList[i].Status = "solving"
								EXAMPLEagentList[j].Status = "busy"
							}

						}
					}
				}
			}
		}
	}
}

func main() {
	OrchestraPort = os.Args[1] // через os.args задаётся порт, на котором будет работать оркестратор
	fmt.Println(OrchestraPort)
	if OrchestraPort == "" {
		log.Fatal("PORT not set")
	}
	go heartbeat()
	go solver()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login/", http.StatusSeeOther)
	})
	http.HandleFunc("/registration/", RegistrationHandler)
	http.HandleFunc("/login/", LoginHandler)

	http.HandleFunc("/adduser/", RegisterUser)
	http.HandleFunc("/submit/", LoginUser)

	http.HandleFunc("/receiveresult/", ReceiveResult)
	http.HandleFunc("/add/", CheckCookieMiddleware(AddExpression, &validCookies))
	http.HandleFunc("/changetimings/", CheckCookieMiddleware(ChangeTimings, &validCookies))
	http.HandleFunc("/addagent/", CheckCookieMiddleware(AddAgent, &validCookies))

	http.HandleFunc("/agents/", CheckCookieMiddleware(AgentsPage, &validCookies))
	http.HandleFunc("/calculator/", CheckCookieMiddleware(CalculatorPage, &validCookies))
	http.HandleFunc("/timings/", CheckCookieMiddleware(TimingsPage, &validCookies))
	http.ListenAndServe(":8080", nil)
}
