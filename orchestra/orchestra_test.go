package main

import (
	"testing"
)

func TestIsValidExpression(t *testing.T) {
	// Тест с правильным выражением
	if !isValidExpression("1+2*(3-1)") {
		t.Errorf("Expected expression to be valid")
	}

	// Тест с неправильным выражением (несовпадение скобок)
	if isValidExpression("1+2*(3-1") {
		t.Errorf("Expected expression to be invalid due to mismatched brackets")
	}

	// Тест с неправильным выражением (несовпадение знаков)
	if !isValidExpression("1+2*3-1") {
		t.Errorf("Expected expression to be invalid due to mismatched operators")
	}

	// Дополнительный тест с правильным выражением
	if !isValidExpression("4*(5-2)+3/1") {
		t.Errorf("Expected expression to be valid")
	}
}

func TestExtractDataFromCookie(t *testing.T) {
	username := "testuser"
	password := "testpassword"
	jwtCookie, _ := generateJWTToken(username, password)

	// Тест с корректным токеном
	username, password, err := extractDataFromCookie(jwtCookie)
	if err != nil || username != "testuser" || password != "testpassword" {
		t.Errorf("Expected username and password to match the token claims")
	}

	// Тест с некорректным токеном
	invalidJwtCookie := "invalid_jwt_token"
	_, _, err = extractDataFromCookie(invalidJwtCookie)
	if err == nil {
		t.Errorf("Expected error for invalid token")
	}

	// Дополнительный тест с некорректным токеном
	_, _, err = extractDataFromCookie("")
	if err == nil {
		t.Errorf("Expected error for empty token")
	}
}

func TestGenerateJWTToken(t *testing.T) {
	// Тест на генерацию JWT токена
	username := "testuser"
	password := "testpassword"
	token, err := generateJWTToken(username, password)
	if err != nil || token == "" {
		t.Errorf("Expected valid JWT token to be generated")
	}

}

func TestGetTimingsByExpression(t *testing.T) {
	EXAMPLEuserList = append(EXAMPLEuserList, User{0, "username", "password", 1, 2, 3, 4, 5})

	// Тест на получение временных параметров по имени пользователя
	expr := Expression{UserName: "username"}
	plus, minus, mu, div, toshow := getTimingsByExpression(expr)

	// Проверка соответствия временных параметров пользователя
	if plus != "1" || minus != "2" || mu != "3" || div != "4" || toshow != "5" {
		t.Errorf("Expected timings to match user's data")
	}

	// Дополнительный тест на получение временных параметров по другому имени пользователя
	expr = Expression{UserName: "otheruser"}
	plus, minus, mu, div, toshow = getTimingsByExpression(expr)

	// Проверка соответствия временных параметров другого пользователя
	if plus != "" || minus != "" || mu != "" || div != "" || toshow != "" {
		t.Errorf("Expected empty timings for non-existing user")
	}
}
