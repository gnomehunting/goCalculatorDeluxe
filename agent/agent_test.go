package main

import (
	"testing"
)

func TestEval(t *testing.T) {
	result := eval("2+3")
	if result != 5 {
		t.Errorf("Expected result to be 5, but got %f", result)
	}
}

func TestEvalWithDelay(t *testing.T) {
	expression := "2+3"
	numbers := []string{"1", "2", "3", "4"}

	result := evalWithDelay(expression, numbers)

	expected := 5.000
	if result != expected {
		t.Error(expected, result)
	}
}
