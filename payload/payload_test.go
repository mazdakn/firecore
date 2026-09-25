package payload

import (
	"testing"
)

func TestNew(t *testing.T) {
	matcher, err := New(`GET /users/\d+`)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if matcher == nil {
		t.Fatal("New() returned nil matcher")
	}
	if got := matcher.String(); got != `GET /users/\d+` {
		t.Errorf("matcher.String() = %q; want %q", got, `GET /users/\d+`)
	}
}

func TestNewInvalidPattern(t *testing.T) {
	matcher, err := New(`[`)
	if err == nil {
		t.Fatal("New(`[`) expected error, got nil")
	}
	if matcher != nil {
		t.Errorf("New(`[`) expected nil matcher, got %v", matcher)
	}
}

func TestMatch(t *testing.T) {
	matcher, err := New(`secret=\w+`)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if !matcher.Match([]byte("GET /?secret=token")) {
		t.Error("matcher.Match() expected true for matching payload")
	}
	if matcher.Match([]byte("GET /?public=true")) {
		t.Error("matcher.Match() expected false for non-matching payload")
	}
}
