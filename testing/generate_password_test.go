package testing

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGeneratePassword(t *testing.T) {
	password := "Admin123" // ganti sesuai kebutuhan

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("PASSWORD :", password)
	fmt.Println("BCRYPT   :", string(hash))
}
