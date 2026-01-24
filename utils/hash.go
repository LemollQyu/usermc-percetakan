package utils

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", nil
	}

	return string(hashed), nil
}

func CheckPasswordHash(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(password), []byte(hash))
	if err != nil {
		return false, err
	}

	return true, nil
}

// Mengecek apakah password baru sama dengan password lama (hash)
func IsSamePassword(oldHashedPassword string, newPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(oldHashedPassword), []byte(newPassword))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	return false, err
}
