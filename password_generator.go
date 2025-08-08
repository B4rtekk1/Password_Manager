package main

import (
	"crypto/rand"
)

func generatePassword(lenght uint8) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"

	if lenght < 8 {
		lenght = 8
	}
	bytes := make([]byte, lenght)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}

	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, c := range string(bytes) {
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	if !hasLower || !hasUpper || !hasDigit || !hasSpecial {
		for i := 0; i < int(lenght); i++ {
			if !hasLower {
				bytes[i] = charset[randInt(0, 26)]
				hasLower = true
			}
			if !hasUpper {
				bytes[i] = charset[randInt(26, 52)]
				hasUpper = true
			}
			if !hasDigit {
				bytes[i] = charset[randInt(52, 62)]
				hasDigit = true
			}
			if !hasSpecial {
				bytes[i] = charset[randInt(62, len(charset))]
				hasSpecial = true
			}
		}
	}
	return string(bytes), nil
}

func randInt(min, max int) byte {
	b := make([]byte, 1)
	rand.Read(b)
	return byte(min + int(b[0])%(max-min))
}
