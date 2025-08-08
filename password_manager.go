package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const file_path = "passwords.json"
const iterations = 100_000

type Password struct {
	Site     string `json:"site"`
	Username string `json:"username"`
	Pass     string `json:"password"`
}

type EncryptedData struct {
	Salt  string `json:"salt"`
	Nonce string `json:"nonce"`
	Data  string `json:"data"`
}

var passwords []Password

func main() {
	reader := bufio.NewReader(os.Stdin)
	var master_password []byte

	if _, err := os.Stat(file_path); os.IsNotExist(err) {
		master_password = getNewMasterPassword()
		passwords = []Password{}
		save_file(master_password)
	} else {
		master_password = getMasterPassword()
		load_data(master_password)
	}
	for {
		fmt.Println("\n1. Show passwords\n2. Add password\n3. Exit")
		fmt.Print("Choose option: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			show_data()
		case "2":
			addPassword(reader, master_password)
		case "3":
			os.Exit(0)
		default:
			fmt.Println("Incorrect option")
		}
	}
}

func encrypt_password(passwords []Password, masterPassword []byte) (*EncryptedData, error) {
	plaintext, err := json.Marshal(passwords)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key := deriveKey(masterPassword, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedData{
		Salt:  base64.RawStdEncoding.EncodeToString(salt),
		Nonce: base64.RawStdEncoding.EncodeToString(nonce),
		Data:  base64.RawStdEncoding.EncodeToString(ciphertext),
	}, nil
}

func decryptPassword(enc *EncryptedData, masterPassword []byte) ([]Password, error) {
	salt, _ := base64.RawStdEncoding.DecodeString(enc.Salt)
	nonce, _ := base64.RawStdEncoding.DecodeString(enc.Nonce)
	data, _ := base64.RawStdEncoding.DecodeString(enc.Data)

	key := deriveKey(masterPassword, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	var passwords []Password
	err = json.Unmarshal(plaintext, &passwords)
	if err != nil {
		return nil, err
	}
	return passwords, nil
}

func getMasterPassword() []byte {
	fmt.Print("Enter master password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Println("Error reading password:", err)
		os.Exit(1)
	}
	return bytePassword
}

func getNewMasterPassword() []byte {
	for {
		fmt.Print("Set new master password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Println("Error while reading password", err)
			continue
		}

		fmt.Print("Confirm master password: ")
		bytePasswordConfirm, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Println("Error while reading password conformation")
			continue
		}

		if string(bytePassword) != string(bytePasswordConfirm) {
			fmt.Println("Passwords do not match. Try again")
			continue
		}
		return bytePassword
	}
}

func deriveKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterations, 32, sha256.New)
}

func show_data() {
	if len(passwords) == 0 {
		fmt.Println("No passwords")
		return
	}
	fmt.Println("\nPasswords:")
	for _, p := range passwords {
		fmt.Printf("Site: %s | Username: %s | Password: %s\n",
			p.Site, p.Username, p.Pass)
	}

}

func save_file(masterPassword []byte) {
	encData, err := encrypt_password(passwords, masterPassword)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}

	file, err := os.Create(file_path)
	if err != nil {
		fmt.Println("Error while creating file...", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(encData)
	if err != nil {
		fmt.Println("Error while encoding encrypted data:", err)
		return
	}

	fmt.Println("File saved successfully")
}

func load_data(masterPassword []byte) {
	file, err := os.Open(file_path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("File does not exist, creating new one...")
			passwords = []Password{}
			save_file(masterPassword)
			return
		} else {
			fmt.Println("Error while opening file", err)
			return
		}
	}
	defer file.Close()

	var encData EncryptedData
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&encData)
	if err != nil {
		fmt.Println("Error decoding encrypted data:", err)
		return
	}

	pwds, err := decryptPassword(&encData, masterPassword)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	passwords = pwds
	fmt.Println("Passwords loaded successfully")
}

func addPassword(reader *bufio.Reader, masterPassword []byte) {
	fmt.Print("Site name: ")
	site, _ := reader.ReadString('\n')
	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')
	fmt.Print("Password: ")
	password, _ := reader.ReadString('\n')

	passwords = append(passwords, Password{
		Site:     strings.TrimSpace(site),
		Username: strings.TrimSpace(username),
		Pass:     strings.TrimSpace(password),
	})

	save_file(masterPassword)
}
