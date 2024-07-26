package db

import (
	"errors"

	"github.com/alphadev97.com/go-csrf/db/models"
	"github.com/alphadev97.com/go-csrf/randomstrings"
	"golang.org/x/crypto/bcrypt"
)

var users = map[string]models.User{}
var refreshToken map[string]string

func InitDB() {
	refreshToken = make(map[string]string)
}

func StoreUser(username string, password string, role string) (uuid string, err error) {
	uuid, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	u := models.User{}
	for u != users[uuid] {
		uuid, err = randomstrings.GenerateRandomString(32)
		if err != nil {
			return "", err
		}
	}

	PasswordHash, hashErr := generateBcryptHash(password)
	if hashErr != nil {
		err = hashErr
		return
	}

	users[uuid] = models.User{username, PasswordHash, role}
	return uuid, err

}

func DeleteUser(uuid string) (models.User, error) {
	delete(users, uuid)
}

func FetchUserById(uuid string) (models.User, error) {
	u := users[uuid]
	blankUser := models.User{}

	if blankUser != u {
		return u, nil
	} else {
		return u, errors.New("user not found that matches the given id")
	}
}

func FetchUserByUsername(username string) (models.User, string, error) {
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}
	return models.User{}, "", errors.New("User not found that matches the given username")
}

func StoreRefreshToken() (jti string, err error) {

}

func DeleteRefreshToken()

func CheckAndRefreshTokens()

func LogUserIn()

func generateBcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash[:]), err
}

func checkPasswordAgainstHash()
