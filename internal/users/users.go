package users


import (
    "log"

    "golang.org/x/crypto/bcrypt"

    //"github.com/google/uuid"
    //"github.com/labstack/echo/v4"
    //"github.com/labstack/echo/v4/middleware"

    //"github.com/dogz1lla/login_page/internal/templating"
)


type User struct {
    Email string
    PasswordHash []byte
}

func NewUser(email, password string) User {
    pwdHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        // TODO add proper handling
        log.Println(err)
    }
    return User{Email: email, PasswordHash: pwdHash}
}

type Users []User

func (userList Users) Exists(email string) bool {
    for _, u := range userList {
        if u.Email == email {
            return true
        }
    }
    return false
}

func (userList Users) CheckCredentials(email, password string) error {
    for _, u := range userList {
        if u.Email == email {
            if err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)); err != nil {
                return &IncorrectPassword{}
            }
            return nil
        }
    }
    return &UserNotFound{}
}

func MockUsers() Users {
    return Users{
        NewUser("jd@gmail.com", "123"),
        NewUser("jc@gmail.com", "asdf"),
    }
}

// error for incorrect password
type IncorrectPassword struct{}

func (e *IncorrectPassword) Error() string {
    return "Password does not match"
}

// error for missing user
type UserNotFound struct{}

func (e *UserNotFound) Error() string {
    return "User not found"
}
