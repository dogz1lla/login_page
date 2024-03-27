/*
TODO
- [x] figure out how to redirect to home-page using htmx headers
      (or cookies? see https://shorturl.at/vHIM3)
- [x] add sign up into the flow
- [x] replace int codes with http ones
- [ ] clean up the file structure
- [ ] create a github repo
*/
package main

import (
    //"errors"
    "io"
    "log"
    "html/template"
    "net/http"
    "time"

    "golang.org/x/crypto/bcrypt"

    "github.com/google/uuid"
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
)


type Templates struct {
    templates *template.Template
}

func (t *Templates) Render(w io.Writer, name string, data interface{}, c echo.Context) error { 
    return t.templates.ExecuteTemplate(w, name, data)
}

func newTemplate() *Templates {
    return &Templates{
        templates: template.Must(template.ParseGlob("views/*.html")),
    }
}

type FormData struct {
    Values map[string]string
    Errors map[string]string
}

func newFormData() FormData {
    return FormData{
        Values: make(map[string]string),
        Errors: make(map[string]string),
    }
}

type LoginPage struct {
    Form FormData
}

func newLoginPage() LoginPage {
    return LoginPage{
        Form: newFormData(),
    }
}

type SignupPage struct {
    Form FormData
}

func newSignupPage() SignupPage {
    return SignupPage{
        Form: newFormData(),
    }
}

type User struct {
    Email string
    PasswordHash []byte
}

type HomePage struct {
    // TODO use User?
    Username string
}

func newUser(email, password string) User {
    pwdHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        // TODO add proper handling
        log.Println(err)
    }
    return User{Email: email, PasswordHash: pwdHash}
}

type Users []User

func (users Users) exists(email string) bool {
    for _, u := range users {
        if u.Email == email {
            return true
        }
    }
    return false
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

func (users Users) checkCredentials(email, password string) error {
    for _, u := range users {
        if u.Email == email {
            if err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)); err != nil {
                return &IncorrectPassword{}
            }
            return nil
        }
    }
    return &UserNotFound{}
}

func mockUsers() Users {
    return Users{
        newUser("jd@gmail.com", "123"),
        newUser("jc@gmail.com", "asdf"),
    }
}

type Session struct {
    Email string
    Expiry time.Time
}

var sessions = map[string]Session{}

func (s Session) isExpired() bool {
    expiration := s.Expiry
    return expiration.Before(time.Now())
}

// see https://echo.labstack.com/docs/cookies#create-a-cookie
// TODO make expiration duration a param
func writeSessionCookie(c echo.Context) (string, time.Time) {
    cookie := new(http.Cookie)
    // set cookie security params, see
    // https://htmx.org/essays/web-security-basics-with-htmx
    cookie.Secure = true
    cookie.HttpOnly = true
    cookie.SameSite = http.SameSiteLaxMode

    authToken := uuid.NewString()
    expiration := time.Now().Add(10 * time.Second)

    cookie.Name = "session_token"
    cookie.Value = authToken
    cookie.Expires = expiration
    c.SetCookie(cookie)
    return authToken, expiration
}

func main () {
    e := echo.New()
    e.Use(middleware.Logger())

    e.Renderer = newTemplate()
    //e.static("/images", "images")
    //e.static("/css", "css")

    loginPage := newLoginPage()
    signupPage := newSignupPage()
    users := mockUsers()

    e.GET("/signup", func(c echo.Context) error {
        return c.Render(http.StatusOK, "signup-page", signupPage)
    })

    e.POST("/signup", func(c echo.Context) error {
        email := c.FormValue("email")
        password := c.FormValue("password")
        passwordConfirm := c.FormValue("passwordConfirm")

        if users.exists(email) {
            // user already exists with this email
            formData := newFormData()
            formData.Values["email"] = email
            formData.Values["password"] = password
            formData.Values["passwordConfirm"] = passwordConfirm
            formData.Errors["email"] = "User with this email already exists"
            return c.Render(http.StatusUnprocessableEntity, "signup-form", formData)
        } else if password != passwordConfirm {
            // password confirmation does not match the password
            formData := newFormData()
            formData.Values["email"] = email
            formData.Values["password"] = password
            formData.Values["passwordConfirm"] = passwordConfirm
            formData.Errors["password"] = "Password and confirmation do not match"
            return c.Render(http.StatusUnprocessableEntity, "signup-form", formData)
        }

        // create user and redirect to the login page
        user := newUser(email, password)
        users = append(users, user)
        c.Response().Header().Set("HX-Redirect", "/login")
        return c.NoContent(http.StatusOK)
    })

    e.GET("/login", func(c echo.Context) error {
        return c.Render(http.StatusOK, "login-page", loginPage)
    })

    e.POST("/login", func(c echo.Context) error {
        email := c.FormValue("email")
        password := c.FormValue("password")

        if err := users.checkCredentials(email, password); err != nil {
            formData := newFormData()
            formData.Values["email"] = email
            formData.Values["password"] = password
            var statusCode int
            switch err.(type) {
                case *IncorrectPassword:
                    formData.Errors["password"] = "Invalid password"
                    statusCode = http.StatusUnauthorized
                case *UserNotFound:
                    formData.Errors["email"] = "User not found, please sign up"
                    statusCode = http.StatusNotFound
                default:
                    formData.Errors["email"] = "Uncaught auth error"
                    statusCode = http.StatusInternalServerError
            }
            return c.Render(statusCode, "login-form", formData)
        }

        // login successful -> go /home
        authToken, expiry := writeSessionCookie(c)
        sessions[authToken] = Session{Email: email, Expiry: expiry}
        c.Response().Header().Set("HX-Redirect", "/home")
        return c.NoContent(http.StatusOK)
    })

    e.GET("/home", func(c echo.Context) error {
        cookie, err := c.Cookie("session_token")
        if err != nil {
            // token has expired and the client removed the cookie -> need login
            log.Printf("TEST: Cookie not found!")
            return c.Redirect(http.StatusTemporaryRedirect, "/login")
        }

        authToken := cookie.Value
        session, ok := sessions[authToken]
        if !ok {
            log.Printf("TEST: Session not found!")
        }
        if session.isExpired() {
            log.Printf("TEST: Session expired!")
        }
        homePage := HomePage{Username: session.Email}
        return c.Render(http.StatusOK, "home-page", homePage)
    })

    e.Logger.Fatal(e.Start(":42069"))
}
