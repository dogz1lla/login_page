/*
TODO
- [x] figure out how to redirect to home-page using htmx headers
      (or cookies? see https://shorturl.at/vHIM3)
- [x] add sign up into the flow
- [x] replace int codes with http ones
- [x] clean up the file structure
      NOTE following the guidelines for server projects, see
      https://go.dev/doc/modules/layout
- [ ] create a github repo
*/
package main

import (
    "log"
    "net/http"

    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"

    "github.com/dogz1lla/login_page/internal/templating"
    "github.com/dogz1lla/login_page/internal/users"
)


var activeSessions = map[string]users.Session{}

func main () {
    e := echo.New()
    e.Use(middleware.Logger())

    e.Renderer = templating.NewTemplate()
    //e.static("/images", "images")
    //e.static("/css", "css")

    loginPage := templating.NewLoginPage()
    signupPage := templating.NewSignupPage()
    allUsers := users.MockUsers()

    e.GET("/signup", func(c echo.Context) error {
        return c.Render(http.StatusOK, "signup-page", signupPage)
    })

    e.POST("/signup", func(c echo.Context) error {
        email := c.FormValue("email")
        password := c.FormValue("password")
        passwordConfirm := c.FormValue("passwordConfirm")

        if allUsers.Exists(email) {
            // user already exists with this email
            formData := templating.NewFormData()
            formData.Values["email"] = email
            formData.Values["password"] = password
            formData.Values["passwordConfirm"] = passwordConfirm
            formData.Errors["email"] = "User with this email already exists"
            return c.Render(http.StatusUnprocessableEntity, "signup-form", formData)
        } else if password != passwordConfirm {
            // password confirmation does not match the password
            formData := templating.NewFormData()
            formData.Values["email"] = email
            formData.Values["password"] = password
            formData.Values["passwordConfirm"] = passwordConfirm
            formData.Errors["password"] = "Password and confirmation do not match"
            return c.Render(http.StatusUnprocessableEntity, "signup-form", formData)
        }

        // create user and redirect to the login page
        newUser := users.NewUser(email, password)
        allUsers = append(allUsers, newUser)
        c.Response().Header().Set("HX-Redirect", "/login")
        return c.NoContent(http.StatusOK)
    })

    e.GET("/login", func(c echo.Context) error {
        return c.Render(http.StatusOK, "login-page", loginPage)
    })

    e.POST("/login", func(c echo.Context) error {
        email := c.FormValue("email")
        password := c.FormValue("password")

        if err := allUsers.CheckCredentials(email, password); err != nil {
            formData := templating.NewFormData()
            formData.Values["email"] = email
            formData.Values["password"] = password
            var statusCode int
            switch err.(type) {
                case *users.IncorrectPassword:
                    formData.Errors["password"] = "Invalid password"
                    statusCode = http.StatusUnauthorized
                case *users.UserNotFound:
                    formData.Errors["email"] = "User not found, please sign up"
                    statusCode = http.StatusNotFound
                default:
                    formData.Errors["email"] = "Uncaught auth error"
                    statusCode = http.StatusInternalServerError
            }
            return c.Render(statusCode, "login-form", formData)
        }

        // login successful -> go /home
        authToken, expiry := users.WriteSessionCookie(c)
        activeSessions[authToken] = users.Session{Email: email, Expiry: expiry}
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
        session, ok := activeSessions[authToken]
        if !ok {
            log.Printf("TEST: Session not found!")
        }
        if session.IsExpired() {
            log.Printf("TEST: Session expired!")
        }
        homePage := templating.HomePage{Username: session.Email}
        return c.Render(http.StatusOK, "home-page", homePage)
    })

    e.Logger.Fatal(e.Start(":42069"))
}
