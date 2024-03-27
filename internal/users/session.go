package users

import (
    "net/http"
    "time"

    "github.com/google/uuid"
    "github.com/labstack/echo/v4"
)


type Session struct {
    Email string
    Expiry time.Time
}

func (s Session) IsExpired() bool {
    expiration := s.Expiry
    return expiration.Before(time.Now())
}

// see https://echo.labstack.com/docs/cookies#create-a-cookie
// TODO make expiration duration a param
func WriteSessionCookie(c echo.Context) (string, time.Time) {
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
