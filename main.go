package main

import (
  "encoding/json"
  "fmt"
  "log"
  "net/http"
  "net/url"
  "os"
  "strings"

  "github.com/joho/godotenv"
  "github.com/julienschmidt/httprouter"
  "github.com/dgrijalva/jwt-go"
)

var listen string
var secret []byte

func main() {
  // Load .env
  err := godotenv.Load()
  if err != nil {
    log.Fatal("Error loading .env file")
  }
  listen = os.Getenv("LISTEN")
  secret = []byte(os.Getenv("SECRET"))

  // Routes
  router := httprouter.New()
  router.OPTIONS("/auth", PassThrough)
  router.GET("/auth", Auth)
  router.POST("/auth", Auth)
  router.PUT("/auth", Auth)
  router.DELETE("/auth", Auth)
  router.PATCH("/auth", Auth)

  // Start server
  log.Printf("starting server on %s", listen)
	log.Fatal(http.ListenAndServe(listen, router))
}

func PassThrough(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
  w.WriteHeader(http.StatusOK)
}

type UserClaims struct {
  UserId string `json:"userid"`
  ClientId string `json:"clientid"`
}
func Auth(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
  tokenString := ""

  // Extract token from querystrign in X-Forwarded-Uri
  uri, err := url.Parse(r.Header.Get("X-Forwarded-Uri"))
  if err != nil {
    http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
    return
  }
  queries, err := url.ParseQuery(uri.RawQuery)
  if err != nil {
    http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
    return
  }
  if len(queries["token"]) > 0 {
    tokenString = queries["token"][0]
  }

  // Extract token from Authorization header
  reqToken := r.Header.Get("Authorization")
  splitToken := strings.Split(reqToken, "Bearer ")
  if len(splitToken) > 1 {
    tokenString = splitToken[1]
  }

  // Make sure token string is not null
  if tokenString == "" {
    http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
    return
  }

  // Parse token
  token, err := jwt.Parse(tokenString, func (token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
      return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
    }
    return secret, nil
  })
  if err != nil {
    http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
    return
  }
  if !token.Valid {
    http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
    return
  }

  claims, ok := token.Claims.(jwt.MapClaims)
  if !ok {
    http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
    return
  }

  userclaims := UserClaims {
    UserId: claims["userid"].(string),
    ClientId: claims["clientid"].(string),
  }

  userclaimBytes, err := json.Marshal(&userclaims)
  if err != nil {
    http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
    return
  }

  w.Header().Set("X-User-Claim", (string)(userclaimBytes))
  w.WriteHeader(http.StatusOK)
}
