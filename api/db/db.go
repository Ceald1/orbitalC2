package db

import (
	"context"
	"fmt"
	"strings"

	surrealdb "github.com/surrealdb/surrealdb.go"

	"crypto/rand"
	"math/big"
	"os"

	"github.com/surrealdb/surrealdb.go/pkg/models"
)

var (
	ctx = context.Background()
)

const (
	// LowerLetters is the list of lowercase letters.
	LowerLetters = "abcdefghijklmnopqrstuvwxyz"

	// UpperLetters is the list of uppercase letters.
	UpperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// Digits is the list of permitted digits.
	Digits = "0123456789"

	// Symbols is the list of symbols.
	Symbols = "~!@#$%^&*()_+`-={}|[]\\:\"<>?,./"
)

type SURREALCONN struct {
	Token string
	Conn  *surrealdb.DB
}

type Agent struct {
	ID       *models.RecordID `json:"id,omitempty"`
	Name     string           `json:"name"`
	Password string           `json:"password"`
	Command  string           `json:"command,omitempty"`
}

func BootStrapDB(surrealHost string) (conn *SURREALCONN, err error) {
	Sdb, err := surrealdb.FromEndpointURLString(ctx, surrealHost)
	if err != nil {
		return
	}
	authData := &surrealdb.Auth{
		Username: os.Getenv("SURREAL_ADMIN"),
		Password: os.Getenv("SURREAL_PASS"),
	}
	token, err := Sdb.SignIn(ctx, authData)
	if err != nil {
		return
	}
	err = Sdb.Authenticate(ctx, token)
	if err != nil {
		return
	}
	conn = &SURREALCONN{
		Conn:  Sdb,
		Token: token,
	}

	// define scopes
	Sdb.Use(ctx, `Agents`, `Agents`)
	scope := `
DEFINE ACCESS agent_scope ON DATABASE TYPE RECORD
  SIGNUP (
    CREATE agent SET
      name = $user,
      password = crypto::argon2::generate($pass),
      command = $command
  )
  SIGNIN (
    SELECT * FROM agent
    WHERE name = $user
      AND crypto::argon2::compare(password, $pass)
  )
  DURATION FOR SESSION 1d;
`
	tablePerms := `
DEFINE TABLE IF NOT EXISTS agent SCHEMAFULL
  PERMISSIONS
    FOR select WHERE id = $auth.id,
    FOR update NONE,
    FOR delete NONE,
    FOR create NONE;
	`
	_, err = surrealdb.Query[any](ctx, Sdb, scope, map[string]any{})
	if err != nil {
		if strings.Contains(err.Error(), "exists") {
			err = nil

		} else {
			return
		}
	}
	_, err = surrealdb.Query[any](ctx, Sdb, tablePerms, map[string]any{})

	return

}

func UserLogin(surrealHost, username, password string) (conn *SURREALCONN, err error) {
	Sdb, err := surrealdb.FromEndpointURLString(ctx, surrealHost)
	if err != nil {
		return
	}
	authData := &surrealdb.Auth{
		Username: username,
		Password: password,
	}
	token, err := Sdb.SignIn(ctx, authData)
	if err != nil {
		return
	}
	err = Sdb.Authenticate(ctx, token)
	if err != nil {
		return
	}
	conn = &SURREALCONN{
		Conn:  Sdb,
		Token: token,
	}
	return
}

func RandomSecret() string {
	const charset = LowerLetters + UpperLetters + Digits + Symbols
	length := 20
	password := make([]byte, length)
	for i := range password {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return ""
		}
		password[i] = charset[num.Int64()]
	}
	return string(password)
}

// add and create a record user for the new user into the Agents namespace and database
func CreateAgent(conn *SURREALCONN, agentName string) (passwd string, err error) {
	sdb := conn.Conn
	passwd = RandomSecret()
	if passwd == "" {
		return passwd, fmt.Errorf("Cannot create password")
	}
	err = sdb.Use(ctx, `Agents`, `Agents`)
	auth_data := &surrealdb.Auth{
		Username: agentName,
		Password: passwd,
		Access:   "agent_scope",
	}
	_, err = sdb.SignUp(ctx, &auth_data)
	return
}
