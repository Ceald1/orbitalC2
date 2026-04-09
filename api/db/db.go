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
	//Symbols = "~!@#$%^&*()_+`-={}|[]\\:\"<>?,./"
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

	if err = Sdb.Use(ctx, `Agents`, `Agents`); err != nil {
		return
	}

	scope := `
DEFINE ACCESS OVERWRITE agent_scope ON DATABASE TYPE RECORD
  SIGNUP {
    -- 1. IF $auth.id HAS A VALUE, THEY ARE LOGGED IN AS AN AGENT
    IF ($auth.id != NONE) {
      THROW "Security Error: Existing agents cannot create new agents."
    };

    -- 2. Prevent duplicate names
    IF (SELECT id FROM agent WHERE name = $user) {
      THROW "agent already exists"
    };

    -- 3. Only guests or system admins can reach this
    CREATE agent SET
      name = $user,
      password = crypto::argon2::generate($pass)
  }
  SIGNIN {
    SELECT * FROM agent
    WHERE name = $user
    AND crypto::argon2::compare(password, $pass)
    LIMIT 1
  }
  DURATION FOR SESSION 1d;
	`

	tablePerms := `
DEFINE TABLE OVERWRITE agent SCHEMAFULL
  PERMISSIONS
    FOR select WHERE id = $auth.id,
    FOR create NONE,
    FOR update WHERE id = $auth.id,
    FOR delete NONE;
`
	fields := `
DEFINE FIELD name ON TABLE agent TYPE string;
DEFINE FIELD password ON TABLE agent TYPE string;
DEFINE FIELD command ON TABLE agent TYPE option<string>;
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
	if err != nil {
		if strings.Contains(err.Error(), "exists") {
			err = nil
		} else {
			return
		}
	}

	_, err = surrealdb.Query[any](ctx, Sdb, fields, map[string]any{})
	if err != nil {
		if strings.Contains(err.Error(), "exists") {
			err = nil
		} else {
			return
		}
	}

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
	const charset = LowerLetters + UpperLetters + Digits // + Symbols
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

// add and create a record user for the new user into the Agents namespace and database, returns the token
func CreateAgent(surrealHost, agentName, intoken string) (token string, err error) {
	// fresh unauthenticated connection for signup
	sdb, err := surrealdb.FromEndpointURLString(ctx, surrealHost)
	if err != nil {
		return
	}
	passwd := RandomSecret()
	if passwd == "" {
		return passwd, fmt.Errorf("Cannot create password")
	}

	err = sdb.Authenticate(ctx, intoken)
	if err != nil {
		return
	}
	err = TokenCheck(sdb)
	if err != nil {
		return

	}
	token, err = sdb.SignUp(ctx, &surrealdb.Auth{
		Namespace: "Agents",
		Database:  "Agents",
		Access:    "agent_scope",
		Username:  agentName,
		Password:  passwd,
	})

	return
}

func TokenCheck(sdb *surrealdb.DB) (err error) {
	err = sdb.Use(ctx, `Agents`, `Agents`)
	if err != nil {
		return err
	}
	query := `RETURN $access == "agent_scope" && $access != NONE;`
	res, err := surrealdb.Query[bool](ctx, sdb, query, map[string]any{})
	if err != nil {
		return err
	}
	for _, qr := range *res {
		if qr.Result == true {
			return fmt.Errorf("unauthorized for creating new agents")
		}
	}
	return nil
}

func DeleteEntry(surrealHost, token, agentName string) (err error) {
	sdb, err := surrealdb.FromEndpointURLString(ctx, surrealHost)
	if err != nil {
		return
	}
	err = sdb.Use(ctx, `Agents`, `Agents`)
	if err != nil {
		return
	}
	err = sdb.Authenticate(ctx, token)
	if err != nil {
		return
	}
	err = TokenCheck(sdb)
	if err != nil {
		return
	}
	query := fmt.Sprintf(`DELETE agent WHERE name = "%s"`, agentName)
	_, err = surrealdb.Query[any](ctx, sdb, query, map[string]any{})
	return
}

func DeleteTable(surrealHost, token string) (err error) {
	sdb, err := surrealdb.FromEndpointURLString(ctx, surrealHost)
	if err != nil {
		return
	}
	err = sdb.Use(ctx, `Agents`, `Agents`)
	if err != nil {
		return
	}
	err = sdb.Authenticate(ctx, token)
	if err != nil {
		return
	}
	err = TokenCheck(sdb)
	if err != nil {
		return
	}
	query := `REMOVE TABLE agent`
	_, err = surrealdb.Query[any](ctx, sdb, query, map[string]any{})
	if err != nil {
		return
	}
	_, err = BootStrapDB(surrealHost)
	return
}
