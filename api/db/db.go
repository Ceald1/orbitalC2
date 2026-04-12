package db

import (
	"context"
	"fmt"
	"strings"
	"time"

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

type Note struct {
	ID          *models.RecordID `json:"id,omitempty"`
	Name        string           `json:"name"`
	Content     string           `json:"content,omitempty"`
	LinkedAgent string           `json:"linkedAgent"`
}

type Agent struct {
	ID       *models.RecordID `json:"id,omitempty"`
	Name     string           `json:"name"`
	Password string           `json:"password"`
	Command  string           `json:"command,omitempty"`
}

type AgentBeacon struct { // linked to Agent record (CAN be modified)
	ID *models.RecordID `json:"id,omitempty"`

	Name          string                 `json:"name"`
	OS            string                 `json:"os"`
	CommandResult string                 `json:"cmd_result,omitempty"`
	LastChecked   *models.CustomDateTime `json:"checked"`
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
  DURATION FOR SESSION 365d;
	`

	tablePerms := `
DEFINE TABLE OVERWRITE agent SCHEMAFULL
  PERMISSIONS
    FOR select WHERE id = $auth.id,
    FOR create NONE,
    FOR update NONE,
    FOR delete NONE;
`
	agentBeaconPerms := `
DEFINE TABLE OVERWRITE agentBeacons SCHEMAFULL
    PERMISSIONS
        FOR select WHERE record::id(id) = record::id($auth.id),
        FOR create WHERE record::id(id) = record::id($auth.id),
        FOR update WHERE record::id(id) = record::id($auth.id),
        FOR delete NONE;
	`
	agentBeaconFields := `
DEFINE FIELD name ON TABLE agentBeacons TYPE string;
DEFINE FIELD os ON TABLE agentBeacons TYPE string;
DEFINE FIELD cmd_result ON TABLE agentBeacons TYPE option<string>;
DEFINE FIELD checked ON TABLE agentBeacons TYPE datetime;
	`
	fields := `
DEFINE FIELD name ON TABLE agent TYPE string;
DEFINE FIELD password ON TABLE agent TYPE string;
DEFINE FIELD command ON TABLE agent TYPE option<string>;
`
	notes := `
DEFINE TABLE OVERWRITE notes SCHEMAFULL;
DEFINE FIELD name ON TABLE notes TYPE string;
DEFINE FIELD linkedAgent ON TABLE notes TYPE string;
DEFINE FIELD content ON TABLE notes TYPE option<string>;
	`
	_, err = surrealdb.Query[any](ctx, Sdb, notes, map[string]any{})
	if err != nil {
		if strings.Contains(err.Error(), "exists") {
			err = nil
		} else {
			return
		}
	}
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
	_, err = surrealdb.Query[any](ctx, Sdb, agentBeaconPerms, map[string]any{})

	if err != nil {
		if strings.Contains(err.Error(), "exists") {
			err = nil
		} else {
			return
		}
	}

	_, err = surrealdb.Query[any](ctx, Sdb, agentBeaconFields, map[string]any{})

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
	if err != nil {
		return
	}
	query = fmt.Sprintf(`DELETE agentBeacons WHERE name = "%s" `, agentName)
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
	query = `REMOVE TABLE agentBeacons`
	_, err = surrealdb.Query[any](ctx, sdb, query, map[string]any{})
	if err != nil {
		return
	}

	_, err = BootStrapDB(surrealHost)
	return
}

// for agent check ins and heartbeats
func CheckIn(surrealHost, token, os, cmd_result string) (err error) {
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
	queryCheck := `SELECT * FROM agentBeacons WHERE name = $auth.name`
	results, err := surrealdb.Query[[]AgentBeacon](ctx, sdb, queryCheck, map[string]any{})
	if err != nil {
		return
	}
	var agent AgentBeacon = AgentBeacon{}
	for _, qr := range *results {
		for _, r := range qr.Result {
			agent = r
		}
	}
	if agent.ID != nil {
		fmt.Println(agent.ID.String())
	}
	// First time checking in
	if agent.Name == "" {
		//		query := fmt.Sprintf(`
		//CREATE agentBeacons SET
		//		name = $auth.name,
		//		os = '%s',
		//		cmd_result = '',
		//		checked = time::now();`, os)
		//		_, err = surrealdb.Query[any](ctx, sdb, query, map[string]any{})
		//		if err != nil {
		//			return
		//		}
		//		// link record
		//		query = `
		//LET $agent = (SELECT id FROM agent WHERE id = $auth.id)[0];
		//LET $beacon = (SELECT id FROM agentBeacons WHERE name = $auth.name)[0];
		//RELATE $agent->Beacon->$beacon;`
		//		_, err = surrealdb.Query[any](ctx, sdb, query, map[string]any{})
		query := fmt.Sprintf(`
LET $agentId = $auth.id;
LET $beaconId = type::record("agentBeacons", record::id($auth.id));
CREATE $beaconId SET
    name = $auth.name,
    os = '%s',
    cmd_result = '%s',
    checked = time::now();
RELATE $agentId->Beacon->$beaconId;`, os, cmd_result)

		_, err = surrealdb.Query[any](ctx, sdb, query, map[string]any{})
		if err != nil {
			return
		}
	} else {
		t := models.CustomDateTime{Time: time.Now()}
		_, err = surrealdb.Update[AgentBeacon](ctx, sdb, *agent.ID, AgentBeacon{
			CommandResult: cmd_result,
			LastChecked:   &t,
			Name:          agent.Name,
			OS:            agent.OS,
		})
	}

	return
}

func ListAgents(surrealHost, token string) (agents []AgentBeacon, err error) {
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

	res, err := surrealdb.Select[[]AgentBeacon](ctx, sdb, models.Table("agentBeacons"))
	if err != nil {
		return
	}
	agents = *res
	return agents, nil
}

func ListInactive(surrealHost, token string) (agents []Agent, err error) {
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
	query := `SELECT * FROM agent WHERE count(->Beacon->agentBeacon) = 0;`
	res, err := surrealdb.Query[[]Agent](ctx, sdb, query, map[string]any{})
	if err != nil {
		return
	}

	for _, qr := range *res {
		agents = qr.Result
	}
	return
}

// surreal host, token, agentName, note name
func CreateNote(surrealHost, token, agentName, name string) (err error) {
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
	exists := fmt.Sprintf(`SELECT * FROM notes WHERE name = '%s' AND linkedAgent = '%s'`, name, agentName)
	res, err := surrealdb.Query[[]Note](ctx, sdb, exists, map[string]any{})
	if err != nil {
		return
	}
	for _, qr := range *res {
		if len(qr.Result) > 0 {
			return fmt.Errorf("record exists!")
		}
	}
	NewNote := Note{
		Name:        name,
		Content:     "RklMTEVSCg==", // FILLER
		LinkedAgent: agentName,
	}
	recordID := models.NewRecordID(`notes`, NewNote)
	_, err = surrealdb.Create[Note](ctx, sdb, recordID, NewNote)

	// no relate because I don't wanna
	return
}

type NoteRecord struct {
	Name string `json:"name"`
}

func GetNotes(surrealHost, token, agentName string) (notes []string, err error) {
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
	exists := fmt.Sprintf(`SELECT name FROM notes WHERE linkedAgent = '%s'`, agentName)
	res, err := surrealdb.Query[[]NoteRecord](ctx, sdb, exists, map[string]any{})
	if err != nil {
		return
	}
	for _, qr := range *res {
		for _, r := range qr.Result {
			notes = append(notes, r.Name)
		}
	}
	return
}

type NoteContent struct {
	Content string `json:"content"`
}

// / returns the base64 encoded note
func GetNote(surrealHost, token, agentName, noteName string) (note string, err error) {
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
	query := fmt.Sprintf(`SELECT content FROM notes WHERE linkedAgent = '%s' AND name = '%s'`, agentName, noteName)
	res, err := surrealdb.Query[[]NoteContent](ctx, sdb, query, map[string]any{})
	if err != nil {
		return
	}
	for _, qr := range *res {
		for _, record := range qr.Result {
			if len(record.Content) > 0 {
				note = record.Content
				return
			}
		}
		//return qr.Result.Content, nil
	}
	return
}

// content is base64 encoded to prevent issues in DB and from API
func UpdateNote(surrealHost, token, agentName, name, content string) (err error) {
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
	exists := fmt.Sprintf(`SELECT * FROM notes WHERE linkedAgent = '%s' AND name = '%s'`, agentName, name)
	res, err := surrealdb.Query[[]Note](ctx, sdb, exists, map[string]any{})
	if err != nil {
		return
	}
	var record Note
	for _, qr := range *res {
		record = qr.Result[0]
	}
	record.Content = content
	_, err = surrealdb.Update[Note](ctx, sdb, *record.ID, record)
	return
}

func DeleteNote(surrealHost, token, agentName, name string) (err error) {
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
	exists := fmt.Sprintf(`SELECT * FROM notes WHERE linkedAgent = '%s' AND name = '%s'`, agentName, name)
	res, err := surrealdb.Query[[]Note](ctx, sdb, exists, map[string]any{})
	if err != nil {
		return
	}
	var record Note
	for _, qr := range *res {
		record = qr.Result[0]
	}
	_, err = surrealdb.Delete[Note](ctx, sdb, *record.ID)
	return
}
