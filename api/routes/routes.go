package routes

import (
	"net/http"

	"encoding/base64"
	"github.com/Ceald1/orbitalC2/api/db"
	"github.com/gin-gonic/gin"
	"strings"
)

// --------------------- User related interactions -----------

type UserLogin struct {
	Name     string `json:"name" example:"test"`
	Password string `json:"password" example:"test"`
}
type TokenResponse struct {
	Token string `json:"token" example:"eyJhbGci..."`
}

// APIUserLogin godoc
// @Summary User login for API access
// @Tags user
// @Accept json
// @Produce json
// @Param body body UserLogin true "Login credentials"
// @Success 200 {object} TokenResponse
// @Failure 403 {object} map[string]string
// @Router /api/v1/user/login [post]
func APIUserLogin(ctx *gin.Context, surrealHost string) {
	var newUser UserLogin
	err := ctx.ShouldBindBodyWithJSON(&newUser)
	if err != nil {
		ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	conn, err := db.UserLogin(surrealHost, newUser.Name, newUser.Password)
	if err != nil {
		ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, TokenResponse{Token: conn.Token})
	conn = nil
}

// CreateAgent
// @Summary Create a new C2 agent
// @Tags user
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Security BearerAuth
// @Param name path string true "Agent Name"
// @Router /api/v1/agent/create/{name} [get]
func CreateAgent(c *gin.Context, surrealHost string) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(403, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}

	// strip "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")

	name := c.Param("name")
	if name == "" {
		c.JSON(403, gin.H{"error": "no name specified"})
		return
	}
	passwd, err := db.CreateAgent(surrealHost, name, token)
	if err != nil {
		c.JSON(403, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"result": passwd})

}

// DeleteAgents
// @Summary Delete table
// @Tags user
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Security BearerAuth
// @Param name path string false "Agent Name"
// @Router /api/v1/agent/delete/{name} [get]
func DeleteAgents(c *gin.Context, surrealHost string) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(403, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}

	// strip "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	name := c.Param("name")
	if name == "" || name == "undefined" { // delete all entries
		err := db.DeleteTable(surrealHost, token)
		if err != nil {
			c.JSON(403, gin.H{"error": err.Error()})
			return
		}
	}
	err := db.DeleteEntry(surrealHost, token, name)
	if err != nil {
		c.JSON(403, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"result": "ok"})
}

//type AgentBeacon struct { // linked to Agent record (CAN be modified)
//	ID *models.RecordID `json:"id,omitempty"`
//
//	Name          string                 `json:"name"`
//	OS            string                 `json:"os"`
//	CommandResult string                 `json:"cmd_result,omitempty"`
//	LastChecked   *models.CustomDateTime `json:"checked"`
//}

type AgentParsed struct {
	ID            string `json:"id,omitempty"`
	Name          string `json:"name"`
	OS            string `json:"os"`
	CommandResult string `json:"cmd_result,omitempty"`
	LastChecked   string `json:"checked"`
}

// ListAgents
// @Summary list agents
// @Tags user
// @Accept json
// @Produce json
// @Success 200 {object} map[string]AgentParsed
// @Failure 403 {object} map[string]string
// @Security BearerAuth
// @Router /api/v1/agent/list [get]
func ListAgents(c *gin.Context, surrealHost string) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(403, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}

	// strip "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	agents, err := db.ListAgents(surrealHost, token)
	if err != nil {
		c.JSON(403, gin.H{"error": err.Error()})
		return
	}
	agentsParsed := make([]AgentParsed, 0)
	for _, agent := range agents {
		agents_p := AgentParsed{
			ID:            agent.ID.String(),
			Name:          agent.Name,
			OS:            agent.OS,
			CommandResult: agent.CommandResult,
			LastChecked:   agent.LastChecked.String(),
		}
		agentsParsed = append(agentsParsed, agents_p)
	}
	c.JSON(200, gin.H{"result": agentsParsed})
}

// ListInactiveAgents
// @Summary list inactive agents
// @Tags user
// @Accept json
// @Produce json
// @Success 200 {object} map[string]AgentParsed
// @Failure 403 {object} map[string]string
// @Security BearerAuth
// @Router /api/v1/agent/list/inactive [get]
func ListInactiveAgents(c *gin.Context, surrealHost string) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(403, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}

	// strip "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	agents, err := db.ListInactive(surrealHost, token)
	if err != nil {
		c.JSON(403, gin.H{"error": err.Error()})
		return
	}
	agentsParsed := make([]AgentParsed, 0)
	for _, agent := range agents {
		agents_p := AgentParsed{
			ID:            agent.ID.String(),
			Name:          agent.Name,
			OS:            "NULL",
			CommandResult: "",
			LastChecked:   "NEVER CHECKED IN",
		}
		agentsParsed = append(agentsParsed, agents_p)
	}
	c.JSON(200, gin.H{"result": agentsParsed})
}

// --------------------- notes
type Note struct {
	Name    string `json:"name"`
	Content string `json:"content,omitempty"`
}

// ListNotes
// @Summary List notes on an agent
// @Tags agent notes
// @Accept json
// @Produce json
// @Param name path string true "Agent Name"
// @Success 200 {object} map[string][]string
// @Failure 403 {object} map[string]string
// @Security BearerAuth
// @Router /api/v1/notes/{name} [get]
func ListNotes(c *gin.Context, surrealHost string) {

	name := c.Param("name")
	if name == "" {
		c.JSON(403, gin.H{"error": "no agent specified"})
		return
	}
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(403, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}
	// strip "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	NotesDB, err := db.GetNotes(surrealHost, token, name)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error in db query": err.Error()})
		return
	}
	var Notes []string
	for _, noteDB := range NotesDB {
		//note := Note{
		//	Name: noteDB,
		//}
		Notes = append(Notes, noteDB)
	}
	c.JSON(200, gin.H{"result": Notes})
}

// GetNote
// @Summary get note from agent name and note name, returns base64
// @Tags agent notes
// @Accept json
// @Produce json
// @Param name path string true "Agent Name"
// @Param noteName path string true "Note Name"
// @Success 200 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Security BearerAuth
// @Router /api/v1/notes/{name}/{noteName} [get]
func GetNote(c *gin.Context, surrealHost string) {

	name := c.Param("name")
	if name == "" {
		c.JSON(403, gin.H{"error": "no agent specified"})
		return
	}
	noteName := c.Param("noteName")
	if noteName == "" {
		c.JSON(403, gin.H{"error": "no noteName specified"})
		return
	}
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(403, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}
	// strip "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	NotesDB, err := db.GetNote(surrealHost, token, name, noteName)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"result": NotesDB})
}

// CreateNote
// @Summary create note from note name and agent name.
// @Tags agent notes
// @Accept json
// @Produce json
// @Param name path string true "Agent Name"
// @Param noteName path string true "Note Name"
// @Success 200 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Security BearerAuth
// @Router /api/v1/notes/create/{name}/{noteName} [get]
func NewNote(c *gin.Context, surrealHost string) {

	name := c.Param("name")
	if name == "" {
		c.JSON(403, gin.H{"error": "no agent specified"})
		return
	}
	noteName := c.Param("noteName")
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(403, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}
	// strip "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	err := db.CreateNote(surrealHost, token, name, noteName)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"result": "ok"})

}

type NoteContent struct {
	Content string `json:"content"`
}

// UpdateNote
// @Summary update note from note name and agent name.
// @Tags agent notes
// @Accept json
// @Produce json
// @Param name path string true "Agent Name"
// @Param noteName path string true "Note Name"
// @Param body body NoteContent true "note content"
// @Success 200 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Security BearerAuth
// @Router /api/v1/notes/update/{name}/{noteName} [post]
func UpdateNote(c *gin.Context, surrealHost string) {
	var newNoteContent NoteContent
	err := c.ShouldBindBodyWithJSON(&newNoteContent)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	name := c.Param("name")
	if name == "" {
		c.JSON(403, gin.H{"error": "no agent specified"})
		return
	}
	noteName := c.Param("noteName")
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(403, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}
	_, err = base64.RawStdEncoding.DecodeString(newNoteContent.Content)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	// strip "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	err = db.UpdateNote(surrealHost, token, name, noteName, newNoteContent.Content)
	// err := db.CreateNote(surrealHost, token, name, noteName)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"result": "ok"})

}

// ------------------- agent side crap

type AgentCheckinData struct {
	OS         string `json:"os"`
	CMD_Result string `json:"cmd_result,omitempty"`
}

// AgentCheckin
// @Summary Agent checkin
// @Tags agent
// @Accept json
// @Produce json
// @Param body body AgentCheckinData true "Login credentials"
// @Success 200 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Security BearerAuth
// @Router /api/v1/agent/agent/login [post]
func AgentCheckin(c *gin.Context, surrealHost string) {
	var newUser AgentCheckinData
	err := c.ShouldBindBodyWithJSON(&newUser)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(403, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}

	// strip "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	if newUser.CMD_Result != "" {
		_, err = base64.RawStdEncoding.DecodeString(newUser.CMD_Result)
		if err != nil {
			c.JSON(403, gin.H{"error": err.Error()})
			return
		}
	}
	err = db.CheckIn(surrealHost, token, newUser.OS, newUser.CMD_Result)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"result": "ok"})
}
