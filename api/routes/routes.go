package routes

import (
	"net/http"

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
	if name == "" { // delete all entries
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
// @Tags agent
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
