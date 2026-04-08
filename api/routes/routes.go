package routes

import (
	//	"encoding/json"
	"net/http"

	"github.com/Ceald1/orbitalC2/api/db"
	"github.com/gin-gonic/gin"
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
