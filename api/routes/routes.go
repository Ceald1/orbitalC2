package routes

import (
	"encoding/json"
	"github.com/Ceald1/orbitalC2/api/db"
	"github.com/gin-gonic/gin"
)

// --------------------- User related interactions -----------

type UserLogin struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

//
