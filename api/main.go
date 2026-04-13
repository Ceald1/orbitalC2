// @title           orbitalC2 api
// @version         1.0
// @description     A sample API
// @host            localhost:8080
// @BasePath        /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

package main

import (
	"github.com/Ceald1/orbitalC2/api/db"
	_ "github.com/Ceald1/orbitalC2/api/docs"
	orbitalRoutes "github.com/Ceald1/orbitalC2/api/routes"
	"github.com/charmbracelet/log"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"net/http"
	"os"
)

func main() {
	// get DB connection
	if os.Getenv("SURREAL_HOSTURL") == "" {
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file") // load .env file if not found as env var
		}
	}
	surrealHost := os.Getenv("SURREAL_HOSTURL")
	DBConn, err := db.BootStrapDB(surrealHost)
	if err != nil {
		log.Fatalf("failed to connect to database! %v", err)
	}
	if DBConn != nil { // piss off errors about not being used
		log.Info("Database initialized")
		DBConn = nil // destroy after creation
	}

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // or lock to "http://localhost:8080"
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
	}))
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.Any("/", func(ctx *gin.Context) {
		ctx.Redirect(http.StatusMovedPermanently, "/swagger/index.html")
	})

	v1 := r.Group("/api/v1")
	v1.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	noteGroup := v1.Group("/notes")
	noteGroup.GET("/:name", func(ctx *gin.Context) {
		orbitalRoutes.ListNotes(ctx, surrealHost)
	})
	noteGroup.GET("/:name/:noteName", func(ctx *gin.Context) {
		orbitalRoutes.GetNote(ctx, surrealHost)
	})

	noteGroup.GET("/create/:name/:noteName", func(ctx *gin.Context) {
		orbitalRoutes.NewNote(ctx, surrealHost)
	})
	noteGroup.POST("/update/:name/:noteName", func(ctx *gin.Context) {
		orbitalRoutes.UpdateNote(ctx, surrealHost)
	})
	noteGroup.GET("/delete/:name/:noteName", func(ctx *gin.Context) {
		orbitalRoutes.DeleteNote(ctx, surrealHost)
	})

	userGroup := v1.Group("/user")
	userGroup.POST("/login", func(ctx *gin.Context) {
		orbitalRoutes.APIUserLogin(ctx, surrealHost)
	})
	agentGroup := v1.Group("/agent")
	agentGroup.GET("/create/:name", func(ctx *gin.Context) {
		orbitalRoutes.CreateAgent(ctx, surrealHost)
	})
	agentGroup.GET("/delete/:name", func(ctx *gin.Context) {
		orbitalRoutes.DeleteAgents(ctx, surrealHost)
	})
	agentGroup.GET("/list", func(ctx *gin.Context) {
		orbitalRoutes.ListAgents(ctx, surrealHost)
	})
	agentGroup.GET("/list/inactive", func(ctx *gin.Context) {
		orbitalRoutes.ListInactiveAgents(ctx, surrealHost)
	})
	agentGroup.POST("/command/:name", func(ctx *gin.Context) {
		orbitalRoutes.CMDAgent(ctx, surrealHost)
	})
	agentAgentGroup := agentGroup.Group("/agent")
	agentAgentGroup.POST("/login", func(ctx *gin.Context) {
		orbitalRoutes.AgentCheckin(ctx, surrealHost)
	})

	log.Info("swagger UI on /swagger/index.html")
	if err := r.Run(); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}
