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

	// Database endpoints
	beego.Router("/db/agents", &controllers.APIController{}, "get:Agents")
	beego.Router("/db/delete", &controllers.APIController{}, "get:ClearAll")

}