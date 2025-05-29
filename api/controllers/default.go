package controllers

import (
	"context"
	"crypto/sha256"

	// "encoding/hex"
	"encoding/hex"
	"encoding/json"

	beego "github.com/beego/beego/v2/server/web"
	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()
var rdb = redis.NewClient(&redis.Options{
        Addr:     "localhost:6379",
        Password: "", // no password set
        DB:       0,  // use default DB
})

type MainController struct {
	beego.Controller
}

type APIController struct {
	beego.Controller
}
type Message struct{
	Message interface{} `json:"message"`
}

type AgentController struct {
	beego.Controller
}

// @Summary Hello World
// @Description Hello World
// @Tags hello
// @Produce json
// @Success 200 {object} map[string]string
// @Router /
func (c *MainController) Get() {
	in := []byte(`{"message":"hello world!"}`)
	var msg Message
	json.Unmarshal(in, &msg)
	c.Data["json"] = msg
	c.ServeJSON()
}

// Agent Endpoints
// register agent
func (c *AgentController) Register() {
	var agentID = c.Ctx.Input.Param(":id")
	valid := AuthAgent(agentID)
	if !valid {

		c.Data["json"] = map[string]int{"message": 404}
		c.ServeJSON()
		return
	}
	c.Data["json"] = map[string]int{"message": 200}
	c.ServeJSON()
}

// Database Endpoints
// clear database agents
func (c *APIController) ClearAll() {
	var msg Message
	var token = c.Ctx.Input.Header("Authorization")
	err := Verify_JWT(token)
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	err = ClearDB()
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	
	c.Data["json"] = map[string]int{"message": 200}
	c.ServeJSON()
}

func ClearDB() (error){
	var cursor uint64

    for {
        keys, nextCursor, err := rdb.Scan(ctx, cursor, "agent:*", 1000).Result()
        if err != nil {
            return err
        }

        if len(keys) > 0 {
            // Delete the keys in bulk
            if err := rdb.Del(ctx, keys...).Err(); err != nil {
                return err
            }
        }

        cursor = nextCursor
        if cursor == 0 {
            break
        }
    }

    return nil
}



// list agents
func (c *APIController) Agents() {
	var msg Message
	var token = c.Ctx.Input.Header("Authorization")
	err := Verify_JWT(token)
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	agents, err := ScanAgents()
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	err = json.Unmarshal(agents, &msg)
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	c.Data["json"] = msg
	c.ServeJSON()

}

// delete agent
func (c *APIController) Del_Agent() {

}




// run command 
func (c *APIController) RunCommand() {

}

type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// log in user
func (c *APIController) Login() {
	var userInput LoginInput
	

	if err := c.Ctx.BindJSON(&userInput); err != nil {
		c.Ctx.WriteString(err.Error())
		return
	}
	
	var msg Message
	username := userInput.Username
	auth := AuthUser(username, userInput.Password)
	if auth {
		token, err := TokenGen(username)
		if err != nil {
			
			json.Unmarshal([]byte(`{"message":` +`"` + err.Error() + `"}`), &msg)
			c.Data["json"] = msg
			c.ServeJSON()
			return
		}
		json.Unmarshal([]byte(`{"message":` + `"` + token+ `"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	// json.Unmarshal([]byte(`{"message":"invalid login"}`), &msg)
	c.Data["json"] = map[string]int{"message": 403}
	c.ServeJSON()

}

func hashPasswordSHA256(password string) string {
    hash := sha256.Sum256([]byte(password))
    return hex.EncodeToString(hash[:])
}

func AuthUser(username, password string) bool {
    storedHash, err := rdb.Get(ctx, "user:"+username).Result()
    if err == redis.Nil {
        // User does not exist
        return false
    } else if err != nil {
        // Redis error
        // Optionally log err here
        return false
    }
    return storedHash == hashPasswordSHA256(password)
}

func AuthAgent(agent_id string) bool {
	storedHash, err := rdb.Get(ctx, "agent:"+agent_id).Result()
	if err == redis.Nil {
        // User does not exist
        return false
    } else if err != nil {
        // Redis error
        // Optionally log err here
        return false
    }
	return storedHash == hashPasswordSHA256(agent_id)
}

func ScanAgents() ([]byte, error) {
	var cursor uint64
    var keys []string
	for {
        newKeys, nextCursor, err := rdb.Scan(ctx, cursor, "agent:*", 1000).Result()
        if err != nil {
            return nil, err
        }

        keys = append(keys, newKeys...)
        cursor = nextCursor

        if cursor == 0 {
            break
        }
    }

    return json.Marshal(keys)
}