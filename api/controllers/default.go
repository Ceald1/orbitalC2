package controllers

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"

	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"

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
// register agent/authenticate
func (c *AgentController) Register() {
	var agentID = c.Ctx.Input.Param(":id")
	valid := AuthAgent(agentID)
	if !valid {

		c.Data["json"] = map[string]int{"message": 404}
		c.ServeJSON()
		return
	}
	token, err := TokenGen(hashPasswordSHA256(agentID))
	if err != nil {
		c.Data["json"] = map[string]string{"message": err.Error()}
		c.ServeJSON()
		return
	}
	
	c.Data["json"] = map[string]string{"message": token}
	c.ServeJSON()
}

type CMDResult struct {
	// result should be base64 encoded for less server side code.
	Result string `json:"result"`
}

func (c *AgentController) Result() {
	// get command result
	var agentID = c.Ctx.Input.Param(":id")
	valid := AuthAgent(agentID)
	var msg Message
	if !valid {

		c.Data["json"] = map[string]int{"message": 404}
		c.ServeJSON()
		return
	}
	var token = c.Ctx.Input.Header("Authorization")
	var secret = []byte(os.Getenv("secret"))
	userID, err := TokenDecode(token, secret)
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	if userID != agentID {
		json.Unmarshal([]byte(`{"message":403}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	var Result CMDResult
	if err := c.Ctx.BindJSON(&Result); err != nil {
		c.Ctx.WriteString(err.Error())
		return
	}
	// check if valid base64
	_, valid_b64 := base64.StdEncoding.DecodeString(Result.Result)
	if valid_b64 != nil {
		c.Ctx.WriteString(valid_b64.Error())
		return
	}
	data, err := rdb.HGetAll(ctx, agentID).Result()
	if err != nil {
		c.Ctx.WriteString(err.Error())
		return
	}
	data["result"] = Result.Result
	_, err = rdb.HSet(ctx, agentID, data).Result()
	if err != nil {
		c.Ctx.WriteString(err.Error())
		return
	}

	// return result
	c.Data["json"] = map[string]interface{}{"message": 200}
}



func (c *AgentController) GetCommand() {
	var agentID = c.Ctx.Input.Param(":id")
	var msg Message
	valid := AuthAgent(agentID)
	if !valid {
		c.Data["json"] = map[string]int{"message": 404}
		c.ServeJSON()
		return
	}


	var token = c.Ctx.Input.Header("Authorization")
	var secret = []byte(os.Getenv("secret"))
	userID, err := TokenDecode(token, secret)
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	if userID != agentID {
		json.Unmarshal([]byte(`{"message":403}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}

	// get plaintext id
	PlaintextID, _ := rdb.Get(ctx, agentID).Result()
	cmdData, _ := rdb.HGetAll(ctx, PlaintextID).Result()
	delete(cmdData, "history")
	c.Data["json"] = map[string]interface{}{"message": cmdData}
	c.ServeJSON()

}



// Database Endpoints
// clear database agents
func (c *APIController) ClearAll() {
	var msg Message
	var token = c.Ctx.Input.Header("Authorization")
	err := VerifyAdmin(token)
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
// create an agent id
func (c *APIController) CreateAgent() {
	var msg Message
	var token = c.Ctx.Input.Header("Authorization")
	err := VerifyAdmin(token)
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	agentID := ""
	for {
		agentID = uuid.NewString()

		var cursor uint64
		var keys []string

		for {
			newKeys, nextCursor, err := rdb.Scan(ctx, cursor, "agent:*", 1000).Result()
			if err != nil {
				json.Unmarshal([]byte(`{"message":"` + err.Error() + `"}`), &msg)
				c.Data["json"] = msg
				c.ServeJSON()
				return
			}

			keys = append(keys, newKeys...)
			cursor = nextCursor

			if cursor == 0 {
				break
			}
		}

		if !contains(keys, agentID) {
			break // found a unique ID
		}
	}
	agentKey := "agent:" + agentID
	hashKey := "agent_index:" + hashPasswordSHA256(agentID)
	_, err = rdb.HSet(ctx, agentKey, map[string]string{"filler":"filler"}).Result()
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() + `"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	rdb.Set(ctx, hashKey, agentKey, 0)
	json.Unmarshal([]byte(`{"message":` +`"`+ agentID+`"}`), &msg)
	c.Data["json"] = msg
	c.ServeJSON()
}

func contains(slice []string, str string) bool {
    for _, s := range slice {
        if s == str {
            return true
        }
    }
    return false
}





// list agents
func (c *APIController) Agents() {
	var token = c.Ctx.Input.Header("Authorization")
	if err := VerifyAdmin(token); err != nil {
		c.Data["json"] = Message{Message: err.Error()}
		c.ServeJSON()
		return
	}

	agents, err := ScanAgents()
	if err != nil {
		c.Data["json"] = Message{Message: err.Error()}
		c.ServeJSON()
		return
	}

	// Wrap the list of agents into your Message struct
	c.Data["json"] = Message{Message: agents}
	c.ServeJSON()
}


type Agent struct {
	Agent_id string `json:"agent"`
	Command string `json:"command"`
	Directory string `json:"directory"`
}

type AgentID struct {
	Id string `json:"id"`
}


// delete agent
func (c *APIController) Del_Agent() {
	var msg Message
	var token = c.Ctx.Input.Header("Authorization")
	err := VerifyAdmin(token)
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	var agentID AgentID
	if err := c.Ctx.BindJSON(&agentID); err != nil {
		c.Ctx.WriteString(err.Error())
		return
	}
	
	err = Del(agentID.Id)
	if err != nil {
		json.Unmarshal([]byte(`{"message":` +`"` + err.Error() + `"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	json.Unmarshal([]byte(`{"message":` +`200}`), &msg)
	c.Data["json"] = msg
	c.ServeJSON()
}




// run command 
func (c *APIController) RunCommand() {
	var msg Message
	var token = c.Ctx.Input.Header("Authorization")
	err := VerifyAdmin(token)
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	var agent Agent
	if err := c.Ctx.BindJSON(&agent); err != nil {
		c.Ctx.WriteString(err.Error())
		return
	}
	err = AddCommand(agent.Command, agent.Directory, agent.Agent_id)
	if err != nil {
			
			json.Unmarshal([]byte(`{"message":` +`"` + err.Error() + `"}`), &msg)
			c.Data["json"] = msg
			c.ServeJSON()
			return
	}
	c.Data["json"] = map[string]int{"message": 200}
	c.ServeJSON()

}

func AddCommand(command, dir, agentID string) (err error) {
	data, err := rdb.HGetAll(ctx, agentID).Result()
	if err != nil {
		return err
	}
	data["command"] = command
	data["dir"] = dir
	data["cmdID"] = uuid.NewString()
	data["result"] = "none"
	data["history"] = data["history"] + "," + base64.StdEncoding.EncodeToString([]byte(command))
	_, err = rdb.HSet(ctx, agentID, data).Result()
	if err != nil {
		return err
	}
	return
}

type AgentResponseCommand struct {
	AgentID string `json:"id"`
}

func (c *APIController) GetOutput() {
	var msg Message
	var token = c.Ctx.Input.Header("Authorization")
	err := VerifyAdmin(token)
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	var agent AgentResponseCommand
	if err := c.Ctx.BindJSON(&agent); err != nil {
		c.Ctx.WriteString(err.Error())
		return
	}
	agent_id := agent.AgentID
	cmdOutput, err := Get_commandOutput(agent_id)
	if err != nil {
		json.Unmarshal([]byte(`{"message":"` + err.Error() +`"}`), &msg)
		c.Data["json"] = msg
		c.ServeJSON()
		return
	}
	c.Data["json"] = map[string]string{"message": cmdOutput}
	c.ServeJSON()

} 

func Get_commandOutput(agent_id string) (output string, err error) {
	agentData, err := rdb.HGetAll(ctx, "agent:" + agent_id).Result()
	if err != nil {
		return
	}
	output = agentData["result"]
	return
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

func AuthAgent(hashedAgentID string) bool {
    // Step 1: Look up the real agent key from the hash
    agentKey, err := rdb.Get(ctx, "agent_index:"+hashedAgentID).Result()
    if err == redis.Nil {
        // Index doesn't exist
        return false
    } else if err != nil {
        // Redis error
        return false
    }

    // Step 2: Get the original UUID (agent ID) from the key
    originalID := agentKey[len("agent:"):] // strip "agent:" prefix

    // Step 3: Compare hash
    expectedHash := hashPasswordSHA256(originalID)
    return expectedHash == hashedAgentID
}


func Del(agent_id string) (err error){
	_, err = rdb.Del(ctx, "agent:"+agent_id).Result()
	if err != nil {
		return err
	}
	_, err = rdb.Del(ctx, "agent_index:" + hashPasswordSHA256(agent_id)).Result()
	return err
}


func ScanAgents() ([]string, error) {
	var (
		cursor uint64
		keys   []string
	)

	for {
		newKeys, nextCursor, err := rdb.Scan(ctx, cursor, "agent:*", 1000).Result()
		if err != nil {
			return nil, fmt.Errorf("error scanning Redis: %w", err)
		}
		keys = append(keys, newKeys...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return keys, nil
}