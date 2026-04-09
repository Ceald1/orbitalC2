package req

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	APIROUTES "github.com/Ceald1/orbitalC2/api/routes"
)

var (
	contentType = "application/json"
)

func GetToken(username, password, APIHost string) (token string, err error) {
	url := fmt.Sprintf("%s/api/v1/user/login", APIHost)
	creds := APIROUTES.UserLogin{}
	creds.Name = username
	creds.Password = password
	body, err := json.Marshal(creds)
	if err != nil {
		return
	}
	resp, err := http.Post(url, contentType, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["error"] != "" {
		err = fmt.Errorf("%s", result["error"])
		return
	}
	token = result["token"]
	return

}
