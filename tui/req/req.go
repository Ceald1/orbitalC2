package req

import (
	"bytes"
	"encoding/base64"
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

func GetAgents(APIHost, token string) (agents []APIROUTES.AgentParsed, err error) {
	url := fmt.Sprintf("%s/api/v1/agent/list", APIHost)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	var result map[string][]APIROUTES.AgentParsed
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return
	}
	agents = result["result"]
	return
}

func GetInactiveAgents(APIHost, token string) (agents []APIROUTES.AgentParsed, err error) {
	url := fmt.Sprintf("%s/api/v1/agent/list/inactive", APIHost)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	var result map[string][]APIROUTES.AgentParsed
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return
	}
	agents = result["result"]

	return
}

func DeleteAgent(APIHost, token, agent string) (err error) {
	url := fmt.Sprintf("%s/api/v1/agent/delete/%s", APIHost, agent)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return
	}
	if result["error"] != "" {
		return fmt.Errorf("%s", result["error"])
	}
	return nil
}

func CreateAgent(APIHost, token, agent string) (tokenAgent string, err error) {
	url := fmt.Sprintf("%s/api/v1/agent/create/%s", APIHost, agent)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return
	}
	if result["error"] != "" {
		err = fmt.Errorf("%s", result["error"])
		return
	}
	tokenAgent = result["result"]
	return
}

type notesResponse struct {
	Error  string   `json:"error"`
	Result []string `json:"result"`
}

func GetNotes(APIHost, token, agent string) (NoteList []string, err error) {
	url := fmt.Sprintf("%s/api/v1/notes/%s", APIHost, agent)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var result notesResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return
	}
	if result.Error != "" {
		err = fmt.Errorf("%s", result.Error)
		return
	}
	NoteList = result.Result
	return
}

func UpdateNote(APIHost, token, agent, NoteName, content string) (err error) {
	url := fmt.Sprintf("%s/api/v1/notes/update/%s/%s", APIHost, agent, NoteName)
	encoded := base64.RawStdEncoding.EncodeToString([]byte(content))
	noteContent := APIROUTES.NoteContent{
		Content: encoded,
	}
	body, err := json.Marshal(noteContent)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["error"] != "" {
		err = fmt.Errorf("%s", result["error"])
		return
	}
	return nil
}

func GetNoteContent(APIHost, token, agent, SelectedNote string) (content string, err error) {
	url := fmt.Sprintf("%s/api/v1/notes/%s/%s", APIHost, agent, SelectedNote)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return
	}
	if result["error"] != "" {
		err = fmt.Errorf("%s", result["error"])
		return
	}
	content = result["result"]
	return
}

func DeleteNote(APIHost, token, agent, SelectedNote string) (err error) {
	url := fmt.Sprintf("%s/api/v1/notes/delete/%s/%s", APIHost, agent, SelectedNote)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return
	}
	if result["error"] != "" {
		err = fmt.Errorf("%s", result["error"])
		return
	}
	return
}

func CreateNote(APIHost, token, agent, SelectedNote string) (err error) {
	url := fmt.Sprintf("%s/api/v1/notes/create/%s/%s", APIHost, agent, SelectedNote)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	var result map[string]string
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return
	}
	if result["error"] != "" {
		err = fmt.Errorf("%s", result["error"])
		return
	}
	return
}
