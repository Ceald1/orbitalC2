package main

import (
	"strings"
	"time"

	"encoding/base64"
	"github.com/Ceald1/orbitalC2/tui/models/forms"
	editorModels "github.com/Ceald1/orbitalC2/tui/models/notes"
	"github.com/Ceald1/orbitalC2/tui/models/table"
	"github.com/Ceald1/orbitalC2/tui/req"
	"github.com/atotto/clipboard"
	"github.com/charmbracelet/log"
)

func main() {

	user, password, url := forms.NewToken()
	token, err := req.GetToken(user, password, url)
	if err != nil {
		log.Fatal(err)
	}
	log.Info(token)
MAINMENU:

	option := forms.MainMenu()
	switch option {
	case "exit":
		log.Fatal("quitting..")
	case "config":
		user, password, url := forms.NewToken()
		token, err = req.GetToken(user, password, url)
		if err != nil {
			log.Fatal(err)
		}
		goto MAINMENU
	case "createAgent":
		// create agent forum
		agentName := forms.CreateAgentMenu()
		agentToken, err := req.CreateAgent(url, token, agentName)
		if err != nil {
			if strings.Contains(err.Error(), "exists") {
				log.Warn(err.Error())
			} else {
				log.Fatal(err)
			}
		}
		err = clipboard.WriteAll(agentToken)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("agentToken Copied to clipboard")
		time.Sleep(time.Second * 2)
		goto MAINMENU
	case "deleteAgent":
	DELETEAGENTS:
		agents, err := req.GetAgents(url, token)
		if err != nil {
			log.Fatal(err)
		}
		inActive, err := req.GetInactiveAgents(url, token)
		if err != nil {
			log.Fatal(err)
		}
		agents = append(agents, inActive...)
		s, err := table.NewTable(agents)
		if err != nil {
			log.Fatal(err)
		}
		if s == "" {
			goto MAINMENU
		} else {
			err = req.DeleteAgent(url, token, s)
			if err != nil {
				log.Fatal(err)
			}

		}
		goto DELETEAGENTS
	case "agents":
	AGENTS:
		agents, err := req.GetAgents(url, token)
		if err != nil {
			log.Fatal(err)
		}
		inActive, err := req.GetInactiveAgents(url, token)
		if err != nil {
			log.Fatal(err)
		}
		agents = append(agents, inActive...)
		s, err := table.NewTable(agents)
		if err != nil {
			log.Fatal(err)
		}
		if s == "" {

			goto MAINMENU
		} else {
			notes, err := req.GetNotes(url, token, s)
			if err != nil {
				log.Fatal(err)
			}
		NOTES:
			SelectedNote := forms.NoteMenu(notes, s)
			if SelectedNote == "EXIT" {
				goto AGENTS
			}
			content, err := req.GetNoteContent(url, token, s, SelectedNote)
			if err != nil {
				log.Fatal(err)
			}
			data, _ := base64.StdEncoding.DecodeString(content)
			err = editorModels.RunNotes(string(data))
			if err != nil {
				log.Fatal(err)
			}
			content = editorModels.NoteText
			err = req.UpdateNote(url, token, s, SelectedNote, content)
			if err != nil {
				log.Fatal(err)
			} else {
				goto NOTES
			}
		}
	}
}
