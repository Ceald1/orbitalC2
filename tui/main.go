package main

import (
	"github.com/Ceald1/orbitalC2/tui/models/forms"
	"github.com/Ceald1/orbitalC2/tui/req"
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
		goto MAINMENU
	case "deleteAgent":
		goto MAINMENU
	case "agents":
		goto MAINMENU
	}
}
