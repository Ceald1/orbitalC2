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
}
