package forms

import (
	"charm.land/huh/v2"
	"github.com/Ceald1/orbitalC2/tui/styles"
)

func NewToken() (username, password, APIHost string) {
	theme := new(styles.CustomTheme)
	titleUser := "Enter Username"
	promptUser := "Username > "
	titlePassword := "Enter Password"
	promptPassword := "Password > "
	titleAPIHost := "Enter API Base URL (default is in place holder)"
	promptAPIHost := "API > "
	APIHost = "http://127.0.0.1:8080"
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title(titleAPIHost).Value(&APIHost).Prompt(promptAPIHost).Placeholder("http://127.0.0.1:8080"),
			huh.NewInput().Title(titleUser).Value(&username).Prompt(promptUser),
			huh.NewInput().Title(titlePassword).Value(&password).Prompt(promptPassword),
		),
	)
	form.WithTheme(theme)
	form.Run()
	return

}
