package forms

import (
	"charm.land/huh/v2"
	"github.com/Ceald1/orbitalC2/tui/styles"
)

func NewToken() (username, password string) {
	theme := new(styles.CustomTheme)
	titleUser := "Enter Username"
	promptUser := "Username > "
	titlePassword := "Enter Password"
	promptPassword := "Password > "
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title(titleUser).Value(&username).Prompt(promptUser),
			huh.NewInput().Title(titlePassword).Value(&password).Prompt(promptPassword),
		),
	)
	form.WithTheme(theme)
	form.Run()
	return

}
