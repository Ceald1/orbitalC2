package forms

import (
	"fmt"

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
	fmt.Print("\033[H\033[2J")
	form.Run()
	return

}

func MainMenu() (option string) {
	fmt.Print("\033[H\033[2J")
	huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Options(
				huh.NewOption("Config API", "config"),
				huh.NewOption("Create Agent", "createAgent"),
				huh.NewOption("Delete Agent", "deleteAgent"),
				huh.NewOption("Agents", "agents"),
				huh.NewOption("exit", "exit"),
			).Value(&option),
		).Title("Main Menu"),
	).WithTheme(new(styles.CustomTheme)).Run()
	return option
}

func CreateAgentMenu() (name string) {
	fmt.Print("\033[H\033[2J")
	huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Prompt("Name > ").Value(&name),
		).Title("New Agent"),
	).WithTheme(new(styles.CustomTheme)).Run()
	return
}

func NoteMenu(noteNames []string, selectedAgent string) (selectedNote string) {
	var ops []huh.Option[string]
	fmt.Print("\033[H\033[2J")
	for _, note := range noteNames {
		option := huh.NewOption(note, note)
		ops = append(ops, option)
	}
	ops = append(ops, huh.NewOption("return to prev", "EXIT"))
	huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Options(ops...).Value(&selectedNote),
		).Title(fmt.Sprintf("Notes for %s", selectedAgent)),
	).WithTheme(new(styles.CustomTheme)).Run()

	fmt.Print("\033[H\033[2J")
	return
}

// manage notes
func NoteMenu2(noteName string) (selectedOption string) {
	fmt.Print("\033[H\033[2J")

	huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Options(
				huh.NewOption("edit", "edit"),
				huh.NewOption("delete", "delete"),
				huh.NewOption("return to menu", "EXIT"),
			).Value(&selectedOption),
		).Title(fmt.Sprintf("Options for note: %s", noteName)),
	).WithTheme(new(styles.CustomTheme)).Run()
	return selectedOption
}

func DeleteNote() (areSure bool) {
	fmt.Print("\033[H\033[2J")
	huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().Affirmative("Yes").Negative("No").Value(&areSure),
		).Title("Are you sure?"),
	).WithTheme(new(styles.CustomTheme)).Run()

	return areSure
}
