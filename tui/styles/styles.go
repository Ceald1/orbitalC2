package styles

import (
	"fmt"
	"image/color"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

var (
	Focus = lipgloss.Color("#E6B8AF")
	// Background (deep dusk)
	BgDark = lipgloss.Color("#201C28")

	// Secondary background / panels
	BgMid = lipgloss.Color("#534B64")

	// Primary text
	TextPrimary = lipgloss.Color("#949494")

	// Secondary / muted text
	TextMuted = lipgloss.Color("#90859C")

	// Accents (warm tones from figure/light)
	AccentSoft = lipgloss.Color("#C58D84")
	AccentDark = lipgloss.Color("#785759")

	// Neutral UI elements (borders, separators)
	Border    = lipgloss.Color("#5A5C5A")
	BaseStyle = lipgloss.NewStyle().
			Foreground(TextPrimary).
			Background(BgDark)

	PanelStyle = lipgloss.NewStyle().
			Background(BgMid).
			Padding(1, 2)

	TitleStyle = lipgloss.NewStyle().
			Foreground(AccentSoft).
			Padding(1, 1, 1, 1).
			Background(BgDark).
			Bold(true)

	HighlightStyle = lipgloss.NewStyle().
			Foreground(AccentSoft)

	MutedStyle = lipgloss.NewStyle().
			Foreground(TextMuted)

	BorderStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(Border)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(AccentDark)
	PromptStyle = lipgloss.NewStyle().
			Foreground(TextMuted)
)

type CustomTheme struct{}

func (c *CustomTheme) Theme(isDark bool) *huh.Styles {
	t := huh.ThemeBase(false)

	background := BgDark
	foreground := TextPrimary
	comment := TextMuted
	selection := AccentSoft
	highlight := AccentSoft
	errorColor := AccentDark
	focus := Focus

	t.Focused.Base = t.Focused.Base.BorderForeground(selection)
	t.Focused.Card = t.Focused.Base
	t.Focused.Title = t.Focused.Title.Foreground(highlight).Bold(true).Padding(1, 1, 1, 1).Background(BgDark)
	t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(highlight)
	t.Focused.Description = t.Focused.Description.Foreground(comment)
	t.Focused.ErrorIndicator = t.Focused.ErrorIndicator.Foreground(errorColor)
	t.Focused.Directory = t.Focused.Directory.Foreground(highlight)
	t.Focused.File = t.Focused.File.Foreground(foreground)
	t.Focused.ErrorMessage = t.Focused.ErrorMessage.Foreground(errorColor)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(selection)
	t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(selection)
	t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(selection)
	t.Focused.Option = t.Focused.Option.Foreground(foreground)
	t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(selection)
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(focus)
	t.Focused.SelectedPrefix = t.Focused.SelectedPrefix.Foreground(focus)
	t.Focused.UnselectedOption = t.Focused.UnselectedOption.Foreground(foreground)
	t.Focused.UnselectedPrefix = t.Focused.UnselectedPrefix.Foreground(comment)
	t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(focus).Background(highlight).Bold(true)
	t.Focused.BlurredButton = t.Focused.BlurredButton.Foreground(foreground).Background(background)

	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(selection)
	t.Focused.TextInput.Placeholder = t.Focused.TextInput.Placeholder.Foreground(comment)
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(selection)

	t.Blurred = t.Focused
	t.Blurred.Base = t.Blurred.Base.BorderStyle(lipgloss.HiddenBorder())
	t.Blurred.Card = t.Blurred.Base
	t.Blurred.NextIndicator = lipgloss.NewStyle()
	t.Blurred.PrevIndicator = lipgloss.NewStyle()
	t.Blurred.Title = t.Blurred.Title.Foreground(AccentDark).Bold(true).Padding(1, 1, 1, 1).Background(BgDark)

	t.Group.Title = t.Focused.Title
	t.Group.Description = t.Focused.Description

	return t

	// // Use your defined palette
	// background := BgDark
	// //panel := BgMid
	// foreground := TextPrimary
	// comment := TextMuted
	// selection := AccentSoft
	// highlight := AccentSoft
	// errorColor := AccentDark
	// focus := Focus
	//
	// // Focused state
	// t.Focused.Base = t.Focused.Base.BorderForeground(selection)
	// t.Focused.Card = t.Focused.Base
	// t.Focused.Title = t.Focused.Title.Foreground(highlight).Bold(true)
	// t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(highlight)
	// t.Focused.Description = t.Focused.Description.Foreground(comment)
	// t.Focused.ErrorIndicator = t.Focused.ErrorIndicator.Foreground(errorColor)
	// t.Focused.Directory = t.Focused.Directory.Foreground(highlight)
	// t.Focused.File = t.Focused.File.Foreground(foreground)
	// t.Focused.ErrorMessage = t.Focused.ErrorMessage.Foreground(errorColor)
	// t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(selection)
	// t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(selection)
	// t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(selection)
	// t.Focused.Option = t.Focused.Option.Foreground(foreground)
	// t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(selection)
	// t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(focus)
	// t.Focused.SelectedPrefix = t.Focused.SelectedPrefix.Foreground(focus)
	// t.Focused.UnselectedOption = t.Focused.UnselectedOption.Foreground(foreground)
	// t.Focused.UnselectedPrefix = t.Focused.UnselectedPrefix.Foreground(comment)
	// t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(focus).Background(highlight).Bold(true)
	// t.Focused.BlurredButton = t.Focused.BlurredButton.Foreground(foreground).Background(background)
	//
	// t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(selection)
	// t.Focused.TextInput.Placeholder = t.Focused.TextInput.Placeholder.Foreground(comment)
	// t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(selection)
	//
	// // Blurred state
	// t.Blurred = t.Focused
	// t.Blurred.Base = t.Blurred.Base.BorderStyle(lipgloss.HiddenBorder())
	// t.Blurred.Card = t.Blurred.Base
	// t.Blurred.NextIndicator = lipgloss.NewStyle()
	// t.Blurred.PrevIndicator = lipgloss.NewStyle()
	//
	// // Group style
	// t.Group.Title = t.Focused.Title
	// t.Group.Description = t.Focused.Description
	//
	// return t
}

func ShowColors() {
	colors := []struct {
		name string
		col  color.Color
	}{
		{"Focus", Focus},
		{"BgDark", BgDark},
		{"BgMid", BgMid},
		{"TextPrimary", TextPrimary},
		{"TextMuted", TextMuted},
		{"AccentSoft", AccentSoft},
		{"AccentDark", AccentDark},
		{"Border", Border},
	}

	for _, c := range colors {
		// Block of color
		block := lipgloss.NewStyle().
			Background(c.col).
			Padding(0, 6)

		fmt.Println(block.Render(" ") + " " + c.name)
	}
}
