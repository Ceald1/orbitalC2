package styles

import (
	"fmt"
	"image/color"

	"charm.land/glamour/v2/ansi"
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
	Highlight  = lipgloss.Color("#F8D0CC")

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
	highlight := Highlight //AccentSoft
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
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(highlight)
	t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(selection)
	t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(selection)
	t.Focused.Option = t.Focused.Option.Foreground(foreground)
	t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(selection)
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(highlight)
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
	t.Blurred.NextIndicator = MutedStyle
	t.Blurred.PrevIndicator = MutedStyle
	t.Blurred.Title = t.Blurred.Title.Foreground(AccentDark).Bold(true).Padding(1, 1, 1, 1).Background(BgDark)
	t.Blurred.TextInput.Prompt = MutedStyle
	t.Blurred.TextInput.Text = MutedStyle
	t.Help.Ellipsis = HighlightStyle
	t.Help.ShortDesc = HighlightStyle
	t.Help.FullKey = HighlightStyle
	t.Help.ShortKey = HighlightStyle
	// t.Help.Ellipsis.Margin = HighlightStyle

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

const (
	colBgDark      = "#201C28"
	colTextPrimary = "#949494"
	colTextMuted   = "#90859C"
	colAccentSoft  = "#C58D84"
	colHighlight   = "#F8D0CC"
)

func ptr[T any](v T) *T { return &v }

var OrbitalStyle = ansi.StyleConfig{
	Document: ansi.StyleBlock{
		StylePrimitive: ansi.StylePrimitive{
			BackgroundColor: ptr(colBgDark),
			Color:           ptr(colTextPrimary),
		},
		Margin: ptr(uint(0)),
		//Padding: ptr(uint(0)),
	},
	Paragraph: ansi.StyleBlock{
		StylePrimitive: ansi.StylePrimitive{
			BackgroundColor: ptr(colBgDark),
			Color:           ptr(colTextPrimary),
		},
		Margin: ptr(uint(0)),
		//Padding: ptr(uint(0)),
	},
	H1: ansi.StyleBlock{
		StylePrimitive: ansi.StylePrimitive{
			Color:           ptr(colHighlight),
			BackgroundColor: ptr(colBgDark),
			Bold:            ptr(true),
		},
		Margin: ptr(uint(0)),
		//Padding: ptr(uint(0)),
	},
	H2: ansi.StyleBlock{
		StylePrimitive: ansi.StylePrimitive{
			Color:           ptr(colAccentSoft),
			BackgroundColor: ptr(colBgDark),
			Bold:            ptr(true),
		},
		Margin: ptr(uint(0)),
		//Padding: ptr(uint(0)),
	},
	H3: ansi.StyleBlock{
		StylePrimitive: ansi.StylePrimitive{
			Color:           ptr(colAccentSoft),
			BackgroundColor: ptr(colBgDark),
		},
		Margin: ptr(uint(0)),
		//Padding: ptr(uint(0)),
	},
	H4: ansi.StyleBlock{
		StylePrimitive: ansi.StylePrimitive{
			Color:           ptr(colTextMuted),
			BackgroundColor: ptr(colBgDark),
		},
		Margin: ptr(uint(0)),
		//Padding: ptr(uint(0)),
	},
	H5: ansi.StyleBlock{
		StylePrimitive: ansi.StylePrimitive{
			Color:           ptr(colTextMuted),
			BackgroundColor: ptr(colBgDark),
		},
		Margin: ptr(uint(0)),
		//Padding: ptr(uint(0)),
	},
	H6: ansi.StyleBlock{
		StylePrimitive: ansi.StylePrimitive{
			Color:           ptr(colTextMuted),
			BackgroundColor: ptr(colBgDark),
		},
		Margin: ptr(uint(0)),
		//Padding: ptr(uint(0)),
	},
	Strong: ansi.StylePrimitive{
		Color:           ptr(colHighlight),
		BackgroundColor: ptr(colBgDark),
		Bold:            ptr(true),
	},
	Emph: ansi.StylePrimitive{
		Color:           ptr(colAccentSoft),
		BackgroundColor: ptr(colBgDark),
		Italic:          ptr(true),
	},
	Code: ansi.StyleBlock{
		StylePrimitive: ansi.StylePrimitive{
			Color:           ptr(colAccentSoft),
			BackgroundColor: ptr(colBgDark),
		},
		Margin: ptr(uint(0)),
		//Padding: ptr(uint(0)),
	},
	CodeBlock: ansi.StyleCodeBlock{
		StyleBlock: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:           ptr(colTextPrimary),
				BackgroundColor: ptr(colBgDark),
			},
			Margin: ptr(uint(0)),
			//Padding: ptr(uint(1)),
		},
	},
	List: ansi.StyleList{
		StyleBlock: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:           ptr(colTextPrimary),
				BackgroundColor: ptr(colBgDark),
			},
			Margin: ptr(uint(0)),
			//Padding: ptr(uint(0)),
		},
		LevelIndent: 2,
	},
	Item: ansi.StylePrimitive{
		Color:           ptr(colTextPrimary),
		BackgroundColor: ptr(colBgDark),
	},
	Link: ansi.StylePrimitive{
		Color:           ptr(colAccentSoft),
		BackgroundColor: ptr(colBgDark),
		Underline:       ptr(true),
	},
	LinkText: ansi.StylePrimitive{
		Color:           ptr(colHighlight),
		BackgroundColor: ptr(colBgDark),
	},
	BlockQuote: ansi.StyleBlock{
		StylePrimitive: ansi.StylePrimitive{
			Color:           ptr(colTextMuted),
			BackgroundColor: ptr(colBgDark),
			Italic:          ptr(true),
		},
		Indent:      ptr(uint(1)),
		IndentToken: ptr("│ "),
		Margin:      ptr(uint(0)),
		//Padding:     ptr(uint(0)),
	},
	HorizontalRule: ansi.StylePrimitive{
		Color:           ptr(colTextMuted),
		BackgroundColor: ptr(colBgDark),
		Format:          "\n--------\n",
	},
	Table: ansi.StyleTable{
		StyleBlock: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:           ptr(colTextPrimary),
				BackgroundColor: ptr(colBgDark),
			},
		},
		CenterSeparator: ptr("┼"),
		ColumnSeparator: ptr("│"),
		RowSeparator:    ptr("─"),
	},
}
