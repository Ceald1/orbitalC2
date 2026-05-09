package notes

import (
	"fmt"

	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/glamour/v2"
	//gStyles "charm.land/glamour/v2/styles"
	"charm.land/lipgloss/v2"
	"github.com/Ceald1/orbitalC2/tui/styles"
)

// ---- state -----------------------------------------------------------

type sessionState uint

const (
	editMode sessionState = iota
	previewMode
)

// ---- package-level vars (kept for compatibility with callers) ---------

var NoteText string
var NoteName string

// ---- main model ------------------------------------------------------

type MainModel struct {
	state    sessionState
	textarea textarea.Model
	viewport viewport.Model
	width    int
	height   int
}

func NewMainModel(text string) MainModel {
	NoteText = text

	ta := textarea.New()
	ta.SetValue(text)
	ta.Placeholder = ""
	ta.SetVirtualCursor(true)
	ta.SetStyles(textarea.DefaultDarkStyles())
	ta.Focus()

	vp := viewport.New()
	vp.Style = styles.BaseStyle

	return MainModel{
		state:    editMode,
		textarea: ta,
		viewport: vp,
	}
}

// ---- bubbletea interface ---------------------------------------------

func (m MainModel) Init() tea.Cmd {
	return tea.Batch(textarea.Blink, tea.RequestBackgroundColor)
}

func (m MainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.textarea.SetWidth(msg.Width)
		m.textarea.SetHeight(msg.Height - 3)
		m.viewport.SetWidth(msg.Width)
		m.viewport.SetHeight(msg.Height - 3)

	case tea.BackgroundColorMsg:
		m.textarea.SetStyles(textarea.DefaultStyles(msg.IsDark()))

	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc":
			return m, tea.Quit

		case "tab":
			if m.state == editMode {
				NoteText = m.textarea.Value()
				rendered, err := renderMarkdown(NoteText, m.width)
				if err != nil {
					rendered = NoteText
				}
				m.viewport.SetContent(rendered)
				m.viewport.GotoTop()
				m.state = previewMode
			} else {
				m.state = editMode
				return m, m.textarea.Focus()
			}
			return m, nil

		case "q":
			if m.state == previewMode {
				m.state = editMode
				return m, m.textarea.Focus()
			}
			// in edit mode let 'q' be typed normally, fall through below

		default:
			// handled below
		}

		if m.state == previewMode {
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			cmds = append(cmds, cmd)
		} else {
			var cmd tea.Cmd
			m.textarea, cmd = m.textarea.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m MainModel) View() tea.View {
	var body, footer string

	if m.state == previewMode {
		body = m.viewport.View()
		footer = helpStyle("  tab: edit • ↑/↓: scroll • q: back\n")
	} else {
		body = fmt.Sprintf("%s\n%s", NoteName, m.textarea.View())
		footer = helpStyle("  tab: preview • esc: quit\n")
	}

	return tea.NewView(body + "\n" + footer)
}

// ---- helpers ---------------------------------------------------------

var helpStyle = lipgloss.NewStyle().Foreground(styles.Highlight).Render

func renderMarkdown(text string, width int) (string, error) {
	renderWidth := width - 3
	if renderWidth <= 0 {
		renderWidth = 78
	}
	renderer, err := glamour.NewTermRenderer(
		glamour.WithStyles(styles.OrbitalStyle),
		glamour.WithWordWrap(renderWidth),
	)
	if err != nil {
		return "", err
	}
	return renderer.Render(text)
}

// ---- entry point -----------------------------------------------------

func RunNotes(text string) error {
	p := tea.NewProgram(NewMainModel(text))
	_, err := p.Run()
	return err
}
