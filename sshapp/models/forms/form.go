package forms

import (
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/wish/v2"
	"github.com/Ceald1/orbitalC2/tui/req"
	"github.com/Ceald1/orbitalC2/tui/styles"
	"github.com/charmbracelet/ssh"
)

func ClearScreen(s ssh.Session) {
	wish.Print(s, "\033[H\033[2J")
}

type Step int

const (
	StepLogin Step = iota
	StepMainMenu
	StepCreateAgent
	StepAgentMenu
	StepNoteMenu
	StepNoteMenu2
	StepDeleteNote
	StepCreateNote
)

type AppModel struct {
	step      Step
	form      *huh.Form
	formReady bool

	Username      string
	Password      string
	APIHost       string
	MenuOption    string
	AgentName     string
	AgentAction   string
	SelectedNote  string
	NoteOption    string
	DeleteConfirm bool
	NewNoteName   string
	APIToken      string

	NoteNames     []string
	SelectedAgent string
	NoteName      string
	Sess          ssh.Session

	theme huh.Theme
}

func NewAppModel(apiHost, token string, s ssh.Session) *AppModel {
	m := &AppModel{
		APIHost:  apiHost,
		APIToken: token,
		Sess:     s,

		theme: new(styles.CustomTheme),
		step:  StepMainMenu,
		//		step:    StepLogin,
	}
	m.form = m.buildForm()
	return m
}

func (m *AppModel) buildForm() *huh.Form {
	switch m.step {

	case StepLogin:
		m.Username = ""
		m.Password = ""
		return huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Title("Enter API Base URL").
					Value(&m.APIHost).Prompt("API > ").
					Placeholder("http://127.0.0.1:8080"),
				huh.NewInput().Title("Enter Username").
					Value(&m.Username).Prompt("Username > "),
				huh.NewInput().Title("Enter Password").
					Value(&m.Password).Prompt("Password > ").
					EchoMode(huh.EchoModePassword),
			),
		).WithTheme(m.theme)

	case StepMainMenu:
		m.MenuOption = ""
		return huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().Options(
					huh.NewOption("Config API", "config"),
					huh.NewOption("Create Agent", "createAgent"),
					huh.NewOption("Delete Agent", "deleteAgent"),
					huh.NewOption("Agents", "agents"),
					huh.NewOption("Exit", "exit"),
				).Value(&m.MenuOption),
			).Title("Main Menu"),
		).WithTheme(m.theme)

	case StepCreateAgent:
		m.AgentName = ""
		return huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Prompt("Name > ").Value(&m.AgentName),
			).Title("New Agent"),
		).WithTheme(m.theme)

	case StepAgentMenu:
		m.AgentAction = ""
		return huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().Options(
					huh.NewOption("Notes", "notes"),
					huh.NewOption("Command", "command"),
					huh.NewOption("Return", "return"),
				).Value(&m.AgentAction),
			).Title("Agent Menu"),
		).WithTheme(m.theme)

	case StepNoteMenu:
		m.SelectedNote = ""
		ops := make([]huh.Option[string], 0, len(m.NoteNames)+2)
		for _, n := range m.NoteNames {
			ops = append(ops, huh.NewOption(n, n))
		}
		ops = append(ops, huh.NewOption("Create Note", "create note"))
		ops = append(ops, huh.NewOption("Return", "return to prev"))
		return huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().Options(ops...).Value(&m.SelectedNote),
			).Title(fmt.Sprintf("Notes for %s", m.SelectedAgent)),
		).WithTheme(m.theme)

	case StepNoteMenu2:
		m.NoteOption = ""
		return huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().Options(
					huh.NewOption("Edit", "edit"),
					huh.NewOption("Delete", "delete"),
					huh.NewOption("Return", "EXIT"),
				).Value(&m.NoteOption),
			).Title(fmt.Sprintf("Options for: %s", m.NoteName)),
		).WithTheme(m.theme)

	case StepDeleteNote:
		m.DeleteConfirm = false
		return huh.NewForm(
			huh.NewGroup(
				huh.NewConfirm().Affirmative("Yes").Negative("No").
					Value(&m.DeleteConfirm),
			).Title("Are you sure?"),
		).WithTheme(m.theme)

	case StepCreateNote:
		m.NewNoteName = ""
		return huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Prompt("Enter Note Name > ").Value(&m.NewNoteName),
			).Title("Create New Note"),
		).WithTheme(m.theme)
	}

	return nil
}

func (m *AppModel) Init() tea.Cmd {
	if m.form != nil {
		return m.form.Init()
	}
	return nil
}

func (m *AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		m.formReady = true
	}

	if m.form == nil {
		return m, tea.Quit
	}

	f, cmd := m.form.Update(msg)
	m.form = f.(*huh.Form)

	if m.form.State == huh.StateAborted {
		return m, tea.Quit
	}

	if m.formReady && m.form.State == huh.StateCompleted {
		return m, m.transition()
	}

	return m, cmd
}

func (m *AppModel) transition() tea.Cmd {
	m.formReady = false

	switch m.step {
	case StepLogin:
		m.step = StepMainMenu

	case StepMainMenu:
		switch m.MenuOption {
		case "createAgent":
			m.step = StepCreateAgent
		case "agents":
			m.step = StepAgentMenu
		case "exit":
			return tea.Quit
		default:
			m.step = StepMainMenu
		}

	case StepCreateAgent:
		resp, api_err := req.CreateAgent(m.APIHost, m.APIToken, m.AgentName)
		if api_err != nil {
			resp = api_err.Error()
		}
		ClearScreen(m.Sess)
		wish.Println(m.Sess, resp)
		time.Sleep(10 * time.Second)
		m.step = StepMainMenu

	case StepAgentMenu:
		switch m.AgentAction {
		case "notes":
			m.step = StepNoteMenu
		case "return":
			m.step = StepMainMenu
		default:
			m.step = StepAgentMenu
		}

	case StepNoteMenu:
		switch m.SelectedNote {
		case "create note":
			m.step = StepCreateNote
		case "return to prev":
			m.step = StepAgentMenu
		default:
			m.NoteName = m.SelectedNote
			m.step = StepNoteMenu2
		}

	case StepNoteMenu2:
		switch m.NoteOption {
		case "delete":
			m.step = StepDeleteNote
		case "EXIT":
			m.step = StepNoteMenu
		default:
			m.step = StepNoteMenu2
		}

	case StepDeleteNote:
		m.step = StepNoteMenu

	case StepCreateNote:
		m.step = StepNoteMenu
	}

	m.form = m.buildForm()
	if m.form == nil {
		return tea.Quit
	}
	return m.form.Init()
}

func (m *AppModel) View() tea.View {
	var view tea.View
	view.AltScreen = true
	if m.form != nil {
		view.SetContent(m.form.View())
	} else {
		view.SetContent("Done.")
	}
	return view
}
