package form

import (
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"charm.land/wish/v2"
	"github.com/Ceald1/orbitalC2/api/routes"
	"github.com/Ceald1/orbitalC2/tui/req"
	"github.com/Ceald1/orbitalC2/tui/styles"

	//	"github.com/charmbracelet/lipgloss/table"
	"github.com/charmbracelet/ssh"
)

func ClearScreen(s ssh.Session) {
	wish.Print(s, "\033[H\033[2J")
}

type Step string
type ROW [][]string
type COLUMN []string

type AppModel struct {
	step      Step
	form      *huh.Form
	formReady bool

	Username      string
	Password      string
	APIHost       string
	MenuOption    Step
	AgentName     string
	AgentAction   Step
	SelectedNote  string
	NoteOption    Step
	DeleteConfirm bool
	NewNoteName   string
	APIToken      string
	Agents        []routes.AgentParsed
	AreSure       bool

	NoteNames     []string
	SelectedAgent string
	NoteName      string
	Sess          ssh.Session

	theme huh.Theme
}

func (m *AppModel) AgentsForm() *huh.Form {
	agents := m.Agents
	rows := make([][]string, len(agents))
	for i, agent := range agents {
		rows[i] = []string{
			fmt.Sprintf("%d", i),
			agent.Name,
			agent.LastChecked,
			agent.OS,
		}
	}

	t := table.New().
		Headers("ID", "Name", "Last Checked", "OS").
		Rows(rows...).
		Border(lipgloss.NormalBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(styles.TextMuted)).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return lipgloss.NewStyle().Bold(true).Foreground(styles.TextPrimary)
			}
			return lipgloss.NewStyle().Foreground(styles.TextPrimary)
		})
	opts := make([]huh.Option[string], len(agents))
	for i, a := range agents {
		opts[i] = huh.NewOption(a.Name, a.Name)
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Agents").
				Description(t.Render()),
			huh.NewSelect[string]().
				Title("Select an agent").
				Options(opts...).
				Value(&m.SelectedAgent),
		),
	).WithTheme(new(styles.CustomTheme))

	return form
}

func NewAppModel(apiHost, token string, s ssh.Session) *AppModel {
	m := &AppModel{
		APIHost:  apiHost,
		APIToken: token,
		Sess:     s,

		theme: new(styles.CustomTheme),
		step:  "main",
		//		step:    StepLogin,
	}
	m.form = m.buildForm()
	return m
}

func (m *AppModel) buildForm() *huh.Form {
	switch m.step {
	case "config":
		theme := new(styles.CustomTheme)
		titleUser := "Enter Username"
		promptUser := "Username > "
		titlePassword := "Enter Password"
		promptPassword := "Password > "
		titleAPIHost := "Enter API Base URL (default is in place holder)"
		promptAPIHost := "API > "

		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Title(titleAPIHost).Value(&m.APIHost).Prompt(promptAPIHost).Placeholder("http://127.0.0.1:8080"),
				huh.NewInput().Title(titleUser).Value(&m.Username).Prompt(promptUser),
				huh.NewInput().Title(titlePassword).Value(&m.Password).Prompt(promptPassword).EchoMode(huh.EchoModePassword),
			),
		)
		form.WithTheme(theme)
		return form
	case "main":
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[Step]().Options(
					huh.NewOption("Config API", Step("config")),
					huh.NewOption("Create Agent", Step("createAgent")),
					huh.NewOption("Delete Agent", Step("deleteAgent")),
					huh.NewOption("Agents", Step("agents")),
					huh.NewOption("exit", Step("exit")),
				).Value(&m.MenuOption),
			).Title("Main Menu"),
		).WithTheme(new(styles.CustomTheme))
		return form

	case "createAgent":
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Prompt("Name > ").Value(&m.AgentName),
			).Title("New Agent"),
		).WithTheme(new(styles.CustomTheme))
		return form
	case "deleteAgent", "agents":
		resp, err := req.GetAgents(m.APIHost, m.APIToken)
		if err != nil {
			ClearScreen(m.Sess)
			wish.Println(m.Sess, err.Error())
			time.Sleep(5 * time.Second)
			return nil
		} else {
			resp2, err := req.GetInactiveAgents(m.APIHost, m.APIToken)
			if err != nil {
				ClearScreen(m.Sess)
				wish.Println(m.Sess, err.Error())
				time.Sleep(5 * time.Second)
				return nil
			} else {
				resp = append(resp, resp2...)
				m.Agents = resp
			}
		}
		return m.AgentsForm()

	case "manageAgent":
		return huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[Step]().Options(
					huh.NewOption("notes", Step("notes")),
					huh.NewOption("command", Step("command")),
					huh.NewOption("return", Step("agents")),
				).Value(&m.AgentAction),
			).Title("Agent menu"),
		).WithTheme(new(styles.CustomTheme))

	case "notes":
		var ops []huh.Option[string]
		for _, note := range m.NoteNames {
			option := huh.NewOption(note, note)
			ops = append(ops, option)
		}
		ops = append(ops, huh.NewOption("create note", "create note"))
		ops = append(ops, huh.NewOption("return to prev", "return to prev"))

		form := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().Options(ops...).Value(&m.SelectedNote),
			).Title(fmt.Sprintf("Notes for %s", m.SelectedAgent)),
		).WithTheme(new(styles.CustomTheme))
		return form
	case "manageNote":
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[Step]().Options(
					huh.NewOption("edit", Step("edit")),
					huh.NewOption("delete", Step("delete")),
					huh.NewOption("return to menu", Step("notes")),
				).Value(&m.NoteOption),
			).Title(fmt.Sprintf("Options for note: %s", m.NoteName)),
		).WithTheme(new(styles.CustomTheme))
		return form

	case "delNote":
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewConfirm().Affirmative("Yes").Negative("No").Value(&m.AreSure),
			).Title("Are you sure?"),
		).WithTheme(new(styles.CustomTheme))
		return form

	case "createNote":
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Prompt("Enter Note Name > ").Value(&m.NoteName),
			).Title("Create New Note"),
		).WithTheme(new(styles.CustomTheme))
		return form

	default:

		return nil
	}
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
	case "config":
		resp, err := req.GetToken(m.Username, m.Password, m.APIHost)
		if err != nil {
			ClearScreen(m.Sess)
			wish.Println(m.Sess, err.Error())
			time.Sleep(5 * time.Second)
		} else {
			m.APIToken = resp
		}
		m.step = "main"

	case "main":
		m.step = m.MenuOption

	case "createAgent":
		resp, err := req.CreateAgent(m.APIHost, m.APIToken, m.AgentName)
		if err != nil {
			resp = err.Error()
		}
		ClearScreen(m.Sess)
		wish.Println(m.Sess, resp)
		time.Sleep(10 * time.Second)
		m.step = "main"
	case "agents":
		m.step = "manageAgent"

	case "manageAgent":
		m.step = m.AgentAction
	}
	m.form = m.buildForm()

	if m.form == nil {
		return tea.Quit
	}
	return m.form.Init()
}

func (m *AppModel) Init() tea.Cmd {
	if m.form != nil {
		return m.form.Init()
	}
	return nil
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
