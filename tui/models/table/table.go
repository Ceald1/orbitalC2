package table

import (
	"fmt"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	routes "github.com/Ceald1/orbitalC2/api/routes"
	"github.com/Ceald1/orbitalC2/tui/styles"
)

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).BorderBackground(styles.BgMid).Foreground(styles.TextPrimary)

var Selected string

type Model struct {
	table table.Model
}

func (m Model) Init() tea.Cmd {
	Selected = ""
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc":
			return m, tea.Quit
			//if m.table.Focused() {
			//	m.table.Blur()
			//} else {
			//	m.table.Focus()
			//}
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			Selected = m.table.SelectedRow()[1] // agent name
			return m, tea.Quit
		}

	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m Model) View() tea.View {
	return tea.NewView(baseStyle.Render(m.table.View()) + "\n  " + m.table.HelpView() + "\n")
}

func NewTable(agents []routes.AgentParsed) (selectedAgent string, err error) {
	columns := []table.Column{
		{Title: "ID", Width: 4},
		{Title: "Name", Width: 20},
		{Title: "Last Checked", Width: 20},
		{Title: "OS", Width: 10},
	}
	rows := make([]table.Row, 0)
	for i, agent := range agents {
		row := table.Row{
			fmt.Sprintf("%d", i),
			agent.Name,
			agent.LastChecked,
			agent.OS,
		}
		rows = append(rows, row)
	}
	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithHeight(10),
		table.WithWidth(60),
	)
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(styles.TextMuted).BorderBottom(true).Bold(true)
	s.Selected = s.Selected.Foreground(styles.TextPrimary).Background(styles.Highlight).Bold(true)
	t.SetStyles(s)
	m := Model{t}
	_, err = tea.NewProgram(m).Run()
	return Selected, err

}
