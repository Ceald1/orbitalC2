package table

import (
	"fmt"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	routes "github.com/Ceald1/orbitalC2/api/routes"
	"github.com/Ceald1/orbitalC2/tui/styles"
	"golang.org/x/term"
	"os"
)

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).BorderBackground(styles.BgMid).Foreground(styles.TextPrimary)

var Selected string

type Model struct {
	table table.Model
}

func (m Model) Init() tea.Cmd {
	m.table.Focus()
	Selected = ""
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc":
			// return m, tea.Quit
			if m.table.Focused() {
				m.table.Blur()
			} else {
				m.table.Focus()
			}
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "w":
			m.table.MoveUp(1)
		case "down", "s":
			m.table.MoveDown(1)
		case "enter":
			if m.table.SelectedRow() == nil {
				return m, tea.Quit
			}
			Selected = m.table.SelectedRow()[1] // agent name
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		width := msg.Width - 6 // use msg directly, subtract border
		height := msg.Height

		newColumns := make([]table.Column, 0)
		colWidth := (width / 4) - 1
		for _, column := range m.table.Columns() {
			column.Width = colWidth
			newColumns = append(newColumns, column)
		}
		m.table.SetColumns(newColumns)
		m.table.SetWidth(width)
		m.table.SetHeight(height - 20)

	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m Model) View() tea.View {
	return tea.NewView(baseStyle.Render(m.table.View()) + "\n  " + m.table.HelpView() + "\n")
}

func NewTable(agents []routes.AgentParsed) (selectedAgent string, err error) {
	fmt.Print("\033[H\033[2J")
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	width = width - 6 // match the -4 above
	colWidth := (width / 4) - 1

	columns := []table.Column{
		{Title: "ID", Width: colWidth},
		{Title: "Name", Width: colWidth},
		{Title: "Last Checked", Width: colWidth},
		{Title: "OS", Width: colWidth},
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
		table.WithHeight(height-20),
		table.WithWidth(width),
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
