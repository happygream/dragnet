package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/happygream/dragnet/internal/model"
	"github.com/happygream/dragnet/internal/scan"
)

// amber/noir palette
var (
	amber    = lipgloss.Color("#e8a33d")
	amberDim = lipgloss.Color("#7a5a26")
	ink      = lipgloss.Color("#e6dccb")
	muted    = lipgloss.Color("#8a7c66")
	bad      = lipgloss.Color("#d9534f")
	good     = lipgloss.Color("#6fae5f")
	bg       = lipgloss.Color("#0c0a08")

	brandStyle  = lipgloss.NewStyle().Foreground(amber).Bold(true)
	tagStyle    = lipgloss.NewStyle().Foreground(muted)
	headerBar   = lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).BorderForeground(amberDim).PaddingBottom(1).MarginBottom(1)
	ipStyle     = lipgloss.NewStyle().Foreground(amber).Bold(true)
	hostnameSty = lipgloss.NewStyle().Foreground(muted)
	portStyle   = lipgloss.NewStyle().Foreground(amber)
	svcStyle    = lipgloss.NewStyle().Foreground(ink)
	bannerStyle = lipgloss.NewStyle().Foreground(muted).Italic(true)
	mutedStyle  = lipgloss.NewStyle().Foreground(muted)
	warnStyle   = lipgloss.NewStyle().Foreground(bad)
	goodStyle   = lipgloss.NewStyle().Foreground(good)
	noteStyle   = lipgloss.NewStyle().Foreground(amberDim)
	footStyle   = lipgloss.NewStyle().Foreground(muted).BorderStyle(lipgloss.NormalBorder()).BorderTop(true).BorderForeground(amberDim).MarginTop(1).PaddingTop(1)
)

type eventMsg scan.Event
type tickMsg time.Time
type autoQuitMsg struct{}

// Model is the Bubble Tea model.
type Model struct {
	cfg     scan.Config
	events  <-chan scan.Event
	spin    spinner.Model
	prog    progress.Model
	hosts   map[string]*model.Host
	order   []string
	total   int
	swept    int
	note     string
	done     bool
	autoExit bool
	started  time.Time
	ended    time.Time
	width    int

	// final report paths, set by the program after Run via SetReportPaths
	jsonPath string
	htmlPath string
}

// New builds the initial model and kicks off the scan pipeline.
// When autoExit is true the TUI quits on its own shortly after the scan
// finishes, rather than waiting for the user to press q.
func New(ctx context.Context, cfg scan.Config, autoExit bool) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(amber)

	p := progress.New(progress.WithoutPercentage(), progress.WithGradient("#7a5a26", "#e8a33d"))

	return Model{
		cfg:      cfg,
		events:   scan.Run(ctx, cfg),
		spin:     s,
		prog:     p,
		hosts:    map[string]*model.Host{},
		started:  time.Now(),
		autoExit: autoExit,
	}
}

// Result exposes collected hosts after the program exits.
func (m Model) Result() (hosts []model.Host, started time.Time) {
	for _, ip := range m.order {
		hosts = append(hosts, *m.hosts[ip])
	}
	return hosts, m.started
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spin.Tick, waitEvent(m.events), tick())
}

func waitEvent(ch <-chan scan.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return eventMsg{Kind: scan.EvFinished}
		}
		return eventMsg(ev)
	}
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.prog.Width = msg.Width - 20
		if m.prog.Width > 60 {
			m.prog.Width = 60
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tickMsg:
		if m.done {
			return m, nil
		}
		return m, tick()

	case eventMsg:
		ev := scan.Event(msg)
		switch ev.Kind {
		case scan.EvExpandDone:
			m.total = ev.Total
			m.note = ev.Note
		case scan.EvHostUp:
			if ev.Host != nil {
				if _, seen := m.hosts[ev.Host.IP]; !seen {
					m.order = append(m.order, ev.Host.IP)
				}
				h := *ev.Host
				m.hosts[ev.Host.IP] = &h
				sortOrder(m.order)
			}
			m.note = ev.Note
		case scan.EvHostDone:
			if ev.Host != nil {
				h := *ev.Host
				m.hosts[ev.Host.IP] = &h
				m.swept++
			}
			m.note = ev.Note
		case scan.EvError:
			m.note = "error: " + ev.Err.Error()
		case scan.EvFinished:
			m.done = true
			m.ended = time.Now()
			m.note = "done"
			if m.autoExit {
				// Hold the final frame briefly so it's readable, then quit.
				return m, tea.Tick(1200*time.Millisecond, func(time.Time) tea.Msg {
					return autoQuitMsg{}
				})
			}
			return m, nil
		}
		return m, waitEvent(m.events)
	}

	if _, ok := msg.(autoQuitMsg); ok {
		return m, tea.Quit
	}

	return m, nil
}

func sortOrder(order []string) {
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
}

func (m Model) View() string {
	var b strings.Builder

	header := lipgloss.JoinHorizontal(lipgloss.Bottom,
		brandStyle.Render("DRAGNET"),
		"  ",
		tagStyle.Render("cast the net"),
	)
	b.WriteString(headerBar.Render(header))
	b.WriteString("\n")

	// status line
	live := len(m.order)
	statusIcon := m.spin.View()
	if m.done {
		statusIcon = goodStyle.Render("✓")
	}
	fmt.Fprintf(&b, "%s  %s  •  hosts up: %s  •  swept: %s/%s\n\n",
		statusIcon,
		noteStyle.Render(m.note),
		ipStyle.Render(fmt.Sprint(live)),
		svcStyle.Render(fmt.Sprint(m.swept)),
		mutedStyle.Render(fmt.Sprint(live)),
	)

	// hosts
	if len(m.order) == 0 {
		b.WriteString(mutedStyle.Render("  casting...\n"))
	}
	for _, ip := range m.order {
		h := m.hosts[ip]
		b.WriteString(renderHost(h))
	}

	// footer
	end := time.Now()
	if m.done && !m.ended.IsZero() {
		end = m.ended
	}
	elapsed := end.Sub(m.started).Round(time.Second)

	hint := "press q to quit"
	if m.done && m.autoExit {
		hint = "finished, exiting"
	}

	foot := fmt.Sprintf("target %s  •  mode %s  •  elapsed %s  •  %s",
		m.cfg.Target, m.cfg.Mode, elapsed, hint)
	if m.done && m.htmlPath != "" {
		foot = fmt.Sprintf("saved %s  •  elapsed %s  •  %s", m.htmlPath, elapsed, hint)
	}
	b.WriteString("\n")
	b.WriteString(footStyle.Render(foot))
	b.WriteString("\n")

	return b.String()
}

func renderHost(h *model.Host) string {
	var b strings.Builder
	name := h.Hostname
	if name == "" {
		name = "—"
	}
	fmt.Fprintf(&b, "  %s  %s  %s\n",
		ipStyle.Render(h.IP),
		hostnameSty.Render(name),
		noteStyle.Render(h.RTT),
	)

	if h.Honeypot {
		fmt.Fprintf(&b, "    %s  %s\n",
			warnStyle.Render("⚠ PROBABLE DECOY"),
			mutedStyle.Render(h.HoneypotReason),
		)
	}

	if len(h.OpenPorts) == 0 {
		return b.String()
	}
	for _, p := range h.OpenPorts {
		line := fmt.Sprintf("    %s  %s",
			portStyle.Render(fmt.Sprintf("%-6d", p.Port)),
			svcStyle.Render(fmt.Sprintf("%-14s", p.Service)),
		)
		if p.Banner != "" {
			line += "  " + bannerStyle.Render(truncate(p.Banner, 50))
		}
		b.WriteString(line + "\n")
	}
	for _, t := range h.TLS {
		w := ""
		if len(t.Warnings) > 0 {
			w = "  " + warnStyle.Render("⚠ "+strings.Join(t.Warnings, "; "))
		}
		fmt.Fprintf(&b, "      %s  %s · %s · expires %dd%s\n",
			mutedStyle.Render("tls"),
			svcStyle.Render(t.Version),
			mutedStyle.Render(t.CipherSuite),
			t.DaysUntilExpiry, w,
		)
	}
	for _, ht := range h.HTTP {
		scoreSty := goodStyle
		if ht.SecurityScore < 50 {
			scoreSty = warnStyle
		} else if ht.SecurityScore < 80 {
			scoreSty = noteStyle
		}
		fmt.Fprintf(&b, "      %s  %s  hdr score %s\n",
			mutedStyle.Render("http"),
			svcStyle.Render(fmt.Sprintf("%d %s", ht.StatusCode, truncate(ht.Title, 30))),
			scoreSty.Render(fmt.Sprintf("%d/100", ht.SecurityScore)),
		)
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
