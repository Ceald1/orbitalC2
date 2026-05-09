package main

import (
	"context"
	"fmt"

	"net"
	"os"
	"os/signal"

	"syscall"
	"time"

	//	tea "charm.land/bubbletea/v2"
	//	"charm.land/log/v2"
	//tea "charm.land/bubbletea/v2"
	tea "charm.land/bubbletea/v2"
	"charm.land/wish/v2"
	"charm.land/wish/v2/activeterm"
	"charm.land/wish/v2/bubbletea"

	"github.com/charmbracelet/log"

	"github.com/joho/godotenv"

	"github.com/Ceald1/orbitalC2/sshapp/models/forms"

	"charm.land/wish/v2/logging"
	//"github.com/Ceald1/orbitalC2/tui/models/table"
	"github.com/Ceald1/orbitalC2/tui/req"
	//	"github.com/atotto/clipboard"
	"github.com/charmbracelet/ssh"
)

var (
	user     string
	password string
	url      string
	token    string
)

func main() {
	// initialization stuff for API
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}
	user = os.Getenv("API_USER")
	password = os.Getenv("PASSWORD")
	url = os.Getenv("API_HOST")
	log.Info(fmt.Sprintf("using: %s:%s on %s\n", user, password, url))
	token, err = req.GetToken(user, password, url)
	if err != nil {
		log.Fatal(err)
	}
	// end of initialization for API
	// make a new wish server
	s, err := wish.NewServer(
		wish.WithAddress(net.JoinHostPort("0.0.0.0", "2222")),
		ssh.AllocatePty(),
		wish.WithMiddleware(
			bubbletea.Middleware(handler),

			activeterm.Middleware(),
			logging.Middleware(),
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Error(err)
		}
	}()
	log.Info("SSH server started on :22")

	<-done
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.Shutdown(ctx)

}

func handler(s ssh.Session) (tea.Model, []tea.ProgramOption) {
	return forms.NewAppModel(url, token, s), []tea.ProgramOption{}
}
