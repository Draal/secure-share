package context

import "github.com/Draal/secure-share/config"

type Context struct {
	Config      *config.Config
	CurrentLang string
}
