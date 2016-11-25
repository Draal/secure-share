package context

import (
	"fmt"

	"github.com/Draal/secure-share/config"
	"github.com/FinalLevel/go-i18n/i18n"
)

type Context struct {
	Config      *config.Config
	CurrentLang string
	T           i18n.TranslateFunc
	MaxFileSize int64
}

func (c *Context) GetMaxFileSizeString() string {
	mB := c.MaxFileSize / (1024 * 1024)
	if mB > 0 {
		return fmt.Sprintf("%dMb", mB)
	} else {
		return fmt.Sprintf("%dKb", c.MaxFileSize/1024)
	}
}
