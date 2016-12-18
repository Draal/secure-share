package config

import (
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/FinalLevel/go-i18n/i18n"
)

type Language struct {
	Code      string
	Iso       string
	Name      string
	ShortName string
}

type Config struct {
	Root        string
	UseMinified bool
	UseHashing  bool
	assets      map[string]string
	MaxFileSize int64
	Languages   []Language
}

func (c *Config) calcAssetCrc32(p string) (string, error) {
	if c.UseMinified {
		if ext := path.Ext(p); ext != "" {
			p = fmt.Sprintf("%s.min%s", strings.TrimSuffix(p, ext), ext)
		}
	}
	cssFile, err := ioutil.ReadFile(c.Root + p)
	if err != nil {
		return "", err
	}
	cssCRC32 := crc32.Checksum(cssFile, crc32.IEEETable)
	if c.UseHashing {
		if ext := path.Ext(p); ext != "" {
			p = fmt.Sprintf("%s.%x%s", strings.TrimSuffix(p, ext), cssCRC32, ext)
		}
	}
	return p, nil
}

func (c *Config) calcAssetsCrc32() error {
	c.assets = make(map[string]string)
	if asset, err := c.calcAssetCrc32("/css/w3.css"); err != nil {
		return err
	} else {
		c.assets["w3.css"] = asset
	}
	if asset, err := c.calcAssetCrc32("/js/share.js"); err != nil {
		return err
	} else {
		c.assets["share.js"] = asset
	}
	if asset, err := c.calcAssetCrc32("/bower_components/crypto-js/crypto-js.js"); err != nil {
		return err
	} else {
		c.assets["crypto-js.js"] = asset
	}
	if asset, err := c.calcAssetCrc32("/bower_components/jquery/dist/jquery.js"); err != nil {
		return err
	} else {
		c.assets["jquery.js"] = asset
	}
	return nil
}

func (c *Config) GetAssetUrl(name string) string {
	return c.assets[name]
}

func (c *Config) loadTranslationFiles() error {
	if err := i18n.LoadTranslationFile("translation/en-us.all.json"); err != nil {
		return err
	}
	if err := i18n.LoadTranslationFile("translation/ru-ru.all.json"); err != nil {
		return err
	}
	c.Languages = []Language{
		Language{Code: "en-us", Iso: "eng", Name: "English", ShortName: "ENG"},
		Language{Code: "ru-ru", Iso: "rus", Name: "Русский", ShortName: "РУС"},
	}
	return nil
}

func (c *Config) GetLanguageByCode(code string) Language {
	for _, l := range c.Languages {
		if l.Code == code {
			return l
		}
	}
	return Language{}
}

const (
	LangEnglish = "en-us"
)

func (c *Config) GetLanguage(req *http.Request, setLang string) (t i18n.TranslateFunc, lang string) {
	acceptLang := req.Header.Get("Accept-Language")
	transF, _, resLang := i18n.Tfunc(setLang, acceptLang, LangEnglish)
	return transF, resLang
}

func OpenFromEnv() (*Config, error) {
	config := Config{
		Root:        "./public",
		UseMinified: os.Getenv("USE_MINIFIED") != "",
		UseHashing:  os.Getenv("USE_HASHING") != "",
		MaxFileSize: 5 * 1024 * 1024,
	}
	if maxFileSize, _ := strconv.ParseInt(os.Getenv("MAX_FILE_SIZE"), 10, 64); maxFileSize > 0 {
		config.MaxFileSize = maxFileSize
	}
	if err := config.calcAssetsCrc32(); err != nil {
		return nil, fmt.Errorf("Couldn't calculate crc32: %s", err.Error())
	}
	if err := config.loadTranslationFiles(); err != nil {
		return nil, fmt.Errorf("Couldn't load translation files: %s", err.Error())
	}
	return &config, nil
}
