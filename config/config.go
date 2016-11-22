package config

import (
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

type Config struct {
	Root        string
	UseMinified bool
	UseHashing  bool
	assets      map[string]string
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

func OpenFromEnv() (*Config, error) {
	config := Config{
		Root:        "./public",
		UseMinified: os.Getenv("USE_MINIFIED") != "",
		UseHashing:  os.Getenv("USE_HASHING") != "",
	}
	err := config.calcAssetsCrc32()
	if err != nil {
		return nil, fmt.Errorf("Can't calculate crc32: %s", err.Error())
	}
	return &config, nil
}
