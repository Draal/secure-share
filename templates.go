package main

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/Draal/secure-share/config"
)

//go:embed templates
var templateFS embed.FS

// templateSet holds a parsed template for every page and language. Each
// language gets its own clone, so "t" is bound to that language.
type templateSet struct {
	pages map[string]map[string]*template.Template // lang code -> page -> template
}

func (s *templateSet) get(lang, page string) *template.Template {
	return s.pages[lang][page]
}

// baseFuncs are placeholders for parsing; real implementations are bound
// per language in langFuncs.
func baseFuncs() template.FuncMap {
	return template.FuncMap{
		"t":     func(string, ...interface{}) string { return "" },
		"th":    func(string, ...interface{}) template.HTML { return "" },
		"asset": func(string) string { return "" },
		"url":   func(string) string { return "" },
		"dict":  dict,
		"list":  func(items ...string) []string { return items },
	}
}

func langFuncs(c *config.Config, l config.Language) template.FuncMap {
	t := c.T(l.Code)
	tr := func(key string, args ...interface{}) string {
		return t(key, translationArgs(c, args)...)
	}
	return template.FuncMap{
		"t": tr,
		// th is for translations that contain markup (<strong>, links). The
		// strings come only from our own translation files.
		"th":    func(key string, args ...interface{}) template.HTML { return template.HTML(tr(key, args...)) },
		"asset": c.GetAssetUrl,
		"url":   func(slug string) string { return pageURL(l, slug) },
	}
}

// translationArgs adds the values every translation may reference, such as
// {{.MaxFileSize}} and {{.Year}}, to the template data passed to go-i18n.
func translationArgs(c *config.Config, args []interface{}) []interface{} {
	data := map[string]interface{}{"MaxFileSize": c.MaxFileSizeString(), "Year": time.Now().Year()}
	var out []interface{}
	for _, a := range args {
		if m, ok := a.(map[string]interface{}); ok {
			for k, v := range m {
				data[k] = v
			}
			continue
		}
		out = append(out, a)
	}
	return append(out, data)
}

// dict builds a map for passing several values to a partial template.
func dict(kv ...interface{}) (map[string]interface{}, error) {
	if len(kv)%2 != 0 {
		return nil, fmt.Errorf("dict: odd number of arguments")
	}
	m := make(map[string]interface{}, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict: key %v is not a string", kv[i])
		}
		m[k] = kv[i+1]
	}
	return m, nil
}

// loadTemplates parses templates/layout.html with templates/partials/*.html
// as the base, then every templates/pages/<name>.html on top of a clone.
func loadTemplates(c *config.Config) (*templateSet, error) {
	base, err := template.New("").Funcs(baseFuncs()).ParseFS(templateFS, "templates/layout.html", "templates/partials/*.html")
	if err != nil {
		return nil, err
	}
	pageFiles, err := fs.Glob(templateFS, "templates/pages/*.html")
	if err != nil {
		return nil, err
	}
	set := &templateSet{pages: make(map[string]map[string]*template.Template)}
	for _, l := range c.Languages {
		set.pages[l.Code] = make(map[string]*template.Template)
	}
	for _, file := range pageFiles {
		name := strings.TrimSuffix(path.Base(file), ".html")
		pageTmpl, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if pageTmpl, err = pageTmpl.ParseFS(templateFS, file); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		for _, l := range c.Languages {
			clone, err := pageTmpl.Clone()
			if err != nil {
				return nil, err
			}
			set.pages[l.Code][name] = clone.Funcs(langFuncs(c, l))
		}
	}
	return set, nil
}
