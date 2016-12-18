package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/Draal/secure-share/config"
	"github.com/Draal/secure-share/context"
	"github.com/Draal/secure-share/storage"
	template "github.com/Draal/secure-share/templates"
)

type Handler struct {
	config                *config.Config
	storage               storage.Storage
	defaultExpire         int64
	badPasswords          map[string]int
	maxWrongPasswordTries int
}

type Data struct {
	Data   string
	Hash   string `json:",omitempty"`
	Attach bool   `json:",omitempty"`
}

func recordEvent(r *http.Request, evt map[string]interface{}) {
	evt["time"] = time.Now().Format(time.RFC3339Nano)
	if r != nil {
		evt["url"] = r.URL.String()
		evt["host"] = r.URL.Host
		evt["path"] = r.URL.Path
	}
	json.NewEncoder(os.Stdout).Encode(evt)
}

func (h *Handler) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	recordEvent(r, map[string]interface{}{
		"error": err.Error(),
	})
	status := http.StatusInternalServerError
	switch err.(type) {
	case BadRequest:
		status = http.StatusBadRequest
	case storage.NotFound:
		status = http.StatusNotFound
	}
	splitCode := strings.Split(fmt.Sprintf("%T", err), ".")
	splitCode[0] = "Secure.Share"
	var message string
	if e, ok := err.(interface {
		FriendlyMessage() string
	}); ok {
		message = e.FriendlyMessage()
	}
	w.WriteHeader(status)
	type Error struct {
		Code    string `json:"code"`
		Message string `json:"message,ommitempty"`
	}
	json.NewEncoder(w).Encode(struct {
		Error Error `json:"error"`
	}{
		Error: Error{
			Code:    strings.Join(splitCode, "."),
			Message: message,
		},
	})
}

type BadRequest struct{ error }

func (e BadRequest) FriendlyMessage() string {
	return e.Error()
}

func (h *Handler) postHandler(w http.ResponseWriter, r *http.Request, ctx *context.Context) {
	data := storage.Data{
		Attach: r.FormValue("att") == "true",
	}
	var err error
	data.Data, err = base64.StdEncoding.DecodeString(r.FormValue("data"))
	if err != nil {
		h.errorHandler(w, r, BadRequest{fmt.Errorf("Data parse error: %s", err.Error())})
		return
	}
	if hash := r.FormValue("passHash"); hash != "" {
		data.PassHash, err = base64.StdEncoding.DecodeString(hash)
		if err != nil {
			h.errorHandler(w, r, BadRequest{fmt.Errorf("Passphrase hash parse error: %s", err.Error())})
			return
		}
	}
	if len(data.Data) > int(ctx.MaxFileSize)*2 { // allow twice size for encoding overheads
		h.errorHandler(w, r, BadRequest{fmt.Errorf("Maximum data size has been exceeded %d out of %d", len(data.Data), ctx.MaxFileSize)})
		return
	}
	expires := time.Now().Unix() + h.defaultExpire
	id, err := h.storage.Post(data, expires)
	if err != nil {
		h.errorHandler(w, r, err)
		return
	}

	answer := struct {
		Id      string `json:"id"`
		Expires int64  `json:"expires"`
	}{
		Id:      id,
		Expires: expires,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(answer)
}

func (h *Handler) getHandler(w http.ResponseWriter, r *http.Request, ctx *context.Context) {
	id := r.FormValue("id")
	if id == "" {
		h.errorHandler(w, r, BadRequest{fmt.Errorf("Provide an id")})
		return
	}
	if r.Method == http.MethodDelete {
		h.storage.Delete(id)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
		return
	}
	data, err := h.storage.Get(id)
	if err != nil {
		h.errorHandler(w, r, err)
		return
	}
	if len(data.PassHash) > 0 {
		if passHash, err := base64.StdEncoding.DecodeString(r.FormValue("passHash")); err != nil {
			h.errorHandler(w, r, BadRequest{fmt.Errorf("Passphrase hash parse error: %s", err.Error())})
			return
		} else if !bytes.Equal(data.PassHash, passHash) {
			tryCount := h.badPasswords[id]
			tryCount++
			h.badPasswords[id] = tryCount
			if tryCount >= h.maxWrongPasswordTries {
				h.storage.Delete(id)
			}
			h.errorHandler(w, r, BadRequest{fmt.Errorf("Provide a correct passphrase %d tries left", h.maxWrongPasswordTries-tryCount)})
			return
		}
	}
	h.storage.Delete(id)

	answer := struct {
		Id     string `json:"id"`
		Data   string `json:"data"`
		Attach bool   `json:"attach,omitempty"`
	}{
		Id:     id,
		Data:   base64.StdEncoding.EncodeToString(data.Data),
		Attach: data.Attach,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(answer)
}

func (h *Handler) indexHandler(w http.ResponseWriter, r *http.Request, ctx *context.Context) {
	template.Index(w, ctx)
}

func (h *Handler) showHandler(w http.ResponseWriter, r *http.Request, ctx *context.Context) {
	template.Show(w, ctx)
}

func (h *Handler) SaveLanguageToCookie(lang string, w http.ResponseWriter) {
	expire := time.Now().AddDate(5, 0, 0)
	cookie := http.Cookie{
		Name:    "lang",
		Value:   lang,
		Path:    "/",
		Expires: expire,
	}
	http.SetCookie(w, &cookie)
}

func (h *Handler) GetLanguageFromCookie(r *http.Request) string {
	lang, _ := r.Cookie("lang")
	if lang != nil {
		return lang.Value
	}
	return ""
}

var hashRe = regexp.MustCompile(`\.[0-9a-f]+(\.[a-z]+)$`)

func (h *Handler) Handler(w http.ResponseWriter, r *http.Request) {
	ctx := &context.Context{
		Config:      h.config,
		MaxFileSize: h.config.MaxFileSize,
	}
	setLanguage := ""
	if len(r.URL.Path) >= 4 {
		for _, l := range ctx.Config.Languages {
			if strings.HasPrefix(r.URL.Path[1:], l.Iso) {
				setLanguage = l.Code
				h.SaveLanguageToCookie(setLanguage, w)
				r.URL.Path = "/"
				break
			}
		}
	} else {
		setLanguage = h.GetLanguageFromCookie(r)
	}
	ctx.T, ctx.CurrentLang = h.config.GetLanguage(r, setLanguage)
	if r.URL.Path == "/" {
		h.indexHandler(w, r, ctx)
		return
	} else if strings.HasPrefix(r.URL.Path, "/s/") {
		h.showHandler(w, r, ctx)
		return
	}
	switch path.Base(r.URL.Path) {
	case "p":
		h.postHandler(w, r, ctx)
	case "g":
		h.getHandler(w, r, ctx)
	default:
		p := hashRe.ReplaceAllString(r.URL.Path, "$1")
		http.ServeFile(w, r, path.Join("public", p))
	}
}

func OpenHandlerFromEnv() (*Handler, error) {
	config, err := config.OpenFromEnv()
	if err != nil {
		return nil, err
	}
	var st storage.Storage
	switch os.Getenv("STORAGE_TYPE") {
	case "disk":
		st, err = storage.OpenDiskStorageFromEnv()
		if err != nil {
			return nil, fmt.Errorf("Coudn't open disk storage: %s", err.Error())
		}
	default:
		st = storage.OpenMemoryStorage()
	}
	handler := Handler{
		config:                config,
		storage:               st,
		badPasswords:          make(map[string]int),
		defaultExpire:         3600 * 24 * 7, // expire in a week by default
		maxWrongPasswordTries: 3,             // allow only 3 password tries
	}
	return &handler, nil
}
