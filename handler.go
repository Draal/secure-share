package main

import (
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
	maxDataLength         int
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
	data := Data{
		Data:   r.FormValue("data"),
		Hash:   r.FormValue("passHash"),
		Attach: r.FormValue("att") == "true",
	}
	if len(data.Data) > h.maxDataLength {
		h.errorHandler(w, r, BadRequest{fmt.Errorf("Maximum data size has been exceeded %d out of %d", len(data.Data), h.maxDataLength)})
		return
	}
	id, err := h.storage.Post(data, time.Now().Unix()+h.defaultExpire)
	if err != nil {
		h.errorHandler(w, r, err)
		return
	}

	answer := struct {
		Id string `json:"id"`
	}{
		Id: id,
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
	data := Data{}
	err := h.storage.Get(id, &data)
	if err != nil {
		h.errorHandler(w, r, err)
		return
	}
	if data.Hash != "" && data.Hash != r.FormValue("passHash") {
		tryCount := h.badPasswords[id]
		tryCount++
		h.badPasswords[id] = tryCount
		if tryCount >= h.maxWrongPasswordTries {
			h.storage.Delete(id)
		}
		h.errorHandler(w, r, BadRequest{fmt.Errorf("Provide a correct passphrase %d tries left", h.maxWrongPasswordTries-tryCount)})
		return
	}
	h.storage.Delete(id)

	answer := struct {
		Id     string `json:"id"`
		Data   string `json:"data"`
		Attach bool   `json:"attach,omitempty"`
	}{
		Id:     id,
		Data:   data.Data,
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

var hashRe = regexp.MustCompile(`\.[0-9a-f]+(\.[a-z]+)$`)

func (h *Handler) Handler(w http.ResponseWriter, r *http.Request) {
	ctx := &context.Context{
		Config: h.config,
	}
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
	handler := Handler{
		config:                config,
		storage:               storage.OpenMemoryStorage(),
		badPasswords:          make(map[string]int),
		defaultExpire:         3600 * 24 * 7,  // expire in a week by default
		maxWrongPasswordTries: 3,              // allow only 3 password tries
		maxDataLength:         128 * 3 * 1024, // tripple max file size because of base64 encoding overhead
	}
	return &handler, nil
}
