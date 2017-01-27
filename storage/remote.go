package storage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Remote struct {
	apiUrl string
}

func (s *Remote) Post(data Data, expires int64) (string, error) {
	u := fmt.Sprintf("%s/p", s.apiUrl)
	vals := url.Values{
		"data": {base64.URLEncoding.EncodeToString(data.Data)},
	}
	if len(data.PassHash) > 0 {
		vals.Add("passHash", base64.URLEncoding.EncodeToString(data.PassHash))
	}
	if data.Attach {
		vals.Add("att", "true")
	}
	resp, err := http.Post(u, "application/x-www-form-urlencoded; charset=UTF-8", strings.NewReader(vals.Encode()))
	if err != nil {
		return "", NetworkError{fmt.Errorf("Couldn't post to %s: %s", u, err.Error())}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", NetworkError{fmt.Errorf("Couldn't post to %s unexpected https status:  %d", u, resp.StatusCode)}
	}
	createdItem := struct {
		Id      string
		Expires int64
	}{}
	err = json.NewDecoder(resp.Body).Decode(&createdItem)
	if err != nil {
		return "", DataError{fmt.Errorf("Couldn't parse response from %s: %s", u, err.Error())}
	}
	return createdItem.Id, nil
}

func (s *Remote) Delete(id string) error {
	u := fmt.Sprintf("%s/g?id=%s", s.apiUrl, url.QueryEscape(id))
	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		return DataError{fmt.Errorf("Couldn't create req: %s", err.Error())}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return NetworkError{fmt.Errorf("Couldn't delete from %s: %s", u, err.Error())}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return NetworkError{fmt.Errorf("Couldn't delete from %s unexpected https status:  %d", u, resp.StatusCode)}
	}
	return nil
}

func (s *Remote) Get(id string, passHash string) (Data, error) {
	u := fmt.Sprintf("%s/g", s.apiUrl)
	vals := url.Values{
		"id":       {id},
		"passHash": {passHash},
	}

	resp, err := http.Post(u, "application/x-www-form-urlencoded; charset=UTF-8", strings.NewReader(vals.Encode()))
	if err != nil {
		return Data{}, NetworkError{fmt.Errorf("Couldn't post to %s: %s", u, err.Error())}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Data{}, NotFound{fmt.Errorf("Id %s not found", id)}
	}
	if resp.StatusCode != http.StatusOK {
		return Data{}, NetworkError{fmt.Errorf("Couldn't get from %s unexpected https status: %d", u, resp.StatusCode)}
	}
	item := struct {
		Id     string
		Data   string
		Attach bool
	}{}
	err = json.NewDecoder(resp.Body).Decode(&item)
	if err != nil {
		return Data{}, DataError{fmt.Errorf("Couldn't parse response from %s: %s", u, err.Error())}
	}
	if item.Id != id {
		return Data{}, DataError{fmt.Errorf("Received wrong id from %s expected %s, got %s", u, id, item.Id)}
	}
	data, err := base64.URLEncoding.DecodeString(item.Data)
	if err != nil {
		return Data{}, DataError{fmt.Errorf("Couldn't parse data from %s: %s", u, err.Error())}
	}
	return Data{
		Data:   data,
		Attach: item.Attach,
	}, nil
}

func OpenRemoteStorage(apiUrl string) (Storage, error) {
	remote := Remote{apiUrl: apiUrl}
	return &remote, nil
}
