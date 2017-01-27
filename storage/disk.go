package storage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type diskItem struct {
	PassHashSize uint16
	DataSize     uint32
	Attach       uint8
}

type Disk struct {
	paths []string
}

func (s *Disk) FormPath(id string) string {
	return fmt.Sprintf("%s/%s/%s", s.paths[(int(id[0])+int(id[1]))%len(s.paths)], id[:1], id)
}

func (s *Disk) Post(data Data, expires int64) (string, error) {
	for t := 0; t < 10; t++ {
		id, err := GenerateRandomId()
		if err != nil {
			return "", err
		}
		p := s.FormPath(id)
		if err := os.MkdirAll(path.Dir(p), os.FileMode(0700)); err != nil && !os.IsExist(err) {
			return "", IoError{fmt.Errorf("Cound't create dir %s:%s", path.Base(p), err.Error())}
		}
		if _, err := os.Lstat(p); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			log.Printf("%T %v", err, err)
			return "", IoError{fmt.Errorf("Cound't get file info %s:%s", p, err.Error())}
		}
		fd, err := os.Create(p)
		if err != nil {
			return "", IoError{fmt.Errorf("Cound't create %s:%s", p, err.Error())}
		}
		defer fd.Close()
		var r io.Reader
		var sig bytes.Buffer
		item := diskItem{
			PassHashSize: uint16(len(data.PassHash)),
			DataSize:     uint32(len(data.Data)),
		}
		if data.Attach {
			item.Attach = 1
		}
		binary.Write(&sig, binary.BigEndian, item)
		r = io.MultiReader(&sig, bytes.NewReader(data.PassHash), bytes.NewReader(data.Data))
		_, err = io.Copy(fd, r)
		if err != nil {
			return "", IoError{fmt.Errorf("Cound't write to %s:%s", p, err.Error())}
		}
		expireTime := time.Unix(expires, 0)
		if err = os.Chtimes(p, expireTime, expireTime); err != nil {
			return "", IoError{fmt.Errorf("Cound't change time of %s:%s", p, err.Error())}
		}
		return id, nil
	}
	return "", IdGenerationError{fmt.Errorf("Could not find unique id")}
}

func (s *Disk) Get(id string, passHash string) (Data, error) {
	p := s.FormPath(id)
	if d, err := os.Lstat(p); err != nil {
		if os.IsNotExist(err) {
			return Data{}, NotFound{fmt.Errorf("Id %s not found", id)}
		} else {
			return Data{}, IoError{fmt.Errorf("Cound't get file info %s:%s", p, err.Error())}
		}
	} else if d.ModTime().Unix() < time.Now().Unix() {
		return Data{}, NotFound{fmt.Errorf("Id %s not found", id)}
	}
	fd, err := os.Open(p)
	if err != nil {
		return Data{}, IoError{fmt.Errorf("Cound't open %s:%s", p, err.Error())}
	}
	defer fd.Close()
	item := diskItem{}
	err = binary.Read(fd, binary.BigEndian, &item)
	if err != nil {
		return Data{}, IoError{fmt.Errorf("Cound't read signature %s:%s", p, err.Error())}
	}
	data := Data{
		Attach: item.Attach == 1,
	}
	if item.PassHashSize > 0 {
		data.PassHash = make([]byte, item.PassHashSize)
		_, err = io.ReadFull(fd, data.PassHash)
		if err != nil {
			return Data{}, IoError{fmt.Errorf("Cound't read pass hash %s:%s", p, err.Error())}
		}
	}
	data.Data = make([]byte, item.DataSize)
	_, err = io.ReadFull(fd, data.Data)
	if err != nil {
		return Data{}, IoError{fmt.Errorf("Cound't read data %s:%s", p, err.Error())}
	}
	return data, nil
}

func (s *Disk) Delete(id string) error {
	p := s.FormPath(id)
	if err := os.Remove(p); err != nil && err != os.ErrNotExist {
		return err
	}
	return nil
}

func (s *Disk) gc() {
	now := time.Now().Unix()
	for _, path := range s.paths {
		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if info.ModTime().Unix() < now {
				if err := os.Remove(path); err != nil && err != os.ErrNotExist {
					return fmt.Errorf("Coudn't remove %s: %s", path, err.Error())
				}
			}
			return nil
		})
		if err != nil {
			log.Printf("Disk gc: %s", err)
		}
	}
}

func OpenDiskStorageFromEnv() (Storage, error) {
	disk := Disk{
		paths: strings.Split(os.Getenv("DISK_STORAGE_PATHS"), ":"),
	}
	if len(disk.paths) == 0 {
		return nil, fmt.Errorf("Coudn't create a disk storage without DISK_STORAGE_PATHS")
	}
	go func() {
		for t := time.Tick(24 * time.Hour); ; <-t {
			disk.gc()
		}
	}()
	return &disk, nil
}
