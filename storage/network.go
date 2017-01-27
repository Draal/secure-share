package storage

import (
	"fmt"
	"log"
	"os"
	"strconv"
)

type Network struct {
	storages  map[int]Storage
	storageId int
}

type NetworkError struct{ error }

func (n *Network) Post(data Data, expires int64) (string, error) {
	// try to post locally first
	storageId := n.storageId
	id, err := n.storages[storageId].Post(data, expires)
	if err != nil {
		log.Printf("%d:%s", storageId, err.Error())
		for remoteStorageId, storage := range n.storages {
			id, err = storage.Post(data, expires)
			if err == nil {
				storageId = remoteStorageId
				break
			}
			err = NetworkError{fmt.Errorf("%d: %s", remoteStorageId, err.Error())}
			log.Println(err)
		}
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%2x%s", storageId, id), nil
}

func getStorageIdFromId(id string) int {
	storageId, _ := strconv.ParseInt(id[:2], 16, 64)
	return int(storageId)
}

func (n *Network) Get(id string, passHash string) (Data, error) {
	storageId := getStorageIdFromId(id)
	if storage, present := n.storages[storageId]; present {
		return storage.Get(id, passHash)
	} else {
		return n.storages[n.storageId].Get(id, passHash)
	}
}

func (n *Network) Delete(id string) error {
	storageId := getStorageIdFromId(id)
	if storage, present := n.storages[storageId]; present {
		return storage.Delete(id)
	} else {
		return n.storages[n.storageId].Delete(id)
	}
}

func OpenNetworkStorageFromEnv() (Storage, error) {
	network := Network{
		storages: make(map[int]Storage),
	}
	if network.storageId, _ = strconv.Atoi(os.Getenv("NETWORK_STORAGE_ID")); network.storageId == 0 {
		return nil, fmt.Errorf("NETWORK_STORAGE_ID must be set")
	}
	i := 1
	for {
		if url := os.Getenv(fmt.Sprintf("NETWORK_STORAGE_%d", i)); url != "" {
			if i == network.storageId {
				localStorage, err := OpenDiskStorageFromEnv()
				if err != nil {
					return nil, fmt.Errorf("Couldn't create local storage %s", err.Error())
				}
				network.storages[i] = localStorage
			} else {
				remoteStorage, err := OpenRemoteStorage(url)
				if err != nil {
					return nil, fmt.Errorf("Couldn't open remote %s storage %s", url, err.Error())
				}
				network.storages[i] = remoteStorage
			}
		} else {
			break
		}
		i++
	}
	if len(network.storages) == 0 {
		return nil, fmt.Errorf("Coudn't create a network storage without NETWORK_STORAGE_*")
	}
	return &network, nil
}
