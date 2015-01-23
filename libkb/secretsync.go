// A module for syncing secrets with the server, such as P3SKB PGP keys,
// and server-halves of our various secret keys.
package libkb

import (
	"sync"
)

type ServerPrivateKey struct {
	Kid     string `json:"kid"`
	KeyType int    `json:"key_type"`
	Bundle  string `json:"bundle"`
	Mtime   int    `json:"mtime"`
	Ctime   int    `json:"ctime"`
	KeyBits int    `json:"key_bits"`
	KeyAlgo int    `json:"key_algo"`
}

type ServerPrivateKeyMap map[string]ServerPrivateKey

type ServerPrivateKeys struct {
	Status      ApiStatus           `json:"status"`
	Version     int                 `json:"version"`
	Mtime       int                 `json:"mtime"`
	PrivateKeys ServerPrivateKeyMap `json:"private_keys"`
}

type SecretSyncer struct {
	// Locks the whole object
	sync.Mutex
	Uid    UID
	loaded bool
	dirty  bool
	keys   ServerPrivateKeys
}

// Load loads a set of secret keys from storage and then checks if there are
// updates on the server.  If there are, it will sync and store them.
func (ss *SecretSyncer) Load() (err error) {

	ss.Lock()
	defer ss.Unlock()

	if err = ss.loadFromStorage(); err != nil {
		return
	}
	if err = ss.syncFromServer(); err != nil {
		return
	}
	if err = ss.store(); err != nil {
		return
	}
	return
}

func (ss *SecretSyncer) loadFromStorage() (err error) {
	ss.loaded, err = G.LocalDb.GetInto(&ss.keys, ss.dbKey())
	return
}

func (ss *SecretSyncer) syncFromServer() (err error) {
	hargs := HttpArgs{}
	if ss.loaded {
		hargs.Add("version", I{ss.keys.Version})
	}
	var obj ServerPrivateKeys
	_, err = G.API.Get(ApiArg{
		Endpoint:    "key/fetch_private",
		Args:        hargs,
		NeedSession: true,
		DecodeTo:    &obj,
	})
	if err != nil {
		return
	}
	if !ss.loaded || obj.Version > ss.keys.Version {
		ss.keys = obj
		ss.dirty = true
	}
	ss.loaded = true
	return
}

func (ss *SecretSyncer) dbKey() DbKey {
	return DbKey{Typ: DB_USER_SECRET_KEYS, Key: ss.Uid.ToString()}
}

func (ss *SecretSyncer) store() (err error) {
	if !ss.dirty {
		return
	}
	if err = G.LocalDb.PutObj(ss.dbKey(), nil, ss.keys); err != nil {
		return
	}
	ss.dirty = false
	return
}
