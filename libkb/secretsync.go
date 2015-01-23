// A module for syncing secrets with the server, such as P3SKB PGP keys,
// and server-halves of our various secret keys.
package libkb

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
	Version     int                 `json:"version"`
	Mtime       int                 `json:"mtime"`
	PrivateKeys ServerPrivateKeyMap `json:"private_keys"`
}

type SecretSyncer struct {
	uid     UID
	version int
	loaded  bool
}
