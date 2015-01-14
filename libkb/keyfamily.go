// A KeyFamily is a group of sibling keys that have equal power for a user.
// A family can consist of 1 PGP keys, and arbitrarily many NaCl Sibkeys.
// There also can be some subkeys dangling off for ECDH.
package libkb

import (
	"encoding/json"
	"github.com/keybase/go-jsonw"
)

// As returned by user/lookup.json
type ServerKeyRecord struct {
	Kid            string  `json:"kid"`
	KeyType        int     `json:"key_type"`
	Bundle         string  `json:"bundle"`
	Mtime          int     `json:"mtime"`
	Ctime          int     `json:"ctime"`
	Etime          int     `json:"etime"`
	KeyFingerprint string  `json:"key_fingerprint"`
	SigningKid     *string `json:"signing_kid"`
	EldestKid      *string `json:"eldest_kid"`
	KeyLevel       int     `json:"key_level"`
	Status         int     `json:"status"`
	KeyBits        int     `json:"key_bits"`
	KeyAlgo        int     `json:"key_algo"`
}

// As returned by user/lookup.json
type KeyFamily struct {
	eldest_kid *KID
	Sibkeys    map[string]ServerKeyRecord `json:"sibkeys"`
	Subkeys    map[string]ServerKeyRecord `json:"subkeys"`
}

func ParseKeyFamily(jw *jsonw.Wrapper) (ret *KeyFamily, err error) {
	var tmp []byte
	if jw == nil && jw.IsNil() {
		err = KeyFamilyError{"nil record from server"}
	}

	// Somewhat wasteful but probably faster than using Jsonw wrappers,
	// and less error-prone
	if tmp, err = jw.Marshal(); err != nil {
		return
	}

	var obj KeyFamily

	if err = json.Unmarshal(tmp, &obj); err == nil {
		ret = &obj
	}

	return
}
