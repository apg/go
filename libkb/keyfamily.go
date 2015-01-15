// A KeyFamily is a group of sibling keys that have equal power for a user.
// A family can consist of 1 PGP keys, and arbitrarily many NaCl Sibkeys.
// There also can be some subkeys dangling off for ECDH.
package libkb

import (
	"encoding/json"
	"fmt"
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

	key GenericKey `json:-`
}

type KeyMap map[string]ServerKeyRecord

// As returned by user/lookup.json
type KeyFamily struct {
	eldest_kid *KID
	Sibkeys    KeyMap `json:"sibkeys"`
	Subkeys    KeyMap `json:"subkeys"`
}

func (km KeyMap) ImportKeys() (err error) {
	for _, v := range km {
		if err = v.ImportKey(); err != nil {
			return
		}
	}
	return
}

func (kf *KeyFamily) ImportKeys() (err error) {
	G.Log.Debug("+ ImportKeys")
	defer func() {
		G.Log.Debug("- ImportKeys -> %s", ErrToOk(err))
	}()
	if err = kf.Sibkeys.ImportKeys(); err != nil {
		return
	}
	if err = kf.Subkeys.ImportKeys(); err != nil {
		return
	}
	return
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

	if err = json.Unmarshal(tmp, &obj); err != nil {
		return
	}

	if err = obj.ImportKeys(); err != nil {
		return
	}
	ret = &obj
	return
}

func (skr *ServerKeyRecord) ImportKey() (err error) {
	switch skr.KeyAlgo {
	case KID_PGP_RSA, KID_PGP_RSA, KID_PGP_ELGAMAL, KID_PGP_DSA, KID_PGP_ECDH, KID_PGP_ECDSA:
		var pgp *PgpKeyBundle
		if pgp, err = ReadOneKeyFromString(skr.Bundle); err == nil {
			skr.key = pgp
		}
	case KID_NACL_EDDSA:
		var ns NaclSigningKeyPair
		if ns, err = ImportNaclSigningKeyPair(skr.Bundle); err == nil {
			skr.key = ns
		}
	case KID_NACL_DH:
		var nd NaclDHKeyPair
		if nd, err = ImportNaclDHKeyPair(skr.Bundle); err == nil {
			skr.key = nd
		}
	default:
		err = BadKeyError{fmt.Sprintf("algo=%d is unknown", skr.KeyAlgo)}
	}
	if err == nil {
		G.Log.Debug("| Imported Key %s", skr.key.GetKid().ToString())
	}
	return
}
