// A KeyFamily is a group of sibling keys that have equal power for a user.
// A family can consist of 1 PGP keys, and arbitrarily many NaCl Sibkeys.
// There also can be some subkeys dangling off for ECDH.
package libkb

import (
	"encoding/json"
	"fmt"
	"github.com/keybase/go-jsonw"
)

type ComputedKeyInfo struct {
	Status      int
	Eldest      bool
	Delegations map[SigId]KID
	Revocations map[SigId]KID
}

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

// When we play a sigchain forward, it yields ComputeKeyInfo. We're going to
// store CKIs separately from the keys, since the server can clobber the
// former.  We should rewrite CKIs every time we (re)check a user's SigChain
type ComputedKeyInfos struct {
	dirty bool // whether it needs to be written to disk or not
	Infos map[string]ComputedKeyInfo
}

// As returned by user/lookup.json
type KeyFamily struct {
	eldest_kid *KID
	Sibkeys    KeyMap `json:"sibkeys"`
	Subkeys    KeyMap `json:"subkeys"`
}

func (km KeyMap) Import() (err error) {
	for _, v := range km {
		if err = v.Import(); err != nil {
			return
		}
	}
	return
}

func (kf *KeyFamily) Import() (err error) {
	G.Log.Debug("+ ImportKeys")
	defer func() {
		G.Log.Debug("- ImportKeys -> %s", ErrToOk(err))
	}()
	if err = kf.Sibkeys.Import(); err != nil {
		return
	}
	if err = kf.Subkeys.Import(); err != nil {
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

	if err = obj.Import(); err != nil {
		return
	}
	ret = &obj
	return
}

func (skr *ServerKeyRecord) Import() (err error) {
	switch skr.KeyAlgo {
	case KID_PGP_RSA, KID_PGP_RSA, KID_PGP_ELGAMAL, KID_PGP_DSA, KID_PGP_ECDH, KID_PGP_ECDSA:
		skr.key, err = ReadOneKeyFromString(skr.Bundle)
	case KID_NACL_EDDSA:
		skr.key, err = ImportNaclSigningKeyPair(skr.Bundle)
	case KID_NACL_DH:
		skr.key, err = ImportNaclDHKeyPair(skr.Bundle)
	default:
		err = BadKeyError{fmt.Sprintf("algo=%d is unknown", skr.KeyAlgo)}
	}
	if err == nil {
		G.Log.Debug("| Imported Key %s", skr.key.GetKid().ToString())
	}
	return
}

func (kf KeyFamily) GetSigningKey(kid_s string) (ret GenericKey) {
	if skr, found := kf.Sibkeys[kid_s]; found {
		ret = skr.key
	}
	return
}
