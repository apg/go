// A KeyFamily is a group of sibling keys that have equal power for a user.
// A family can consist of 1 PGP keys, and arbitrarily many NaCl Sibkeys.
// There also can be some subkeys dangling off for ECDH.
package libkb

import (
	"encoding/json"
	"fmt"
	"github.com/keybase/go-jsonw"
	"time"
)

// We have two notions of time we can use -- standard UTC which might
// be screwy (skewy) based upon local clock problems; or MerkleRoot seqno,
// which is totally ordered and all clients and server ought to agree on it.
// The issue is that we're not uniformly signing Merkle roots into signatures,
// especially those generated on the Web site.
type KeybaseTime struct {
	Utc   time.Time // UTC wallclock time
	Chain int       // Merkle root chain time
}

type ComputedKeyInfo struct {
	Status      int
	Eldest      bool
	Delegations map[SigId]KID
	Revocations map[SigId]KID
	Delegated   *KeybaseTime
	Revoked     *KeybaseTime
}

// As returned by user/lookup.json
type ServerKeyRecord struct {
	Kid            string  `json:"kid"`
	KeyType        int     `json:"key_type"`
	Bundle         string  `json:"bundle"`
	Mtime          int     `json:"mtime"`
	Ctime          int     `json:"ctime"`
	Etime          int     `json:"etime"`
	PgpFingerprint string  `json:"key_fingerprint"`
	SigningKid     *string `json:"signing_kid"`
	EldestKid      *string `json:"eldest_kid"`
	KeyLevel       int     `json:"key_level"`
	Status         int     `json:"status"`
	KeyBits        int     `json:"key_bits"`
	KeyAlgo        int     `json:"key_algo"`

	key GenericKey `json:-`
}

type KeyMap map[string]*ServerKeyRecord

// When we play a sigchain forward, it yields ComputeKeyInfo. We're going to
// store CKIs separately from the keys, since the server can clobber the
// former.  We should rewrite CKIs every time we (re)check a user's SigChain
type ComputedKeyInfos struct {
	dirty bool // whether it needs to be written to disk or not

	// Map of KID (in HEX) to a computed info
	Infos map[string]ComputedKeyInfo
}

// As returned by user/lookup.json
type KeyFamily struct {
	eldest  *FOKID
	pgps    []*PgpKeyBundle
	pgp2kid map[string]string

	Sibkeys KeyMap `json:"sibkeys"`
	Subkeys KeyMap `json:"subkeys"`
}

type ComputedKeyFamily struct {
	kf  *KeyFamily
	cki *ComputedKeyInfos
}

func (cki *ComputedKeyInfos) Insert(f *FOKID, i *ComputeKeyInfo) {
	if f != nil {
		v := f.ToStrings()
		for _, s := range v {
			cki.Infos[s] = i
		}
		cki.dirty = true
	}
}

// NewComputedKeyInfos creates a new ComputedKeyInfos object
// from the given key family.  It finds the eldest sibling in the family and marks
// his status LIVE, so that he can be used to verify signatures. There's
// obviously no one who can delegate to him, so we take it on faith.
func (kf KeyFamily) NewComputedKeyInfos() *ComputedKeyInfos {

	ret := ComputedKeyInfos{
		Infos: make(map[string]*ComputedKeyInfo),
	}

	ret.Insert(kf.eldest, &ComputedKeyInfo{
		Eldest: true,
		Status: KEY_LIVE,
	})

	return &ret
}

// FindSibkey finds a sibkey in our KeyFamily, by either PGP fingerprint or
// KID.  It returns the GenericKey object that's useful for actually performing
// PGP ops.
func (kf KeyFamily) FindActiveSibkey(f FOKID) (key GenericKey, err error) {

	var found bool
	var i string
	kid := f.Kid
	if kid == nil && f.Fp != nil {
		i = f.Fp.ToString()
		if kid, found = kf.pgp2kid[i]; !found {
			err = NoKeyError{fmt.Sprintf("No KID for PGP fingerprint %s found", i)}
			return
		}
	}
	if kid == nil {
		err = NoKeyFound{"Can't lookup sibkey without a KID"}
		return
	}

	i = f.Kid.ToString()
	if sk, ok := kf.Sibkeys[i]; !ok {
		err = NoKeyError{fmt.Sprintf("No sibkey found for %s", i)}
	} else {
		key = sk.key
	}
	return
}

func (km KeyMap) Import(pgps_i []*PgpKeyBundle) (pgps_o []*PgpKeyBundle, err error) {
	pgps_o = pgps_i
	for _, v := range km {
		var pgp *PgpKeyBundle
		if pgp, err = v.Import(); err != nil {
			return
		}
		if pgp != nil {
			pgps_o = append(pgps_o, pgp)
		}
	}
	return
}

func (kf *KeyFamily) Import() (err error) {
	G.Log.Debug("+ ImportKeys")
	defer func() {
		G.Log.Debug("- ImportKeys -> %s", ErrToOk(err))
	}()
	if kf.pgps, err = kf.Sibkeys.Import(kf.pgps); err != nil {
		return
	}
	if kf.pgps, err = kf.Subkeys.Import(kf.pgps); err != nil {
		return
	}
	for _, p := range kf.pgps {
		kf.pgp2kid[p.PgpFingerprint] = p.Kid
	}
	err = kf.findEldest()
	return
}

func (kf *KeyFamily) SetEldest(hx string) (err error) {
	var kid KID
	if kid, err = ImportKID(hx); err != nil {
		return
	}
	if kf.eldest == nil {
		kf.eldest = &FOKID{Kid: kid}
	} else if !kf.eldest.EqKid(kid) {
		err = KeyFamilyError{fmt.Sprintf("Kid mismatch: %s != %s",
			kf.eldest.Kid.ToString(), hx)}
	}
	return
}

func (kf *KeyFamily) GetEldest() *FOKID {
	return kf.eldest
}

// findEldest finds the eldest key in the given Key family, and sanity
// checks that the eldest key is unique.  If tests pass, it sets a "FOKID"
// object to capture both the KID and the (optional) PgpFingerprint
// of the eldest key in the family.
func (kf *KeyFamily) findEldest() (err error) {
	for _, v := range kf.Sibkeys {
		if v.EldestKid == nil {
			err = kf.SetEldest(v.Kid)
		} else {
			err = kf.SetEldest(*v.EldestKid)
		}
		if err != nil {
			return
		}
	}
	if kf.eldest != nil {
		x := kf.eldest.Kid.ToString()
		if key, found := kf.Sibkeys[x]; !found {
			err = KeyFamilyError{fmt.Sprintf("Eldest KID %s disappeared", x)}
		} else {
			kf.eldest.Fp, err = PgpFingerprintFromHex(key.PgpFingerprint)
		}
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

func (skr ServerKeyRecord) IsPgp() bool {
	return skr.key != nil && IsPgpAlgo(skr.KeyAlgo)
}

func (skr *ServerKeyRecord) Import() (pgp *PgpKeyBundle, err error) {
	switch {
	case IsPgpAlgo(skr.KeyAlgo):
		if pgp, err = ReadOneKeyFromString(skr.Bundle); err == nil {
			skr.key = pgp
		}
	case skr.KeyAlgo == KID_NACL_EDDSA:
		skr.key, err = ImportNaclSigningKeyPair(skr.Bundle)
	case skr.KeyAlgo == KID_NACL_DH:
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

func (ckf ComputedKeyFamily) FindActiveSibkey(f FOKID) (key GenericKey, err error) {
	s := f.ToString()
	if ki := ckf.ki.Infos[s]; ki == nil {
		err = NoKeyError{fmt.Sprintf("The key '%s' wasn't found", s)}
	} else if ki.Status != KEY_LIVE {
		err = BadKeyError{fmt.Sprintf("The key '%s' is no longer active", s)}
	} else {
		key, err = ckf.FindSibkey(f)
	}
	return
}
