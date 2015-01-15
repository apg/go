package libkb

import (
	"encoding/hex"
	"github.com/keybase/go-triplesec"
)

type KID []byte
type KID2 []byte

type GenericKey interface {
	GetKid() KID
	GetFingerprintP() *PgpFingerprint
	GetAlgoType() int
	SignToString([]byte) (string, *SigId, error)
	ToP3SKB(ts *triplesec.Cipher) (*P3SKB, error)
	VerboseDescription() string
	CheckSecretKey() error
	Encode() (string, error) // encode public key to string
}

func (k KID) ToMapKey() string {
	return k.ToString()
}

func (k KID) ToString() string {
	return hex.EncodeToString(k)
}

func ImportKID(s string) (ret KID, err error) {
	var tmp []byte
	if tmp, err = hex.DecodeString(s); err == nil {
		ret = KID(tmp)
	}
	return
}

func (k KID) ToBytes() []byte {
	return []byte(k)
}

func WriteP3SKBToKeyring(k GenericKey, tsec *triplesec.Cipher, lui LogUI) (p3skb *P3SKB, err error) {
	if G.Keyrings == nil {
		err = NoKeyringsError{}
	} else if p3skb, err = k.ToP3SKB(tsec); err == nil {
		err = G.Keyrings.P3SKB.PushAndSave(p3skb, lui)
	}
	return
}
