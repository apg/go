package main

import (
	"github.com/keybase/go/libkb"
	"github.com/keybase/protocol/go"
	"github.com/maxtaco/go-framed-msgpack-rpc/rpc2"
)

type MykeyHandler struct {
	BaseHandler
	keyGenUI libkb.KeyGenUI
}

type KeyGenUI struct {
	sessionId int
	cli       keybase_1.MykeyUiClient
}

func NewMykeyHandler(xp *rpc2.Transport) *MykeyHandler {
	return &MykeyHandler{BaseHandler{xp: xp}, nil}
}

func (p *KeyGenUI) GetPushPreferences() (ret keybase_1.PushPreferences, err error) {
	return p.cli.GetPushPreferences()
}

func (h *MykeyHandler) getKeyGenUI(sessionId int) libkb.KeyGenUI {
	if h.keyGenUI == nil {
		h.keyGenUI = &KeyGenUI{
			sessionId: sessionId,
			cli:       keybase_1.MykeyUiClient{h.getRpcClient()},
		}
	}
	return h.keyGenUI
}

func (h *MykeyHandler) KeyGen(arg keybase_1.KeyGenArg) (err error) {
	iarg := libkb.ImportKeyGenArg(arg)

	sessionId := nextSessionId()
	iarg.LogUI = h.getLogUI(sessionId)
	iarg.LoginUI = h.getLoginUI(sessionId)
	iarg.KeyGenUI = h.getKeyGenUI(sessionId)
	iarg.SecretUI = h.getSecretUI(sessionId)

	eng := libkb.NewKeyGen(&iarg)
	_, err = eng.Run()
	return
}