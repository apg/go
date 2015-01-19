package libkb

// Provision ourselves or other devices via the various key exchange
// posibilities

type SelfProvisioner struct {
	me        *User
	secretKey *P3SKB
}

func (sp *SelfProvisioner) LoadMe() (err error) {
	sp.me, err = LoadMe(LoadUserArg{LoadSecrets: true})
	return
}

// CheckProvisioned checks the current status of our client, to see if
// it's provisioned or not, and if so, whether we have the corresponding
// private key.
func (sp *SelfProvisioner) CheckProvisioned() (err error) {
	if kid := G.Env.GetPerDeviceKID(); kid == nil {
		err = NotProvisionedError{}
	} else if ring := G.Keyrings.P3SKB; ring == nil {
		err = NoKeyringsError{}
	} else if sp.secretKey = ring.LookupByKid(kid); sp.secretKey == nil {
		err = NoSecretKeyError{}
	}
	return
}
