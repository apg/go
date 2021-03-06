package libkb

type UserInfo struct {
	Uid      UID
	Username string
}

type CurrentStatus struct {
	Configured        bool
	Registered        bool
	LoggedIn          bool
	PublicKeySelected bool
	HasPrivateKey     bool
	User              *User
}

func GetCurrentStatus() (res CurrentStatus, err error) {
	if cr := G.Env.GetConfig(); cr == nil {
	} else {
		res.Configured = true
		if u := cr.GetUid(); u != nil {
			res.Registered = true
			res.User = NewUserThin(cr.GetUsername(), *u)
		}
		res.LoggedIn, err = G.Session.LoadAndCheck()
		if fp := G.Env.GetPgpFingerprint(); fp != nil {
			res.PublicKeySelected = true
		}
	}
	return
}
