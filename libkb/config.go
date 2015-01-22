package libkb

import (
	"encoding/hex"
	"github.com/keybase/go-jsonw"
)

type JsonConfigFile struct {
	*JsonFile
}

func NewJsonConfigFile(s string) *JsonConfigFile {
	return &JsonConfigFile{NewJsonFile(s, "config")}
}

type valueGetter func(*jsonw.Wrapper) (interface{}, error)

func (f JsonConfigFile) getValueAtPath(
	p string, getter valueGetter) (ret interface{}, is_set bool) {
	is_set = false
	var err error
	ret, err = getter(f.jw.AtPath(p))
	if err == nil {
		is_set = true
	}
	return
}

func getString(w *jsonw.Wrapper) (interface{}, error) {
	return w.GetString()
}

func getBool(w *jsonw.Wrapper) (interface{}, error) {
	return w.GetBool()
}

func getInt(w *jsonw.Wrapper) (interface{}, error) {
	return w.GetInt()
}

func (f JsonConfigFile) GetStringAtPath(p string) (ret string, is_set bool) {
	i, is_set := f.getValueAtPath(p, getString)
	if is_set {
		ret = i.(string)
	}
	return
}

func (f JsonConfigFile) GetBoolAtPath(p string) (ret bool, is_set bool) {
	i, is_set := f.getValueAtPath(p, getBool)
	if is_set {
		ret = i.(bool)
	}
	return
}

func (f JsonConfigFile) GetIntAtPath(p string) (ret int, is_set bool) {
	i, is_set := f.getValueAtPath(p, getInt)
	if is_set {
		ret = i.(int)
	}
	return
}

func (f JsonConfigFile) GetNullAtPath(p string) (is_set bool) {
	is_set = false
	w := f.jw.AtPath(p)
	is_set = w.IsNil() && w.Error() == nil
	return
}

func (f JsonConfigFile) GetTopLevelString(s string) (ret string) {
	var e error
	f.jw.AtKey(s).GetStringVoid(&ret, &e)
	G.Log.Debug("Config: mapping %s -> %s", s, ret)
	return
}

func (f JsonConfigFile) GetTopLevelBool(s string) (res bool, is_set bool) {
	is_set = false
	res = false
	if w := f.jw.AtKey(s); !w.IsNil() {
		is_set = true
		var e error
		w.GetBoolVoid(&res, &e)
	}
	return
}

func (f *JsonConfigFile) UserDict() *jsonw.Wrapper {
	if f.jw.AtKey("user").IsNil() {
		f.jw.SetKey("user", jsonw.NewDictionary())
		f.dirty = true
	}
	return f.jw.AtKey("user")
}

func (f *JsonConfigFile) setValueAtPath(
	p string, getter valueGetter, v interface{}) (err error) {
	existing, err := getter(f.jw.AtPath(p))

	if err != nil || existing != v {
		err = f.jw.SetValueAtPath(p, jsonw.NewWrapper(v))
		if err == nil {
			f.dirty = true
		}
	}
	return
}

func (f *JsonConfigFile) SetStringAtPath(p string, v string) (err error) {
	return f.setValueAtPath(p, getString, v)
}

func (f *JsonConfigFile) SetBoolAtPath(p string, v bool) (err error) {
	return f.setValueAtPath(p, getBool, v)
}

func (f *JsonConfigFile) SetIntAtPath(p string, v int) (err error) {
	return f.setValueAtPath(p, getInt, v)
}

func (f *JsonConfigFile) SetNullAtPath(p string) (err error) {
	existing := f.jw.AtPath(p)
	if !existing.IsNil() || existing.Error() != nil {
		err = f.jw.SetValueAtPath(p, jsonw.NewNil())
		if err == nil {
			f.dirty = true
		}
	}
	return
}

func (f *JsonConfigFile) SetUsername(s string) {
	f.SetUserField("name", s)
}

func (f *JsonConfigFile) SetUid(u UID) {
	f.SetUserField("id", string(u.ToString()))
}

func (f *JsonConfigFile) SetSalt(b []byte) {
	f.SetUserField("salt", hex.EncodeToString(b))
}
func (f *JsonConfigFile) SetPgpFingerprint(fp *PgpFingerprint) {
	key := "fingerprint"
	if fp == nil {
		f.DeleteUserField(key)
	} else {
		s := fp.ToString()
		f.SetUserField(key, s)
	}
}

func (f *JsonConfigFile) SetUserField(k, v string) {
	existing := f.GetUserField(k)
	if existing != v {
		f.UserDict().SetKey(k, jsonw.NewString(v))
		f.dirty = true
	}
}

func (f *JsonConfigFile) DeleteUserField(k string) {
	f.jw.AtKey("user").DeleteKey(k)
	f.dirty = true
}

func (f *JsonConfigFile) DeleteAtPath(p string) {
	f.jw.DeleteValueAtPath(p)
	f.dirty = true
}

func (f *JsonConfigFile) Reset() {
	f.jw = jsonw.NewDictionary()
	f.dirty = true
}

func (f *JsonConfigFile) Write() error {
	return f.MaybeSave(true, 0)
}

func (f JsonConfigFile) GetUserField(s string) string {
	var ret string
	var err error
	ret, err = f.jw.AtKey("user").AtKey(s).GetString()
	if err != nil {
		ret = ""
	}
	G.Log.Debug("Config: mapping user.%s-> %s", s, ret)
	return ret
}

func (f JsonConfigFile) GetHome() (ret string) {
	return f.GetTopLevelString("home")
}
func (f JsonConfigFile) GetServerUri() (ret string) {
	return f.GetTopLevelString("server")
}
func (f JsonConfigFile) GetConfigFilename() (ret string) {
	return f.GetTopLevelString("config")
}
func (f JsonConfigFile) GetSecretKeyring() string {
	return f.GetTopLevelString("secret_keyring")
}
func (f JsonConfigFile) GetSessionFilename() (ret string) {
	return f.GetTopLevelString("session")
}
func (f JsonConfigFile) GetDbFilename() (ret string) {
	return f.GetTopLevelString("db")
}
func (f JsonConfigFile) GetPinentry() string {
	res, _ := f.GetStringAtPath("pinentry.path")
	return res
}
func (f JsonConfigFile) GetGpg() string {
	res, _ := f.GetStringAtPath("gpg.command")
	return res
}
func (f JsonConfigFile) GetLocalRpcDebug() string {
	return f.GetTopLevelString("local_rpc_debug")
}
func (f JsonConfigFile) GetGpgOptions() []string {
	var ret []string
	if f.jw == nil {
		// noop
	} else if v := f.jw.AtPath("gpg.options"); v == nil {
		// noop
	} else if l, e := v.Len(); e != nil || l == 0 {
		// noop
	} else {
		ret := make([]string, 0, l)
		for i := 0; i < l; i++ {
			if s, e := v.AtIndex(i).GetString(); e != nil {
				ret = append(ret, s)
			}
		}
	}
	return ret
}
func (f JsonConfigFile) GetNoPinentry() (bool, bool) {
	return f.GetBoolAtPath("pinentry.disabled")
}
func (f JsonConfigFile) GetUsername() string {
	return f.GetUserField("name")
}
func (f JsonConfigFile) GetSalt() []byte {
	s := f.GetUserField("salt")
	if len(s) == 0 {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		G.Log.Warning("In getting salt from %s: %s", f.filename, err.Error())
	}
	return b
}
func (f JsonConfigFile) GetUid() *UID {
	i, err := UidFromHex(f.GetUserField("id"))
	if err != nil {
		i = nil
	}
	return i
}
func (f JsonConfigFile) GetPgpFingerprint() *PgpFingerprint {
	ret := PgpFingerprintFromHexNoError(f.GetUserField("fingerprint"))
	return ret
}
func (f JsonConfigFile) GetEmail() (ret string) {
	return f.GetTopLevelString("email")
}
func (f JsonConfigFile) GetProxy() (ret string) {
	return f.GetTopLevelString("proxy")
}
func (f JsonConfigFile) GetDebug() (bool, bool) {
	return f.GetTopLevelBool("debug")
}
func (f JsonConfigFile) GetPlainLogging() (bool, bool) {
	return f.GetTopLevelBool("plain_logging")
}
func (f JsonConfigFile) GetStandalone() (bool, bool) {
	return f.GetTopLevelBool("standalone")
}

func (f JsonConfigFile) GetCacheSize(w string) (ret int, ok bool) {
	ret, ok = f.jw.AtPathGetInt(w)
	return
}

func (f JsonConfigFile) GetUserCacheSize() (ret int, ok bool) {
	return f.GetCacheSize("cache.limits.users")
}
func (f JsonConfigFile) GetProofCacheSize() (ret int, ok bool) {
	return f.GetCacheSize("cache.limits.proofs")
}

func (f JsonConfigFile) GetMerkleKeyFingerprints() []string {
	if f.jw == nil {
		return nil
	} else if v, err := f.jw.AtKey("keys").AtKey("merkle").ToArray(); err != nil || v == nil {
		return nil
	} else if l, err := v.Len(); err != nil {
		return nil
	} else if l == 0 {
		return make([]string, 0, 0)
	} else {
		ret := make([]string, 0, l)
		for i := 0; i < l; i++ {
			if s, err := v.AtIndex(i).GetString(); err != nil {
				return nil
			} else {
				ret = append(ret, s)
			}
		}
		return ret
	}
}

func (f JsonConfigFile) GetPgpDir() (ret string) {
	ret = f.GetTopLevelString("pgpdir")
	if len(ret) == 0 {
		ret = f.GetTopLevelString("gpgdir")
	}
	if len(ret) == 0 {
		ret = f.GetTopLevelString("gnupgdir")
	}
	return ret
}

func (f JsonConfigFile) GetBundledCA(host string) (ret string) {
	var err error
	f.jw.AtKey("bundled_CAs").AtKey(host).GetStringVoid(&ret, &err)
	if err == nil {
		G.Log.Debug("Read bundled CA for %s", host)
	}
	return ret
}

func (f JsonConfigFile) GetSocketFile() string {
	return f.GetTopLevelString("socket_file")
}
func (f JsonConfigFile) GetDaemonPort() (int, bool) {
	return f.GetIntAtPath("daemon_port")
}

func (f JsonConfigFile) GetPerDeviceKID() (ret KID) {
	if f.jw != nil {
		if kid, err := GetKID(f.jw.AtKey("device_kid")); err != nil {
			G.Log.Warning("Error reading 'device_kid' from configfile: %s", err.Error())
		} else {
			ret = kid
		}
	}
	return
}

func (f *JsonConfigFile) SetPerDeviceKID(kid KID) (err error) {
	key := "device_kid"
	if kid == nil {
		f.DeleteUserField(key)
	} else {
		f.SetUserField(key, kid.ToString())
	}
	return
}
