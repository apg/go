package libkb

import (
	"fmt"
	"github.com/keybase/go-jsonw"
	"strings"
)

//=============================================================================
//

type ProofError interface {
	error
	GetStatus() ProofStatus
	GetDesc() string
}

func ProofErrorIsSoft(pe ProofError) bool {
	s := int(pe.GetStatus())
	return s >= PROOF_BASE_ERROR && s < PROOF_BASE_HARD_ERROR
}

func ProofErrorToState(pe ProofError) int {
	if pe == nil {
		return PROOF_STATE_OK
	} else if s := pe.GetStatus(); s == PROOF_NO_HINT || s == PROOF_UNKNOWN_TYPE {
		return PROOF_STATE_NONE
	} else {
		return PROOF_STATE_TEMP_FAILURE
	}
}

type ProofErrorImpl struct {
	Status ProofStatus
	Desc   string
}

func NewProofError(s ProofStatus, d string, a ...interface{}) *ProofErrorImpl {
	return &ProofErrorImpl{s, fmt.Sprintf(d, a...)}
}

func (e *ProofErrorImpl) Error() string {
	return fmt.Sprintf("%s (code=%d)", e.Desc, int(e.Status))
}

func (e *ProofErrorImpl) GetStatus() ProofStatus { return e.Status }
func (e *ProofErrorImpl) GetDesc() string        { return e.Desc }

type ProofApiError struct {
	ProofErrorImpl
	url string
}

// Might be overkill, let's revisit...
//func (e *ProofApiError) Error() string {
//	return fmt.Sprintf("%s (url=%s; code=%d)", e.Desc, e.url, int(e.Status))
//}

func NewProofApiError(s ProofStatus, u string, d string, a ...interface{}) *ProofApiError {
	base := NewProofError(s, d, a...)
	return &ProofApiError{*base, u}
}

//=============================================================================

func XapiError(err error, u string) *ProofApiError {
	if ae, ok := err.(*ApiError); ok {
		var code ProofStatus = PROOF_NONE
		switch ae.Code / 100 {
		case 3:
			code = PROOF_HTTP_300
		case 4:
			code = PROOF_HTTP_400
		case 5:
			code = PROOF_HTTP_500
		default:
			code = PROOF_HTTP_OTHER
		}
		return NewProofApiError(code, u, ae.Msg)
	} else {
		return NewProofApiError(PROOF_INTERNAL_ERROR, u, err.Error())
	}
}

//=============================================================================

type FailedAssertionError struct {
	user string
	bad  []AssertionUrl
}

func (u FailedAssertionError) Error() string {
	v := make([]string, len(u.bad), len(u.bad))
	for i, u := range u.bad {
		v[i] = u.ToString()
	}
	return ("for " + u.user + ", the follow assertions failed: " +
		strings.Join(v, ", "))
}

//=============================================================================

type AssertionParseError struct {
	err string
}

func (e AssertionParseError) Error() string {
	return e.err
}

func NewAssertionParseError(s string, a ...interface{}) AssertionParseError {
	return AssertionParseError{
		err: fmt.Sprintf(s, a...),
	}
}

//=============================================================================

type NeedInputError struct {
	err string
}

func (e NeedInputError) Error() string {
	return e.err
}

func NewNeedInputError(s string, a ...interface{}) AssertionParseError {
	return AssertionParseError{
		err: fmt.Sprintf(s, a...),
	}
}

//=============================================================================

type WrongKidError struct {
	wanted, got KID
}

func (w WrongKidError) Error() string {
	return fmt.Sprintf("Wanted KID=%s; but got KID=%s", w.wanted.ToString(), w.got.ToString())
}

//=============================================================================

type WrongKeyError struct {
	wanted, got *PgpFingerprint
}

func (e WrongKeyError) Error() string {
	return fmt.Sprintf("Server gave wrong key; wanted %s; got %s",
		e.wanted.ToString(), e.got.ToString())
}

//=============================================================================

type UnexpectedKeyError struct {
}

func (e UnexpectedKeyError) Error() string {
	return "Found a key or fingerprint when one wasn't expected"
}

//=============================================================================

type UserNotFoundError struct {
	uid UID
	msg string
}

func (u UserNotFoundError) Error() string {
	return fmt.Sprintf("User %s wasn't found (%s)", u.uid.ToString(), u.msg)
}

//=============================================================================

type AlreadyRegisteredError struct {
	uid UID
}

func (u AlreadyRegisteredError) Error() string {
	return fmt.Sprintf("Already registered (with uid=%s)", u.uid.ToString())
}

//=============================================================================

type WrongSigError struct {
	b string
}

func (e WrongSigError) Error() string {
	return "Found wrong signature: " + e.b
}

type BadSigError struct {
	e string
}

func (e BadSigError) Error() string {
	return e.e
}

//=============================================================================

type NotFoundError struct {
	msg string
}

func (e NotFoundError) Error() string {
	return e.msg
}

//=============================================================================

type NoKeyError struct {
	msg string
}

func (u NoKeyError) Error() string {
	if len(u.msg) > 0 {
		return u.msg
	} else {
		return "No public key found"
	}
}

//=============================================================================

type NoSecretKeyError struct {
}

func (u NoSecretKeyError) Error() string {
	return "No secret key available"
}

//=============================================================================

type TooManyKeysError struct {
	n  int
	fp PgpFingerprint
}

func (e TooManyKeysError) Error() string {
	return fmt.Sprintf("Too many keys (%d) found for %s", e.n, e.fp.ToString())
}

//=============================================================================

type NoSelectedKeyError struct {
	wanted *PgpFingerprint
}

func (n NoSelectedKeyError) Error() string {
	return "Please login again to verify your public key"
}

//=============================================================================

type KeyExistsError struct {
	key *PgpFingerprint
}

func (k KeyExistsError) Error() string {
	return fmt.Sprintf("Key already exists for user (%s)", k.key.ToString())
}

//=============================================================================

type PassphraseError struct {
	msg string
}

func (p PassphraseError) Error() string {
	msg := "Bad passphrase"
	if len(p.msg) != 0 {
		msg = msg + ": " + p.msg
	}
	return msg
}

//=============================================================================

type BadKeyError struct {
	msg string
}

func (p BadKeyError) Error() string {
	msg := "Bad key found"
	if len(p.msg) != 0 {
		msg = msg + ": " + p.msg
	}
	return msg
}

//=============================================================================

type BadFingerprintError struct {
	fp1, fp2 PgpFingerprint
}

func (b BadFingerprintError) Error() string {
	return fmt.Sprintf("Got bad PGP key; fingerprint %s != %s",
		b.fp1.ToString(), b.fp2.ToString())
}

//=============================================================================

//=============================================================================

type AppStatusError struct {
	Code   int
	Name   string
	Desc   string
	Fields map[string]bool
}

func (a AppStatusError) IsBadField(s string) bool {
	ok, found := a.Fields[s]
	return ok && found
}

func NewAppStatusError(jw *jsonw.Wrapper) AppStatusError {
	code, _ := jw.AtKey("code").GetInt64()
	desc, _ := jw.AtKey("desc").GetString()
	name, _ := jw.AtKey("name").GetString()
	var tab map[string]bool
	v := jw.AtKey("fields")
	if l, err := v.Len(); err == nil {
		tab = make(map[string]bool)
		for i := 0; i < l; i++ {
			if f, err := v.AtIndex(i).GetString(); err == nil {
				tab[f] = true
			}
		}
	}
	return AppStatusError{
		Code:   int(code),
		Name:   name,
		Desc:   desc,
		Fields: tab,
	}
}

func (a AppStatusError) Error() string {
	v := make([]string, len(a.Fields))
	i := 0

	for k, _ := range a.Fields {
		v[i] = k
		i++
	}

	fields := ""
	if i > 0 {
		fields = fmt.Sprintf(" (bad fields: %s)", strings.Join(v, ","))
	}

	return fmt.Sprintf("Failure from server: %s%s (error %d)", a.Desc, fields, a.Code)
}

//=============================================================================

type GpgError struct {
	m string
}

func (e GpgError) Error() string {
	return fmt.Sprintf("GPG error: %s", e.m)
}

func ErrorToGpgError(e error) GpgError {
	return GpgError{e.Error()}
}

type GpgIndexError struct {
	lineno int
	m      string
}

func (e GpgIndexError) Error() string {
	return fmt.Sprintf("GPG index error at line %d: %s", e.lineno, e.m)
}

func ErrorToGpgIndexError(l int, e error) GpgIndexError {
	return GpgIndexError{l, e.Error()}
}

//=============================================================================

type LoginRequiredError struct {
}

func (e LoginRequiredError) Error() string {
	return "Login required"
}

//=============================================================================

type InternalError struct {
	msg string
}

func (e InternalError) Error() string {
	return fmt.Sprintf("Internal error: %s", e.msg)
}

//=============================================================================

type ServerChainError struct {
	msg string
}

func (e ServerChainError) Error() string {
	return e.msg
}

func NewServerChainError(d string, a ...interface{}) ServerChainError {
	return ServerChainError{fmt.Sprintf(d, a...)}
}

//=============================================================================

type WaitForItError struct{}

func (e WaitForItError) Error() string {
	return "It is advised you 'wait for it'"
}

//=============================================================================

type InsufficientKarmaError struct {
	un string
}

func (e InsufficientKarmaError) Error() string {
	return "Bad karma"
}

//=============================================================================

type InvalidHostnameError struct {
	h string
}

func (e InvalidHostnameError) Error() string {
	return "Invalid hostname: " + e.h
}

//=============================================================================

type WebUnreachableError struct {
	h string
}

func (h WebUnreachableError) Error() string {
	return "Host " + h.h + " is down; tried both HTTPS and HTTP protocols"
}

//=============================================================================

type ProtocolDowngradeError struct {
	msg string
}

func (h ProtocolDowngradeError) Error() string {
	return h.msg
}

//=============================================================================

type BadUsernameError struct {
	n string
}

func (e BadUsernameError) Error() string {
	return "Bad username: '" + e.n + "'"
}

//=============================================================================

type NoUsernameError struct{}

func (e NoUsernameError) Error() string {
	return "No username known"
}

//=============================================================================

type UnmarshalError struct {
	t string
}

func (u UnmarshalError) Error() string {
	return "Bad " + u.t + " packet"
}

type VerificationError struct{}

func (v VerificationError) Error() string {
	return "Verification failed"
}

//=============================================================================

type NoKeyringsError struct{}

func (k NoKeyringsError) Error() string {
	return "No keyrings available"
}

//=============================================================================

type KeyCannotSignError struct{}

func (s KeyCannotSignError) Error() string {
	return "Key cannot create signatures"
}

type KeyCannotVerifyError struct{}

func (k KeyCannotVerifyError) Error() string {
	return "Key cannot verify signatures"
}

//=============================================================================

type NoConfigFile struct{}

func (n NoConfigFile) Error() string {
	return "No configuration file available"
}

//=============================================================================

type SelfTrackError struct{}

func (e SelfTrackError) Error() string {
	return "Cannot track yourself"
}

//=============================================================================

type NoUiError struct {
	which string
}

func (e NoUiError) Error() string {
	return fmt.Sprintf("no %s-UI was available", e.which)
}

//=============================================================================

type NoConfigWriterError struct{}

func (e NoConfigWriterError) Error() string {
	return "Can't write; no ConfigWriter available"
}

//=============================================================================

type BadServiceError struct {
	n string
}

func (e BadServiceError) Error() string {
	return e.n + ": unsupported service"
}

//=============================================================================

type NotConfirmedError struct{}

func (e NotConfirmedError) Error() string {
	return "Not confirmed"
}

//=============================================================================

type ProofNotYetAvailableError struct{}

func (e ProofNotYetAvailableError) Error() string {
	return "Proof wasn't available; we'll keep trying"
}

//=============================================================================

type KeyGenError struct {
	msg string
}

func (e KeyGenError) Error() string {
	return fmt.Sprintf("KeyGen error: %s", e.msg)
}

//=============================================================================

type KeyFamilyError struct {
	msg string
}

func (e KeyFamilyError) Error() string {
	return fmt.Sprintf("Bad key family: %s", e.msg)
}

//=============================================================================

type BadRevocationError struct {
	msg string
}

func (e BadRevocationError) Error() string {
	return fmt.Sprintf("Bad revocation: %s", e.msg)
}

//=============================================================================
