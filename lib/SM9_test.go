package lib

import (
	"crypto/rand"
	"github.com/xlcetc/cryptogm/sm/sm9"
	"testing"
)

func TestSign(t *testing.T) {
	mk, err := sm9.MasterKeyGen(rand.Reader)
	if err != nil {
		t.Errorf("mk gen failed:%s", err)
		return
	}

	var hid byte = 1

	var uid = []byte("Alice")

	uk, err := sm9.UserKeyGen(mk, uid, hid)
	if err != nil {
		t.Errorf("uk gen failed:%s", err)
		return
	}

	msg := []byte("message")

	sig, err := sm9.Sign(uk, &mk.MasterPubKey, msg)
	if err != nil {
		t.Errorf("sm9 sign failed:%s", err)
		return
	}

	if !sm9.Verify(sig, msg, uid, hid, &mk.MasterPubKey) {
		t.Error("sm9 sig is invalid")
		return
	}
}
