package CLKeygen

import (
	"crypto/rand"
	"log"
	"testing"
)

func BenchmarkEncrypt(b *testing.B) {
	s, p_kgc, _, err := Setup()
	if err != nil {
		log.Fatal(err)
	}
	x_A, U_A, err := SetUserKey()
	if err != nil {
		log.Fatal(err)
	}
	_, t, err := ExtractParticialKey(Default_id, s, p_kgc, U_A)
	if err != nil {
		log.Fatal(err)
	}
	d_A, err := SetPrivateKey(x_A, t)
	if err != nil {
		log.Fatal(err)
	}
	msg := []byte("message test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d_A.PublicKey.EncryptAsn1(msg, rand.Reader)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	s, p_kgc, _, err := Setup()
	if err != nil {
		log.Fatal(err)
	}
	x_A, U_A, err := SetUserKey()
	if err != nil {
		log.Fatal(err)
	}
	_, t, err := ExtractParticialKey(Default_id, s, p_kgc, U_A)
	if err != nil {
		log.Fatal(err)
	}
	d_A, err := SetPrivateKey(x_A, t)
	if err != nil {
		log.Fatal(err)
	}
	msg := []byte("message test")
	cipher, _ := d_A.PublicKey.EncryptAsn1(msg, rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d_A.DecryptAsn1(cipher)
	}
}
