package CLKeygen

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/xlcetc/cryptogm/sm/sm9"
	"log"
	"math/big"
	"time"
)

var Default_id = []byte("mydawn@gmail.com")

type MSG struct {
	Priv     *sm2.PrivateKey
	Mk       *sm9.MasterPubKey
	Cipher   []byte
	Sm2sign  []byte
	Sm9sign  *sm9.Sm9Sig
	Tstamp   time.Time
	TranTime time.Time
}

//create new curve and kgc parameters
func Setup() (*sm2.PrivateKey, *sm2.PublicKey, elliptic.Curve, error) {
	s, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	p_kgc := &s.PublicKey
	c := p_kgc.Curve
	return s, p_kgc, c, err
}

func SetUserKey() (*sm2.PrivateKey, *sm2.PublicKey, error) {
	x_A, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	U_A := &x_A.PublicKey
	return x_A, U_A, err
}

func ExtractParticialKey(uid []byte, s *sm2.PrivateKey, p_kgc, U_A *sm2.PublicKey) (*sm2.PublicKey, *big.Int, error) {
	c := U_A.Curve
	N := c.Params().N
	za, err := sm2.ZA(p_kgc, uid)
	if err != nil {
		log.Fatal(err)
	}
	w, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	X := &w.PublicKey
	W_x, W_y := c.Add(U_A.X, U_A.Y, X.X, X.Y)
	W := &sm2.PublicKey{c, W_x, W_y}
	lam := sm3.New()
	lam.Write(W.X.Bytes())
	lam.Write(W.Y.Bytes())
	lam.Write(za)
	lamda := new(big.Int).SetBytes(lam.Sum(nil)[:32])
	l := new(big.Int).Mul(lamda, s.D)
	t := new(big.Int).Add(l, w.D)
	t.Mod(t, N)
	return W, t, err
}

func SetPrivateKey(x_A *sm2.PrivateKey, t *big.Int) (*sm2.PrivateKey, error) {
	c := x_A.PublicKey.Curve
	d := new(big.Int).Add(x_A.D, t)
	d.Mod(d, c.Params().N)
	d_A := new(sm2.PrivateKey)
	d_A.D = d
	d_A.PublicKey.Curve = c
	d_A.PublicKey.X, d_A.PublicKey.Y = c.ScalarBaseMult(d.Bytes())
	return d_A, nil
}

func CalculatePublicKey(pk, p_kgc *sm2.PublicKey, uid []byte) (*sm2.PublicKey, error) {
	za, err := sm2.ZA(p_kgc, uid)
	if err != nil {
		log.Fatal(err)
	}
	lam := sm3.New()
	lam.Write(pk.X.Bytes())
	lam.Write(pk.Y.Bytes())
	lam.Write(za)
	lamda := new(big.Int).SetBytes(lam.Sum(nil)[:32])
	O := new(sm2.PublicKey)
	O.Curve = pk.Curve
	O.X, O.Y = O.Curve.ScalarMult(p_kgc.X, p_kgc.Y, lamda.Bytes())
	return O, err
}

/* verify new O_A,need ECC minus algorithm

func verifyKey(p_kgc,pk *sm2.PublicKey, s *sm2.PrivateKey, uid []byte)  {
	za,err := sm2.ZA(p_kgc,uid)
	if err != nil {
		log.Fatal(err)
	}
	lam :=sm3.New()
	lam.Write(pk.X.Bytes())
	lam.Write(pk.Y.Bytes())
	lam.Write(za)
	lamda :=new(big.Int).SetBytes(lam.Sum(nil)[:32])

}
*/
/*
func main()  {
	s,p_kgc,_,err := Setup()
	if err != nil {
		log.Fatal(err)
	}
	x_A,U_A,err := SetUserKey()
	if err != nil {
		log.Fatal(err)
	}
	_,t,err := ExtractParticialKey(default_id, s, p_kgc, U_A)
	if err != nil {
		log.Fatal(err)
	}
	d_A,err := SetPrivateKey(x_A, t)
	if err != nil {
		log.Fatal(err)
	}
	//O_A,err := CalculatePublicKey(W, p_kgc,default_id)
	if err != nil {
		log.Fatal(err)
	}
	msg := []byte("certlessKey demo")
	fmt.Printf("MSG:%x\n",msg)
	ciphertxt, err := d_A.PublicKey.EncryptAsn1(msg,rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("加密结果:%x\n",ciphertxt)
	plaintxt,err :=  d_A.DecryptAsn1(ciphertxt)  //sm2解密
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(msg,plaintxt){
		log.Fatal("原文不匹配")
	}
	fmt.Printf("RESULT:%x\n",string(plaintxt))
}
*/
