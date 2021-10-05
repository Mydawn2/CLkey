package main

import (
	. "CLkey/CLKeygen"
	. "CLkey/lib"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	//"github.com/xlcetc/cryptogm/sm/sm9"
	"log"
	"strconv"
	"time"
)

var letters = []byte("abcdefghjkmnpqrstuvwxyz123456789")
var longLetters = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ=_")

func RandUp(n int) []byte {
	if n <= 0 {
		return []byte{}
	}
	b := make([]byte, n)
	arc := uint8(0)
	if _, err := rand.Read(b[:]); err != nil {
		return []byte{}
	}
	for i, x := range b {
		arc = x & 63
		b[i] = longLetters[arc]
	}
	return b
}

func client(ip string) error {
	/*cpData := ComplexData{
		N: 10,
		S: "测试string 数据",
		M: map[string]int{"A": 1, "B": 2},
		P: []byte("测试[]byte数据"),
		C: &ComplexData{
			N: 256,
			S: "Recursive structs? Piece of cake!",
			M: map[string]int{"01": 1, "10": 2, "11": 3},
		},
	}*/
	gob.Register(sm2.P256Sm2())
	//gob.Register(sm9.)
	//generate SM9 parameters
	//mk, _ := sm9.MasterKeyGen(rand.Reader)
	//id := []byte("Alice")
	//hid := 3
	//uk, _ := sm9.UserKeyGen(mk, id, byte(hid))
	//build CertlessKey
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
	msg := RandUp(512)
	for i := 0; i < 100; i++ {
		start := time.Now()
		ciphertxt, err := d_A.PublicKey.EncryptAsn1(msg, rand.Reader)
		sign2_txt, err := d_A.Sign(rand.Reader, msg, nil)
		//sign9_txt, err := sm9.Sign(uk, &mk.MasterPubKey, ciphertxt)
		testmsg := MSG{
			Priv: d_A,
			//Mk:       &mk.MasterPubKey,
			Cipher:  ciphertxt,
			Sm2sign: sign2_txt,
			//Sm9sign:  sign9_txt,
			Tstamp:   start,
			TranTime: time.Now(),
		}
		rw, err := Open(ip + Port)
		if err != nil {
			fmt.Println("客户端无法链接改地址：" + ip + Port)
			return err
		}
		n, err := rw.WriteString("string\n")
		if err != nil {
			return errors.Wrap(err, "Could not send the STRING request ("+strconv.Itoa(n)+" bytes written)")
		}
		n, err = rw.WriteString("Additional data.\n")
		if err != nil {
			return errors.Wrap(err, "Could not send additional STRING data ("+strconv.Itoa(n)+" bytes written)")
		}
		err = rw.Flush()
		if err != nil {
			return errors.Wrap(err, "Flush failed.")
		}

		// Read the reply.
		response, err := rw.ReadString('\n')
		if err != nil {
			return errors.Wrap(err, "Client: Failed to read the reply: '"+response+"'")
		}

		log.Println("STRING request: got a response:", response)

		log.Println("Send a struct as GOB:")
		//log.Printf("Outer complexData struct: \n%#v\n", testmsg.Priv.D)
		//log.Printf("Inner complexData struct: \n%#v\n", testmsg.Cipher)
		enc := gob.NewEncoder(rw)
		n, err = rw.WriteString("gob\n")
		if err != nil {
			return errors.Wrap(err, "Could not write GOB data ("+strconv.Itoa(n)+" bytes written)")
		}
		err = enc.Encode(testmsg)
		if err != nil {
			return errors.Wrapf(err, "Encode failed for struct: %#v", testmsg)
		}
		//elapse := time.Since(start)
		//fmt.Println("该函数执行完成耗时：", elapse)
		err = rw.Flush()
		if err != nil {
			return errors.Wrap(err, "Flush failed.")
		}

	}
	return nil
}

func main() {
	err := client("localhost")
	if err != nil {
		fmt.Println("Error:", errors.WithStack(err))
	}
}
