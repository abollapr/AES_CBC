// AES
package main

import "fmt"
import "log"
import "os"
import "encoding/hex"
import "crypto/sha256"
import "math"
import "crypto/rand"

//import "crypto/rand"
//import "crypto/aes"
//import "flag"
//import "io/ioutil"

func gen_hmac(message, key []byte) [32]byte {
	//fmt.Println(key)
	var c byte = 00
	for i := 16; i < 64; i++ {
		key = append(key, c)
	}
	//fmt.Println(key)

	var opad []byte
	for i := 0; i < 64; i++ {
		opad = append(opad, 92)
	}

	var ipad []byte
	for i := 0; i < 64; i++ {
		ipad = append(ipad, 54)
	}
	o_key_pad := make([]byte, 64)
	i_key_pad := make([]byte, 64)

	for i := 0; i < 64; i++ {
		o_key_pad[i] = key[i] ^ opad[i]
		i_key_pad[i] = key[i] ^ ipad[i]
	}

	//fmt.Println(i_key_pad)
	//var second_message []byte
	//i_key_pad = append(i_key_pad, message...)
	//fmt.Println(message)
	//fmt.Println(i_key_pad)

	//h := sha256.New()
	//h.Write(i_key_pad)
	//fmt.Printf("%x", h.Sum(nil))
	hash1 := sha256.Sum256(i_key_pad)
	o_key_pad = append(o_key_pad, hash1[:]...)

	//k := sha256.New()
	//k.Write(o_key_pad)
	//return k.Sum256(nil)
	hash2 := sha256.Sum256(o_key_pad)
	return hash2

}

func compute_padding(message []byte) []byte {
	fmt.Println(message)
	fmt.Println(len(string(message)))
	n := len(string(message)) % 16
	fmt.Println("The value if n is", n)
	PS := 16 - n
	var padding []byte
	var buf [8]byte //Assuming that the
	padding_variable := math.Pow(float64(PS), 2)
	fmt.Println("The padding variabe is", padding_variable)
	fmt.Println("The buf is", buf)
	if n != 0 {
		for i := 0; i < PS; i++ {
			padding = append(padding, byte(padding_variable))
		}
	}
	//	else {
	//		for i := 0; i <16; i++ {
	//			padding = append(padding, 16...)
	//		}
	//	}
	return padding
}

func aes_cbc_encrypt(message []byte) (string, error) {
	bytes := make([]byte, 64)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func encrypt_mac(message []byte, token [32]byte) []byte {
	var M_1 []byte
	token_slice := token[:]
	M_1 = append(message, token_slice...)
	fmt.Println("M_1 is", M_1)
	//returnstr := compute_padding(M_1)
	M_1 = append(M_1, compute_padding(M_1)...)
	encrypted_cipher, _ := aes_cbc_encrypt(M_1)
	fmt.Println(encrypted_cipher)

	return M_1

}

func readNextBytes(file *os.File, number int) []byte {
	bytes := make([]byte, number)

	_, err := file.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}

	return bytes
}

func main() {
	//if len(os.Args[1]) < 32 {

	//decoded := []byte(os.Args[1])
	s := os.Args[1]

	decoded, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println(decoded)

	//kenc := decoded[:16]
	kmac := decoded[16:]

	//fmt.Println(kmac)

	//data_message, err_message := ioutil.ReadFile(os.Args[2])
	//data_message_1 := []byte(data_message)
	//fmt.Println(err_message)

	file, err := os.Open(os.Args[2])
	//input_file := os.Args[2]
	formatName := readNextBytes(file, 9)
	fmt.Println(err)

	returnstr := gen_hmac(formatName, kmac)
	fmt.Printf("HMAC is %x", returnstr)
	fmt.Printf("\n")

	return_encrypt_mac := encrypt_mac(formatName, returnstr)
	fmt.Println(return_encrypt_mac)
	//fmt.Println("\nAnswer:", hex.EncodeToString(returnstr[:]))
	//fmt.Println(formatName)
}
