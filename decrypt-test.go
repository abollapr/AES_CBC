// decrypt-test
package main

import "fmt"

import "os"
import "crypto/sha256"
import "crypto/aes"
import "reflect"

import "io/ioutil"

func gen_hmac(message, key []byte) []byte {
	//fmt.Println(key)
	var c byte = 00
	for i := 16; i < 64; i++ {
		key = append(key, c)
	}
	//fmt.Println("Key is", key)

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

	//fmt.Println("O key pad", o_key_pad)
	i_key_pad = append(i_key_pad, message...)
	//fmt.Println("length of i key pad", len(i_key_pad))

	hash1 := sha256.Sum256(i_key_pad)
	//fmt.Println("Hash 1 is", hash1)
	o_key_pad = append(o_key_pad, hash1[:]...)

	//fmt.Println("o_key_pad + hash1", o_key_pad)
	hash2 := sha256.Sum256(o_key_pad)
	//fmt.Println("hash 2 is", hash2)
	return hash2[:]

}

func decrypt_mac(ciphertext []byte, kenc []byte) []byte {
	number_of_blocks_decrypt := len(ciphertext) / 16
	var final_decrypted_cipher []byte
	count := 0
	moving_i := 0
	moving_j := 16
	//TO DO: HAVE TO PASS THE IV PARAMETER IN THE FUNCTION. HARDCODING IT FOR NOW.
	IV := []byte("1111111111111111")
	final_decrypted_cipher = decrypt_CBC(IV, ciphertext, final_decrypted_cipher, kenc, number_of_blocks_decrypt, count, moving_i, moving_j)
	return final_decrypted_cipher
}

func decrypt_CBC(IV []byte, ciphertext []byte, final_decrypted_cipher []byte, kenc []byte, number_of_blocks int, count int, moving_i int, moving_j int) []byte {
	decipher_1 := make([]byte, 16)
	decipher_11 := make([]byte, 16)

	var None []byte
	block, err := aes.NewCipher(kenc)
	if err != nil {
		return None
	}
	if count < number_of_blocks {
		block.Decrypt(decipher_11, ciphertext[moving_i:moving_j])
		for k := 0; k < 16; k++ {
			decipher_1[k] = IV[k] ^ decipher_11[k]
		}
		IV = ciphertext[moving_i:moving_j]
		moving_i += 16
		moving_j += 16

		final_decrypted_cipher = append(final_decrypted_cipher, decipher_1...)
		count += 1

		return decrypt_CBC(IV, ciphertext, final_decrypted_cipher, kenc, number_of_blocks, count, moving_i, moving_j)
	} else {
		return final_decrypted_cipher
	}
}

func verify_hmac_padding(ciphertext []byte, kmac []byte) string {
	//padding_int := byte(32)
	padding_int := ciphertext[len(ciphertext)-1]
	for j := len(ciphertext) - 1; j > len(ciphertext)-(int(padding_int)+1); j-- {
		if ciphertext[j] != padding_int {
			return "INVALID PADDING"
		}
	}
	var HMAC []byte
	HMAC = ciphertext[len(ciphertext)-(int(padding_int)+32) : len(ciphertext)-int(padding_int)]
	to_be_verified_HMAC := gen_hmac(ciphertext[16:len(ciphertext)-(int(padding_int)+32)], kmac)
	HMAC_validation := reflect.DeepEqual(HMAC, to_be_verified_HMAC)
	if HMAC_validation != true {
		return "INVALID HMAC"
	}
	return "Success!"

}

func main() {

	ciphertext, _ := os.Open("output.txt")
	formatName, _ := ioutil.ReadAll(ciphertext)
	//fmt.Println("Format name is", formatName)

	//formatName, err := ioutil.ReadFile(ciphertext)
	//if err != nil {
	//fmt.Println("Can't read file:", os.Args[2])
	//panic(err)
	//}

	kenc := []byte("1111111111111111")
	return_decrypt_mac := decrypt_mac(formatName, kenc)
	//fmt.Println("The Decrypted value is", return_decrypt_mac)

	error_verify := verify_hmac_padding(return_decrypt_mac, kenc)
	if error_verify == "Success!" {
		fmt.Println(error_verify)
	} else {
		fmt.Println(error_verify)
	}

}
