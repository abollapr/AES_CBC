// AES
package main

import "fmt"
import "os"
import "crypto/sha256"
import "crypto/rand"
import "crypto/aes"
import "reflect"
import "io/ioutil"

func gen_hmac(message, key []byte) []byte {
	//fmt.Println(key)
	var c byte = 00
	for i := 16; i < 64; i++ {
		key = append(key, c)
	}
	fmt.Println("Key is", key)

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

	fmt.Println("O key pad", o_key_pad)
	i_key_pad = append(i_key_pad, message...)
	fmt.Println("length of i key pad", len(i_key_pad))

	hash1 := sha256.Sum256(i_key_pad)
	fmt.Println("Hash 1 is", hash1)
	o_key_pad = append(o_key_pad, hash1[:]...)

	fmt.Println("o_key_pad + hash1", o_key_pad)
	hash2 := sha256.Sum256(o_key_pad)
	fmt.Println("hash 2 is", hash2)
	return hash2[:]

}

func compute_padding(message []byte) []byte {
	n := len(string(message)) % 16
	PS := 16 - n
	var padding []byte
	if n != 0 {
		for i := 0; i < PS; i++ {
			padding = append(padding, byte(PS))
		}
	} else {
		for i := 0; i < 16; i++ {
			padding = append(padding, 16)
		}
	}
	fmt.Println("Padding is", padding)
	return padding
}

func generate_IV(message []byte) ([]byte, error) {
	bytes := make([]byte, 16)
	var None []byte
	if _, err := rand.Read(bytes); err != nil {
		return None, err
	}
	return bytes, nil
}

func decrypt_mac(ciphertext []byte, kenc []byte) []byte {
	number_of_blocks_decrypt := len(ciphertext) / 16
	var final_decrypted_cipher []byte
	count := 1
	moving_i := 16
	moving_j := 32
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

func encrypt_mac(message []byte, token []byte, kenc []byte) []byte {
	var M_1 []byte
	token_slice := token[:]
	M_1 = append(message, token_slice...)
	//fmt.Println("M_1 is", M_1)
	//returnstr := compute_padding(M_1)
	padded_message := append(M_1, compute_padding(M_1)...)

	IV := []byte("1111111111111111")
	IV_with_final_encrypted_cipher := IV

	fmt.Println("IV is:", IV)

	//IV, _ := generate_IV(M_1)

	fmt.Println("the padded message is", padded_message)

	number_of_blocks := len(padded_message) / 16
	var final_encrypted_cipher []byte
	count := 0
	moving_i := 0
	moving_j := 16

	final_encrypted_cipher = encrypt_CBC(IV, padded_message, final_encrypted_cipher, kenc, number_of_blocks, count, moving_i, moving_j)
	IV_with_final_encrypted_cipher = append(IV_with_final_encrypted_cipher, final_encrypted_cipher...)
	return IV_with_final_encrypted_cipher
}

func encrypt_CBC(IV []byte, padded_message []byte, final_encrypted_cipher []byte, kenc []byte, number_of_blocks int, count int, moving_i int, moving_j int) []byte {
	cipher_1 := make([]byte, 16)
	cipher_11 := make([]byte, 16)

	var None []byte
	block, err := aes.NewCipher(kenc)
	if err != nil {
		return None
	}
	if count < number_of_blocks {
		k := 0
		for j := moving_i; j < moving_j; j++ {
			cipher_1[k] = padded_message[j] ^ IV[k]
			k += 1
		}
		block.Encrypt(cipher_11, cipher_1)
		final_encrypted_cipher = append(final_encrypted_cipher, cipher_11...)

		IV = cipher_11
		count += 1
		moving_i += 16
		moving_j += 16

		return encrypt_CBC(IV, padded_message, final_encrypted_cipher, kenc, number_of_blocks, count, moving_i, moving_j)
	} else {
		return final_encrypted_cipher
	}
}

func verify_hmac_padding(ciphertext []byte, kmac []byte) (string, []byte) {
	//padding_int := byte(32)
	padding_int := ciphertext[len(ciphertext)-1]
	var None []byte
	for j := len(ciphertext) - 1; j > len(ciphertext)-(int(padding_int)+1); j-- {
		if ciphertext[j] != padding_int {
			return "INVALID PADDING", None
		}
	}
	var HMAC []byte

	HMAC = ciphertext[len(ciphertext)-(int(padding_int)+32) : len(ciphertext)-int(padding_int)]
	to_be_verified_HMAC := gen_hmac(ciphertext[:len(ciphertext)-(int(padding_int)+32)], kmac)
	HMAC_validation := reflect.DeepEqual(HMAC, to_be_verified_HMAC)
	if HMAC_validation != true {
		return "INVALID HMAC", None
	}
	return "Success!", ciphertext[:len(ciphertext)-(int(padding_int)+32)]

}

func main() {
	//if len(os.Args[1]) < 32 {

	//decoded := []byte(os.Args[1])
	//	s := os.Args[1]

	//	decoded, err := hex.DecodeString(s)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	//fmt.Println(decoded)

	//	kenc := decoded[:16]
	//	kmac := decoded[16:]

	//------JUGAAD---
	temp := []byte("1111111111111111")
	kenc := temp
	kmac := temp

	fmt.Println("kenc is", kenc)
	fmt.Println("kmac is", kmac)

	//fmt.Println(kmac)

	formatName, err := ioutil.ReadFile(os.Args[2])
	if err != nil {
		fmt.Println("Can't read file:", os.Args[2])
		panic(err)
	}

	fmt.Println("Plaintext is", formatName)

	returnstr := gen_hmac(formatName, kmac)
	fmt.Println("HMAC is ", returnstr)

	return_encrypt_mac := encrypt_mac(formatName, returnstr, kenc)
	fmt.Println("Final Encrypted Value is", return_encrypt_mac)

	err = ioutil.WriteFile(os.Args[3], return_encrypt_mac, 0644)
	if err != nil {
		fmt.Println("Can't write to file:", os.Args[7])
		panic(err)

	}

	return_decrypt_mac := decrypt_mac(return_encrypt_mac, kenc)
	fmt.Println("The lenght of Decrypted value is", return_decrypt_mac)

	error_verify, text := verify_hmac_padding(return_decrypt_mac, kmac)
	if error_verify == "Success!" {
		fmt.Printf("%s", text)
	} else {
		fmt.Println(error_verify)
	}
}
