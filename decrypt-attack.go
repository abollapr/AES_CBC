// decrypt-attack
package main

import (
	"crypto/aes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

func decryption_oracle(ciphertext []byte) string {

	err := ioutil.WriteFile("output.txt", ciphertext, 0644)
	if err != nil {
		fmt.Println("Can't write to file:", os.Args[7])
		panic(err)
	}

	result, _ := exec.Command("./decrypt-test.exe").Output()

	result_str := string(result)
	return result_str
}

func find_padding(ciphertext_11 []byte, IV []byte) int {

	count := 0
	for i := len(ciphertext_11) - 32; i < len(ciphertext_11)-16; i++ {
		ciphertext_11[i] = byte(0)

		error_returned := decryption_oracle(ciphertext_11)
		if strings.Compare(error_returned, "INVALID PADDING\n") == 0 {
			count += 1
		}

	}
	return count
}

func round_off_number_of_blocks(ciphertext_of_interest []byte) int {
	round_off_blocks := 0
	if len(ciphertext_of_interest)%16 == 0 {
		round_off_blocks = len(ciphertext_of_interest) / 16
	} else {
		for i := 1; i < 16; i++ {
			Reminder := (len(ciphertext_of_interest) + i) % 16
			if Reminder == 0 {
				round_off_blocks = (len(ciphertext_of_interest) + i) / 16
			}
		}
	}

	return round_off_blocks

}

func attack(ciphertext []byte, pad_number int, modify_IV_position int, final_return_value []byte) []byte {
	if len(final_return_value) == 16 {
		return final_return_value
	}

	moving_i := len(ciphertext) - 16
	moving_j := len(ciphertext)
	var ciphertext_with_change_IV []byte
	var prev_block []byte
	if len(ciphertext) >= 32 { // To check if the left out number of blocks left to decrypt are a minimum of 2 (1 block IV + 1 block M)
		//Setting the IV to the previous block
		for modify_IV_position := 1; modify_IV_position <= pad_number; modify_IV_position++ {
			if modify_IV_position == pad_number {
				for i := 0; i < 256; i++ {

					// Setting the IV to the previous block. If the Pad number is greater than 0, take the IV from the ciphertext_with_change_IV
					if pad_number != 1 {
						prev_block = ciphertext_with_change_IV[len(ciphertext_with_change_IV)-32 : len(ciphertext_with_change_IV)-16]

					} else {
						prev_block = ciphertext[moving_i-16 : moving_j-16] // Is for loop required here?!! Check values
					}

					// IV is being created here and contents from prev_block are copied.
					IV := make([]byte, 16)
					for k := 0; k < 16; k++ {
						IV[k] = prev_block[k]
					}

					IV[len(IV)-modify_IV_position] = byte(int(IV[len(IV)-modify_IV_position]) ^ i ^ pad_number)

					final_ciphertext := make([]byte, len(IV))
					for i := 0; i < len(IV); i++ {
						final_ciphertext[i] = IV[i]
					}

					final_ciphertext = append(final_ciphertext, ciphertext[moving_i:moving_j]...)

					return_error_1 := decryption_oracle(final_ciphertext)

					if strings.Compare(string(return_error_1), "INVALID HMAC\n") == 0 {
						final_return_value = append(final_return_value, byte(i)) //storing the final result = guess
						break
					}
				}
			} else {
				if modify_IV_position == 1 {
					prev_block = ciphertext[moving_i-16 : moving_j-16]
				} else {
					prev_block = ciphertext_with_change_IV[len(ciphertext_with_change_IV)-32 : len(ciphertext_with_change_IV)-16]
				}
				IV := make([]byte, 16)
				for k := 0; k < 16; k++ {
					IV[k] = prev_block[k]
				}

				x := final_return_value[modify_IV_position-1] ^ IV[len(IV)-modify_IV_position]
				y := byte(pad_number) ^ x

				IV[len(IV)-modify_IV_position] = y

				ciphertext_with_change_IV_1 := make([]byte, aes.BlockSize)
				for i := 0; i < aes.BlockSize; i++ {
					ciphertext_with_change_IV_1[i] = IV[i]
				}
				ciphertext_with_change_IV = ciphertext_with_change_IV_1
				ciphertext_with_change_IV = append(ciphertext_with_change_IV, ciphertext[moving_i:moving_j]...)

			}
		}
		pad_number += 1
	}
	return attack(ciphertext, pad_number, 1, final_return_value)
}

func main() {
	//temp := []byte("1111111111111111")
	//kenc := temp
	//kmac := temp
	var final_plain_Text []byte
	//fmt.Println("kenc is", kenc)
	//fmt.Println("kmac is", kmac)

	ciphertext, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("Can't read file:", os.Args[1])
		panic(err)
	}

	modifiable_ciphertext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		modifiable_ciphertext[i] = ciphertext[i]
	}

	IV := ciphertext[:16]
	return_find_padding := find_padding(modifiable_ciphertext, IV)
	ciphertext_of_interest := modifiable_ciphertext[:len(modifiable_ciphertext)-(return_find_padding+32)]
	number_of_blocks := round_off_number_of_blocks(ciphertext_of_interest)
	blocks_to_be_broken := ciphertext[:16*number_of_blocks]
	strip := 0
	for i := 1; i < number_of_blocks; i++ {
		var final_decrypted_test []byte
		final_plain_Text = append(final_plain_Text, attack(blocks_to_be_broken[:len(blocks_to_be_broken)-strip], 1, 1, final_decrypted_test)...)
		strip += 16

	}
	fmt.Println("The final value in reverse is", final_plain_Text)

}
