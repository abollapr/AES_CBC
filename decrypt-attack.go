// decrypt-attack
package main

import (
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

	//	if err_cmd != nil {
	//		fmt.Println("ERROR: ", err_cmd)
	//		os.Exit(1)
	//	}
	result_str := string(result)
	//fmt.Println("Return Result", result_str)
	return result_str
}

func find_padding(ciphertext_11 []byte, IV []byte) int {
	fmt.Println("yo")

	//length_ciphertext := len(ciphertext_11)

	count := 0
	for i := len(ciphertext_11) - 32; i < len(ciphertext_11)-16; i++ {
		ciphertext_11[i] = byte(0)
		//fmt.Println(ciphertext_11)

		error_returned := decryption_oracle(ciphertext_11)
		fmt.Println("Error returned by the decryption oracle is", error_returned)
		if strings.Compare(string(error_returned), "INVALID PADDING") == 1 {
			count += 1
			fmt.Println("Count is", count)

		}

	}
	return count
}

func round_off_number_of_blocks(ciphertext_of_interest []byte) int {
	round_off_blocks := 0
	if len(ciphertext_of_interest)%16 == 0 {
		fmt.Println("hahah")
		round_off_blocks = len(ciphertext_of_interest) / 16
	} else {
		for i := 1; i < 16; i++ {
			fmt.Println("Added length", len(ciphertext_of_interest)+i)
			Reminder := (len(ciphertext_of_interest) + i) % 16
			if Reminder == 0 {
				fmt.Println("i", i)
				round_off_blocks = (len(ciphertext_of_interest) + i) / 16
			}
		}
	}

	return round_off_blocks

}

func attack(ciphertext []byte, number_of_blocks int, pad_number int, modify_IV_position int, final_return_value []byte) []byte {
	moving_i := len(ciphertext) - 16
	moving_j := len(ciphertext)
	//	if blocks_left == 2{
	//		IV := ciphertext[:16]
	//	} else {

	//	}
	//return IV
	if len(ciphertext) >= 32 { // To check if the left out number of blocks left to decrypt are a minimum of 2 (1 block IV + 1 block M)

		//Setting the IV to the previous block
		if modify_IV_position <= pad_number {
			if modify_IV_position == pad_number {
				for i := 0; i < 256; i++ {
					prev_block := ciphertext[moving_i-16 : moving_j-16]
					IV := make([]byte, 16)
					for k := 0; k < 16; k++ {
						IV[k] = prev_block[k]
					}
					fmt.Println("IV before modification is", IV)
					fmt.Println("The modified_IV_position is", modify_IV_position)
					fmt.Println("The last byte should now be", int(IV[len(IV)-modify_IV_position])^i^pad_number)
					fmt.Println("I is", i)

					IV[len(IV)-modify_IV_position] = byte(int(IV[len(IV)-modify_IV_position]) ^ i ^ pad_number)
					fmt.Println("IV is", IV)

					ciphertext_to_be_sent := IV
					ciphertext_to_be_sent = append(ciphertext_to_be_sent, ciphertext[moving_i:moving_j]...)
					fmt.Println("Ciphertext tbs:", ciphertext_to_be_sent)

					return_error := decryption_oracle(ciphertext_to_be_sent)
					//					if strings.Compare(string(return_error), "INVALID HMAC") == 1 {
					//						fmt.Println("Ha")
					//						final_return_value = append(final_return_value, byte(i))
					//						//modify_IV_position += 1
					//						pad_number += 1
					//						ciphertext = ciphertext_to_be_sent
					//					}
					fmt.Println("The return error is", return_error)
				}
			} else {
				prev_block := ciphertext[moving_i-16 : moving_j-16]
				IV := make([]byte, 16)
				for k := 0; k < 16; k++ {
					IV[k] = prev_block[k]
				}
				fmt.Println("Yo")
				x := final_return_value[len(final_return_value)-1] ^ ciphertext[len(ciphertext)-modify_IV_position]
				y := byte(pad_number) ^ x
				IV[modify_IV_position] = y
				modify_IV_position += 1
				ciphertext_with_change_IV := IV
				ciphertext_with_change_IV = append(ciphertext_with_change_IV, ciphertext[moving_i:moving_j]...)
			}
		}
	}
	return attack(ciphertext, number_of_blocks, pad_number, modify_IV_position, final_return_value)
}

func main() {
	//temp := []byte("1111111111111111")
	//kenc := temp
	//kmac := temp

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
	fmt.Println("Modifiable ciphertext before being passed", modifiable_ciphertext)
	return_find_padding := find_padding(modifiable_ciphertext, IV)
	fmt.Println("The padding found is", return_find_padding)

	//	fmt.Println("Cipher post function call", ciphertext)
	//	ciphertext1, err := ioutil.ReadFile(os.Args[1])
	//	if err != nil {
	//		fmt.Println("Can't read file:", os.Args[1])
	//		panic(err)
	//	}

	fmt.Println("Ciphertext read from the file", ciphertext)

	ciphertext_of_interest := modifiable_ciphertext[:len(modifiable_ciphertext)-(return_find_padding+32)]
	fmt.Println("Ciphertext of interest is", ciphertext_of_interest)

	number_of_blocks := round_off_number_of_blocks(ciphertext_of_interest)

	//number_of_blocks := lenght_of_cipher_interest / 16
	fmt.Println("The blocks of interest are:", number_of_blocks)
	blocks_to_be_broken := ciphertext[:16*number_of_blocks]
	fmt.Println("Break all of this", blocks_to_be_broken)

	var final_decrypted_test []byte
	IV_found := attack(blocks_to_be_broken, number_of_blocks, 1, 1, final_decrypted_test)
	fmt.Println("IV of the current block is", IV_found)
}
