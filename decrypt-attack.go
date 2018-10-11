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
	fmt.Println("The length of ciphertext 11 is", len(ciphertext_11))
	count := 0
	for i := len(ciphertext_11) - 32; i < len(ciphertext_11)-16; i++ {
		ciphertext_11[i] = byte(0)
		fmt.Println(ciphertext_11)

		error_returned := decryption_oracle(ciphertext_11)
		fmt.Println("Error returned by the decryption oracle is", error_returned)
		if strings.Compare(error_returned, "INVALID PADDING\n") == 0 {
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

func attack(ciphertext []byte, pad_number int, modify_IV_position int, final_return_value []byte) []byte {
	if len(final_return_value) == 16 {
		return final_return_value
	}
	//fmt.Println("===============================================")
	//fmt.Println("PAD NUMBER IS", pad_number)
	//fmt.Println("Ciphertext is", ciphertext)
	moving_i := len(ciphertext) - 16
	//fmt.Println("Moving I", moving_i)
	moving_j := len(ciphertext)
	//fmt.Println("Moving j", moving_j)
	var ciphertext_with_change_IV []byte
	var prev_block []byte
	if len(ciphertext) >= 32 { // To check if the left out number of blocks left to decrypt are a minimum of 2 (1 block IV + 1 block M)
		//Setting the IV to the previous block
		for modify_IV_position := 1; modify_IV_position <= pad_number; modify_IV_position++ {
			//fmt.Println("******", ciphertext_with_change_IV)
			//fmt.Println("Modify_i_poisition", modify_IV_position)
			if modify_IV_position == pad_number {
				for i := 0; i < 256; i++ {

					// Setting the IV to the previous block. If the Pad number is greater than 0, take the IV from the ciphertext_with_change_IV
					if pad_number != 1 {
						//fmt.Println("Pad number != 0")
						//fmt.Println("Ciphertext with change IV", ciphertext_with_change_IV)
						prev_block = ciphertext_with_change_IV[len(ciphertext_with_change_IV)-32 : len(ciphertext_with_change_IV)-16]
						//prev_block = ciphertext_with_change_IV[moving_i-16 : moving_j-16]

					} else {
						//fmt.Println("Pad number == 0")
						prev_block = ciphertext[moving_i-16 : moving_j-16] // Is for loop required here?!! Check values
					}

					// IV is being created here and contents from prev_block are copied.
					//fmt.Println("Previous Block iS: ", prev_block)
					IV := make([]byte, 16)
					for k := 0; k < 16; k++ {
						IV[k] = prev_block[k]
					}

					//fmt.Println("IV before modification is", IV)
					//fmt.Println("The modified_IV_position is", modify_IV_position)
					//fmt.Println("The last byte should now be", int(IV[len(IV)-modify_IV_position])^i^pad_number)
					//fmt.Println("I is", i)

					IV[len(IV)-modify_IV_position] = byte(int(IV[len(IV)-modify_IV_position]) ^ i ^ pad_number)
					//fmt.Println("IV is", IV)

					final_ciphertext := make([]byte, len(IV))
					for i := 0; i < len(IV); i++ {
						final_ciphertext[i] = IV[i]
					}

					final_ciphertext = append(final_ciphertext, ciphertext[moving_i:moving_j]...)
					//fmt.Println("Ciphertext tbs:", final_ciphertext)

					return_error_1 := decryption_oracle(final_ciphertext)

					//fmt.Println("Return error is-----", return_error_1)
					if strings.Compare(string(return_error_1), "INVALID HMAC\n") == 0 {
						//fmt.Println("Ha", return_error_1)
						final_return_value = append(final_return_value, byte(i)) //storing the final result = guess
						//modify_IV_position = 1
						//pad_number += 1
						//ciphertext = ciphertext_to_be_sent

						break
					}
					//fmt.Println("The return error is", return_error)
				}
			} else {
				//prev_block := ciphertext_with_change_IV[moving_i-16 : moving_j-16]
				if modify_IV_position == 1 {
					prev_block = ciphertext[moving_i-16 : moving_j-16]
				} else {
					prev_block = ciphertext_with_change_IV[len(ciphertext_with_change_IV)-32 : len(ciphertext_with_change_IV)-16]
				}
				//fmt.Println("Second previous block is: ", prev_block)
				IV := make([]byte, 16)
				for k := 0; k < 16; k++ {
					IV[k] = prev_block[k]
				}

				x := final_return_value[modify_IV_position-1] ^ IV[len(IV)-modify_IV_position]
				y := byte(pad_number) ^ x

				//fmt.Println("Final_Return_Value", final_return_value)
				//fmt.Println("ciphertext[len(ciphertext)-modify_IV_position", IV[len(IV)-modify_IV_position])
				//fmt.Println("X is", x)

				IV[len(IV)-modify_IV_position] = y
				//fmt.Println("Modified IV is --------------", IV)

				ciphertext_with_change_IV_1 := make([]byte, aes.BlockSize)
				for i := 0; i < aes.BlockSize; i++ {
					ciphertext_with_change_IV_1[i] = IV[i]
				}
				ciphertext_with_change_IV = ciphertext_with_change_IV_1
				//fmt.Println("Ciphertext with change IV copied with IV")
				ciphertext_with_change_IV = append(ciphertext_with_change_IV, ciphertext[moving_i:moving_j]...)

				//fmt.Println("Ciphertext with changed IV is", ciphertext_with_change_IV)
			}
			//fmt.Println("After else condition, ciphertext with change IV is", ciphertext_with_change_IV)
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

	//fmt.Println("Length of ciphertext", len(modifiable_ciphertext))

	IV := ciphertext[:16]
	//fmt.Println("Modifiable ciphertext before being passed", modifiable_ciphertext)
	return_find_padding := find_padding(modifiable_ciphertext, IV)
	//fmt.Println("The padding found is", return_find_padding)

	//	fmt.Println("Cipher post function call", ciphertext)
	//	ciphertext1, err := ioutil.ReadFile(os.Args[1])
	//	if err != nil {
	//		fmt.Println("Can't read file:", os.Args[1])
	//		panic(err)
	//	}

	//fmt.Println("Ciphertext read from the file", ciphertext)

	ciphertext_of_interest := modifiable_ciphertext[:len(modifiable_ciphertext)-(return_find_padding+32)]
	//fmt.Println("Ciphertext of interest is", ciphertext_of_interest)

	//fmt.Println("Length of ciphertext of interest is", len(ciphertext_of_interest))
	number_of_blocks := round_off_number_of_blocks(ciphertext_of_interest)

	//number_of_blocks := lenght_of_cipher_interest / 16
	//fmt.Println("The blocks of interest are:", number_of_blocks)
	blocks_to_be_broken := ciphertext[:16*number_of_blocks]
	//fmt.Println("Break all of this", blocks_to_be_broken)
	//fmt.Println("Length of blocks to be broken", len(blocks_to_be_broken))
	strip := 0
	for i := 1; i < number_of_blocks; i++ {
		var final_decrypted_test []byte
		final_plain_Text = append(final_plain_Text, attack(blocks_to_be_broken[:len(blocks_to_be_broken)-strip], 1, 1, final_decrypted_test)...)
		strip += 16

	}
	fmt.Println("The final value in reverse is", final_plain_Text)

}
