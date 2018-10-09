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

	result, err_cmd := exec.Command("./decrypt-test.exe").Output()

	if err_cmd != nil {
		fmt.Println("ERROR: ", err_cmd)
		os.Exit(1)
	}
	result_str := string(result)
	fmt.Println("Return Result", result_str)
	return result_str
}

func find_padding(ciphertext_11 []byte, IV []byte) int {
	fmt.Println("yo")

	length_ciphertext := len(ciphertext_11)
	count := 0
	for i := 32; i > 16; i-- {
		ciphertext_11[length_ciphertext-i] = byte(0)
		//fmt.Println(ciphertext)

		error_returned := decryption_oracle(ciphertext_11)
		//fmt.Println("Error returned by the decryption oracle is", error_returned)
		if strings.Compare(string(error_returned), "INVALID PADDING") == 1 {
			count += 1
		}
	}
	return count
}

func round_off_number_of_blocks(ciphertext_of_interest []byte) int {
	round_off_blocks := 0
	if len(ciphertext_of_interest)%16 == 0 {
		fmt.Println("hahah")
		round_off_blocks = len(ciphertext_of_interest) % 16
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

func main() {
	temp := []byte("1111111111111111")
	kenc := temp
	kmac := temp

	fmt.Println("kenc is", kenc)
	fmt.Println("kmac is", kmac)

	ciphertext, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("Can't read file:", os.Args[1])
		panic(err)
	}

	modifiable_ciphertext := ciphertext
	fmt.Println("Ciphertext read from the file", ciphertext)

	IV := ciphertext[:16]
	return_find_padding := find_padding(modifiable_ciphertext, IV)
	fmt.Println(return_find_padding)

	fmt.Println("Cipher post function call", ciphertext)
	ciphertext1, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("Can't read file:", os.Args[1])
		panic(err)
	}

	ciphertext_of_interest := ciphertext1[:len(ciphertext1)-(return_find_padding+32)]
	fmt.Println(ciphertext_of_interest)

	number_of_blocks := round_off_number_of_blocks(ciphertext_of_interest)

	//number_of_blocks := lenght_of_cipher_interest / 16
	fmt.Println("The blocks of interest are:", number_of_blocks)

}
