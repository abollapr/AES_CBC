// decrypt-attack
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
)

func find_padding(ciphertext []byte) int {
	fmt.Println("yo")

	length_ciphertext := len(ciphertext)
	number_of_blocks := length_ciphertext / 16

	//last_block := ciphertext[length_ciphertext-16:]

	return number_of_blocks

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

	return_find_padding := find_padding(ciphertext)
	fmt.Println(return_find_padding)

	result, err_cmd := exec.Command("go run decrypt-test.go output.txt").Output()
	if err_cmd != nil {
		fmt.Println("ERROR: ", err_cmd)
		os.Exit(1)
	}
	result_str := string(result)
	fmt.Println(result_str)
}
