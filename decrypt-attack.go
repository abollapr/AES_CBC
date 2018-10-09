// decrypt-attack
package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	temp := []byte("1111111111111111")
	kenc := temp
	kmac := temp

	fmt.Println("kenc is", kenc)
	fmt.Println("kmac is", kmac)

	result, err_cmd := exec.Command("go run decrypt-test.go output.txt").Output()
	if err_cmd != nil {
		fmt.Println("ERROR: ", err_cmd)
		os.Exit(1)
	}
	result_str := string(result)
	fmt.Println(result_str)
}
