package main

import (
	"bytes"
	"fmt"
)

func main() {
	src := []byte("123456")
	buffer := bytes.NewBuffer(nil)
	bytes.NewReader(src).WriteTo(buffer)
	//buffer.Write(src)
	buffer.Read()
	fmt.Print(buffer.Bytes())
}