package main

import (
	. "CLkey/lib"
	"fmt"
	"github.com/pkg/errors"
)

func server() error {
	endpoint := NewEndPoint()

	endpoint.AddHandleFunc("string", HandleStrings)
	endpoint.AddHandleFunc("gob", HandleGob)

	// 开始监听
	return endpoint.Listen()
}

func main() {
	err := server()
	if err != nil {
		fmt.Println("Error:", errors.WithStack(err))
	}
}
