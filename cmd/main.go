package main

import (
	"fmt"
	"log"

	"github.com/nlepage/go-cuid2"
)

func main() {
	id, err := cuid2.CreateId()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(id)
}
