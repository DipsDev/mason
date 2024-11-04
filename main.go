package main

import (
	"fmt"
	"net/http"
)

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("hello World!"))
		if err != nil {
			return
		}
	})
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		err_message := fmt.Errorf("[Mason] Error while creating server: %v", err)
		fmt.Println(err_message)
		return
	}

}
