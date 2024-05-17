package helpers

import (
	"encoding/json"
	"fmt"
)

// PrintRespJSON receive an interface and parses it into json for print
func PrintRespJSON(resp interface{}) {
	jsonBytes, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		fmt.Println("unable to decode response: ", err)
		return
	}

	fmt.Printf("%s\n", jsonBytes)
}
