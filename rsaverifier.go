package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

func main() {

sig:= "VqBFxeCkU/M/ozjLJsPVZn0wL9o+VxnnLKNWND5dFSVDW0Al3PlEkonjgKE2dF09EjIN/VU76eJEPrrLbH+Li957EEJpYXzq3ittXMlJ8m86ggymNDDFYuZ9D/LnbWsc0yQZbi3TDb9qmeCBQx+1xloeq88voqVHR6eEsiLYpCYoZLd93WZ5zeTcq4Jde4glteVo88KA16v4/Fi6i9YYCKxqvj7q5D1oY13hOiIZO+wqy3//WtdCrA6DpQe/bG72OlaKdKJh3OWFFNyrnGEwtMFssxUWeCaV8DplOWoZstRxeXrBl0/yPW4c6wucFQzIIqf5c0X9xV3ioQR3VdRTCg=="

k:="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuaUO2qem3KZguBJ94L/iSwFPFB+CY9xWjdtZkLJHQyWIzdZBxn4/aoVmUuj0VQ4tIXaOvj+0vDvE6pSuLFfYLwDeON9NqASWtV279E/U5pt/djJylC+JBp/3M5dOvI6G/pRO1DQmtr6CVIYxk9NKTF79jyzyYX+ZLwsVvJRJL8TfzVyQoCAc6NlIhq87//5hroYBAOde5nbabv7cscZEkiq2+RevxJxkn/auLXdAU8wfljTiuzCmtK3cO/pscH9ZCFKPTO6q5kDw08yIC4ZrMGB2tozmoqZUssBpaDQYbiAFKDrSr0F3S2j8Ec8zazfCHPCGeRHlQ/7Ky9L5TMEduwIDAQAB"
key, _ := base64.StdEncoding.DecodeString(k)
re, err := x509.ParsePKIXPublicKey(key)

if err != nil {
		fmt.Println(err)
		return
	}
pub := re.(*rsa.PublicKey)
text := []byte(`{"actor":{"actor_type":"agent","actor_id":"b345fc25-0a80-4df7-b568-407341a25ad2"},"action":"message_create","action_time":"2020-12-04T12:51:47.788Z","data":{"message":{"message_parts":[{"text":{"content":"<sfdg>'id <kril'"}}],"app_id":"25d2f067-ad57-40bc-940d-6923601b2f2e","actor_id":"b345fc25-0a80-4df7-b568-407341a25ad2","id":"363bc8f9-af2e-4173-ba7d-4b2002718f61","channel_id":"b9311ae5-514c-482b-a4f0-f3c62c543ce7","conversation_id":"459e2e51-39e4-4910-a063-307c37988da7","interaction_id":"406696773695621-1602046404502","message_type":"normal","actor_type":"agent","created_time":"2020-12-04T12:51:47.625Z","user_id":"c6d43945-cad8-4470-b49d-dd040b69a9f5"}}}`)
h := sha256.New()
h.Write(text)
digest := h.Sum(nil)

ds, _ := base64.StdEncoding.DecodeString(sig)
err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, ds)
fmt.Println("verify:", err)

}
