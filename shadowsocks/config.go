/**
 * Created with IntelliJ IDEA.
 * User: clowwindy
 * Date: 12-11-2
 * Time: 上午10:31
 * To change this template use File | Settings | File Templates.
 */
package shadowsocks

import (
	"encoding/json"
	"os"
	"log"
)
type Config struct {
	Server string `json:"server"`
	ServerPort int `json:"server_port"`
	LocalPort int `json:"local_port"`
	Password string `json:"password"`
}

func ParseConfig() Config {
	file, err := os.Open("config.json") // For read access.
	if err != nil {
		log.Fatal("error opening config file config.json:", err)
	}
	data := make([]byte, 4096)
	count, err := file.Read(data)
	if err != nil {
		log.Fatal("error reading config:", err)
	}
	if count == 4096 {
		log.Fatal("config file is too large")
	}
	var config Config
	err = json.Unmarshal(data[0:count], &config)
	if err != nil {
		log.Fatal("can not parse config:",err)
	}
	return config
}
