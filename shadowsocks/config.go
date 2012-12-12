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
	"io/ioutil"
	"log"
	"os"
)

type Config struct {
	Server       string            `json:"server"`
	ServerPort   int               `json:"server_port"`
	LocalPort    int               `json:"local_port"`
	Password     string            `json:"password"`
	PortPassword map[string]string `json:"port_password"`
}

func ParseConfig(path string) *Config {
	file, err := os.Open(path) // For read access.
	if err != nil {
		log.Fatalf("error opening config file %s: %v\n", file, err)
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal("error reading config:", err)
	}
	var config Config
	if err = json.Unmarshal(data, &config); err != nil {
		log.Fatal("can not parse config:", err)
	}
	return &config
}
