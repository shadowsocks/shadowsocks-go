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
	"time"
)

type Config struct {
	Server       string            `json:"server"`
	ServerPort   int               `json:"server_port"`
	LocalPort    int               `json:"local_port"`
	Password     string            `json:"password"`
	PortPassword map[string]string `json:"port_password"`
	Timeout      int               `json:"timeout"`
	Debug        bool              `json:"debug"`
}

var readTimeout time.Duration

func ParseConfig(path string) (config *Config, err error) {
	file, err := os.Open(path) // For read access.
	if err != nil {
		log.Println("error opening config file:", err)
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println("error reading config:", err)
		return
	}

	config = &Config{}
	if err = json.Unmarshal(data, config); err != nil {
		log.Println("can not parse config:", err)
		return nil, err
	}
	Debug = DebugLog(config.Debug)
	readTimeout = time.Duration(config.Timeout) * time.Second
	return
}
