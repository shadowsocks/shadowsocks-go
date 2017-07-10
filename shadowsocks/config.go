package shadowsocks

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// Config is used in both ss-server & ss-local server, notice the different role in ss
// can help you get the right config in differen situation
// 1) ss server:
// ServerPort and Password shoud be placed in order if multi user is enabled
// 2) ss local server:
// Server and ServerPort and Password shoud be care when is used in ss local server module
// NOTICE if the config file option is setted, the config option will be disabled automaticly
type Config struct {
	Server     string `json:"server_addr"` // shadowsocks remote Server address
	ServerPort string `json:"server_port"` // shadowsocks remote Server port
	Local      string `json:"local_addr"`  // shadowsocks local socks5 Server address
	LocalPort  int    `json:"local_port"`  // shadowsocks local socks5 Server port
	Password   string `json:"password"`    // shadowsocks remote server password, for multi server password should plase in order and split eith comma
	Method     string `json:"method"`      // encryption method for ss local & ss server communication
	Timeout    int    `json:"timeout"`     // shadowsocks conversation timeout limit

	// following options are only used by server
	PortPassword map[string]string `json:"port_password"` // shadowsocks mutli user password

	// following options are only used by client
	ServerPassword map[string]string `json:"server_password"` // shadowsocks local mutli server password
}

func (c *Config) String() string {
	return fmt.Sprintf("Server: %s, ServerPort: %s, Local: %s, LocalPort: %d, Password: %s, Method: %s, Timeout: %d, portpwds: %v, serverpwds: %v",
		c.Server, c.ServerPort, c.Local, c.LocalPort, c.Password, c.Method, c.Timeout, c.PortPassword, c.ServerPassword)
}

type ConfOption func(c *Config)

func NewConfig(opts ...ConfOption) *Config {
	var config = Config{
		PortPassword:   make(map[string]string),
		ServerPassword: make(map[string]string),
	}
	for _, v := range opts {
		v(&config)
	}
	return &config
}

func WithPortPassword(port, passwd string) ConfOption {
	return func(c *Config) {
		c.PortPassword[port] = passwd
	}
}
func WithServerPassword(server, passwd string) ConfOption {
	return func(c *Config) {
		c.ServerPassword[server] = passwd
	}
}

func WithServer(server string) ConfOption {
	return func(c *Config) {
		c.Server = server
	}
}
func WithServerPort(port string) ConfOption {
	return func(c *Config) {
		c.ServerPort = port
	}
}
func WithPassword(pwd string) ConfOption {
	return func(c *Config) {
		c.Password = pwd
	}
}
func WithLocalAddr(addr string) ConfOption {
	return func(c *Config) {
		c.Local = addr
	}
}
func WithLocalPort(port int) ConfOption {
	return func(c *Config) {
		c.LocalPort = port
	}
}
func WithEncryptMethod(method string) ConfOption {
	return func(c *Config) {
		c.Method = method
	}
}
func WithTimeOut(t int) ConfOption {
	return func(c *Config) {
		c.Timeout = t
	}
}

// return the server addr list split by comma
func (c *Config) GetServerArray() []string {
	// Specifying multiple servers in the "server" options is deprecated.
	// But for backward compatiblity, keep this.
	if c.Server == "" {
		return nil
	}
	return strings.Split(c.Server, ",")
}
func (c *Config) GetServerPortArray() []string {
	if c.ServerPort == "" {
		return nil
	}
	return strings.Split(c.ServerPort, ",")
}
func (c *Config) GetPasswordArray() []string {
	if c.Password == "" {
		return nil
	}
	return strings.Split(c.Password, ",")
}

// ParseConfig parses a config file
func ParseConfig(path string) (conf *Config, err error) {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}

	c := &Config{}
	if err = json.Unmarshal(data, c); err != nil {
		return nil, err
	}

	ProcessConfig(c)
	return c, nil
}

// ProcessConfig fill in the map after the config is unmarshaled
func ProcessConfig(c *Config) {
	c.PortPassword = make(map[string]string)
	c.ServerPassword = make(map[string]string)

	sport := c.ServerPort
	if !strings.Contains(c.ServerPort, ":") {
		sport = ":" + c.ServerPort
	}

	addr := c.Server + c.ServerPort
	c.ServerPassword[addr] = c.Password
	c.PortPassword[sport] = c.Password
}
