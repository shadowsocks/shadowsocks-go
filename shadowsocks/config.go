package shadowsocks

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Config is used in both ss-server & ss-local server, notice the different role in ss
// can help you get the right config in differen situation
// 1) ss server:
// ServerPort and Password shoud be placed in order if multi user is enabled
// 2) ss local server:
// Server and ServerPort and Password shoud be care when is used in ss local server module
//
// NOTICE if the config file is setted, the config option will be disabled automaticly

// rolling index give out the index which server will return on next rolling get server
var rollingIndex int = 0

type Config struct {
	Server          string `json:"server_addr"`     // shadowsocks remote Server address, for multi server split them with comma
	ServerPort      string `json:"server_port"`     // shadowsocks remote Server port, split with comma when multi user is enabled
	Local           string `json:"local_addr"`      // shadowsocks local socks5 Server address
	LocalPort       int    `json:"local_port"`      // shadowsocks local socks5 Server port
	Password        string `json:"password"`        // shadowsocks remote server password, for multi server password should plase in order and split eith comma
	Method          string `json:"method"`          // encryption method for ss local & ss server communication
	Timeout         int    `json:"timeout"`         // shadowsocks connection timeout
	MultiServerMode string `json:"MultiServerMode"` // shadowsocks client multi-server access mode: fastest,round-over,dissable

	// following options are only used by server
	PortPassword map[string]string `json:"port_password"` // shadowsocks mutli user password

	// following options are only used by client
	ServerPassword map[string]string `json:"server_password"` // shadowsocks local mutli server password

	// TODO
	DNSServer string `"json:"dns_server"` // shadowsocks remote dns server, if set to nil, the system DNS will be uesd for dig

	// TODO unsupported function
	//"fast_open":false,
	//"tunnel_remote":"8.8.8.8",
	//"tunnel_remote_port":53,
	//"tunnel_port":53,
	servers []string
}

func (c *Config) String() string {
	return fmt.Sprintf("Server: %s, ServerPort: %s, Local: %s, LocalPort: %d, Password: %s, Method: %s, Timeout: %d, portpwds: %v, serverpwds: %v, multi-server module:%v",
		c.Server, c.ServerPort, c.Local, c.LocalPort, c.Password, c.Method, c.Timeout, c.PortPassword, c.ServerPassword, c.MultiServerMode)
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

	servers := config.GetServerArray()
	ports := config.GetServerPortArray()
	for i, _ := range servers {
		servers[i] = net.JoinHostPort(servers[i], ports[i])
	}
	config.servers = servers

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
func WithMultiServerMode(mode string) ConfOption {
	return func(c *Config) {
		switch mode {
		case "fastest":
			fallthrough
		case "round-over":
			fallthrough
		case "dissable":
			c.MultiServerMode = mode
		default:
			c.MultiServerMode = "fastest"
		}
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
	servers := c.GetServerArray()
	serverports := c.GetServerPortArray()
	passwds := c.GetPasswordArray()

	if c.ServerPassword != nil {
		return
	}
	// check and set for the ss local config
	if len(servers) > 0 && len(serverports) > 0 && len(passwds) > 0 {
		if len(servers) != len(serverports) || len(servers) != len(passwds) {
			Logger.Fatal("error in proces the config file, Invalid config")
		}
		for i := 0; i < len(servers); i++ {
			addr := serverports[i] + ":" + serverports[i]
			c.ServerPassword[addr] = passwds[i]
		}
	}

	if c.PortPassword != nil {
		return
	}
	// check and set for the ss remote server config
	if len(serverports) > 0 && len(passwds) > 0 {
		if len(servers) != len(passwds) {
			Logger.Fatal("error in proces the config file, Invalid config")
		}
		for i, port := range serverports {
			addr := ":" + port
			c.PortPassword[addr] = passwds[i]
		}
	}
}

func (c *Config) GetServer() string {
	return c.servers[0]
}

func (c *Config) GetServerRoundOver() string {
	defer func() { rollingIndex += 1 }()
	servers := c.GetServerArray()
	index := rollingIndex % len(servers)
	return servers[index]
}

// Detect used only when multi tcp based ss server is setted for the client
// Detect will try to dial each server to caculate a delay and sort server
func (c *Config) Detect() {
	if len(c.GetServerArray()) < 2 {
		return
	}

	type pair struct {
		server string
		delay  time.Duration
	}

	ping := func(addr string) time.Duration {
		var avg time.Duration
		for i := 0; i < 3; i++ {
			t := time.Now()
			_, err := net.Dial("tcp", addr)
			ts := time.Now().Sub(t)
			if err != nil {
				return 0xfffffffffffffff
			}
			avg += ts
		}
		return avg / time.Duration(3)
	}

	var ss []pair
	for _, v := range c.GetServerArray() {
		t := ping(v)
		ss = append(ss, pair{v, t})
	}
	sort.Slice(ss, func(i, j int) bool { return ss[i].delay < ss[j].delay })

	var sortedserver string
	for i, v := range ss {
		if i == 0 {
			sortedserver += v.server
		}
		sortedserver += ","
		sortedserver += v.server
	}
	c.Server = sortedserver

	Logger.Info("Detecting the server delay and sort the server in ascend", zap.String("servers", sortedserver))
}
