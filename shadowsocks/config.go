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
var roundRobinIndex int = 0

type Config struct {
	Server          string `json:"server_addr"`     // shadowsocks remote Server address, for multi server split them with comma
	ServerPort      string `json:"server_port"`     // shadowsocks remote Server port, split with comma when multi user is enabled
	Local           string `json:"local_addr"`      // shadowsocks local socks5 Server address
	LocalPort       int    `json:"local_port"`      // shadowsocks local socks5 Server port
	Password        string `json:"password"`        // shadowsocks remote server password, for multi server password should plase in order and split eith comma
	Method          string `json:"method"`          // shadowsocks encryption method
	Timeout         int    `json:"timeout"`         // shadowsocks connection timeout
	MultiServerMode string `json:"MultiServerMode"` // shadowsocks client multi-server access mode: fastest,round-robin,dissable
	DNSServer       string `json:"dns_server"`      // shadowsocks remote Server DNS server option, if set to nil, the system DNS will be uesd for domain lookup

	// following options are only used by server
	PortPassword map[string]string `json:"port_password"` // shadowsocks mutli user password

	// following options are only used by client
	ServerPassword map[string]string `json:"server_password"` // shadowsocks local mutli server password

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
		servers:        make([]string, 1),
	}
	for _, v := range opts {
		v(&config)
	}

	servers := config.GetServerArray()
	ports := config.GetServerPortArray()
	for i, _ := range servers {
		servers[i] = net.JoinHostPort(servers[i], ports[i])
	}
	config.makeupServers()

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
func WithDNSServer(server string) ConfOption {
	return func(c *Config) {
		c.DNSServer = server
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
		case "round-robin":
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

func (c *Config) makeupServers() {
	serversaddr := c.GetServerArray()
	serversport := c.GetServerPortArray()
	servers := make([]string, len(serversaddr))
	for i, _ := range servers {
		servers[i] = net.JoinHostPort(serversaddr[i], serversport[i])
	}
	c.servers = servers
}

// ProcessConfig fill in the map after the config is unmarshaled
func ProcessConfig(c *Config) {
	c.PortPassword = make(map[string]string)
	c.ServerPassword = make(map[string]string)

	serversaddr := c.GetServerArray()
	serversport := c.GetServerPortArray()
	portspasswd := c.GetPasswordArray()

	if len(serversaddr) != len(serversport) {
		Logger.Fatal("error in config check, length of multi servers and ports mismatching")
	}
	if len(serversport) != len(portspasswd) {
		Logger.Fatal("error in config check, length of multi ports and passwards mismatching")
	}
	c.makeupServers()

	for i, v := range portspasswd {
		c.PortPassword[serversport[i]] = v
		c.ServerPassword[c.servers[i]] = v
	}
}

// GetServer return the server array's first item
func (c *Config) GetServer() string {
	if len(c.servers) == 0 {
		Logger.Fatal("error in get server, null slice returned")
	}
	return c.servers[0]
}

func (c *Config) GetServerRoundRobin() string {
	defer func() { roundRobinIndex += 1 }()
	serversaddr := c.GetServerArray()
	serversport := c.GetServerPortArray()
	index := roundRobinIndex % len(serversaddr)
	return serversaddr[index] + ":" + serversport[index]
}

// Detect used only when multi tcp based ss server is setted for the client
// Detect will try to dial each server to caculate a delay and sort server
func (c *Config) Detect() {

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
	serversPort := c.GetServerPortArray()
	for i, v := range c.GetServerArray() {
		t := ping(v + ":" + serversPort[i])
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
