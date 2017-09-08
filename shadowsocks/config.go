package shadowsocks

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/arthurkiller/shadowsocks-go/encrypt"

	"go.uber.org/zap"
)

// Config is used in both ss-server & ss-local server, notice the different role in ss
// can help you get the right config in differen situation
// 1) ss server:
// ServerPort and Password shoud be placed in order if multi user is enabled
// 2) ss local server:
// Server and ServerPort and Password shoud be care when is used in ss local server module
//
// NOTICE if the config file is setted, the config option will be disabled automatically

var (
	// rolling index give out the index which server will return on next rolling get server
	roundRobinIndex int
)

// Config implement the ss config
type Config struct {
	Server          string        `json:"server_addr"`       // shadowsocks remote Server address
	ServerPort      string        `json:"server_port"`       // shadowsocks remote Server port
	Local           string        `json:"local_addr"`        // shadowsocks local socks5 Server address
	LocalPort       string        `json:"local_port"`        // shadowsocks local socks5 Server port
	Password        string        `json:"password"`          // shadowsocks remote server password
	Method          string        `json:"method"`            // shadowsocks encryption method
	Timeout         int           `json:"timeout"`           // shadowsocks connection timeout
	MultiServerMode string        `json:"multi_server_mode"` // shadowsocks client multi-server access mode: fastest,round-robin,dissable
	DNSServer       string        `json:"dns_server"`        // shadowsocks remote Server DNS server option, the system DNS will be uesd for domain lookup by defalut
	ServerList      []ServerEntry `json:"server_list"`       // shadowsocks server list keep a list of remot-server information, this will be coverd with the server and ServerPort field

	lock sync.Mutex
	// TODO unsupported functions
	//"fast_open":false,
	//"tunnel_remote":"8.8.8.8",
	//"tunnel_remote_port":53,
	//"tunnel_port":53,
}

// ServerEntry give out basic elements a server needs
type ServerEntry struct {
	Address  string `json:"address"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

func (se *ServerEntry) String() string {
	return fmt.Sprintf("server: %s, password: %s, method: %s", se.Address, se.Password, se.Method)
}

// Check the server entry if invalid
func (se *ServerEntry) Check() error {
	if !strings.Contains(se.Address, ":") {
		return ErrInvalidServerAddress
	}
	if _, err := net.ResolveIPAddr("", strings.Split(se.Address, ":")[0]); err != nil {
		return ErrInvalidServerAddress
	}
	if se.Password == "" {
		return ErrNilPasswd
	}
	if encrypt.CheckCipherMethod(se.Method) != nil {
		return ErrInvalidCipher
	}
	return nil
}

func (c *Config) Check() error {
	for _, v := range c.ServerList {
		if err := v.Check(); err != nil {
			return err
		}
	}
	if len(c.ServerList) == 0 {
		return ErrInvalidConfig
	}
	if _, err := net.ResolveIPAddr("", c.Local); err != nil {
		return err
	}
	if err := encrypt.CheckCipherMethod(c.Method); err != nil {
		return err
	}
	return nil
}

// String return the ss config content in string
func (c *Config) String() string {
	return fmt.Sprintf("Server: %s, ServerPort: %s, Local: %s , LocalPort: %d, Password: %s, Method: %s, Timeout: %d, server_DNS: %s, multi-server module: %v",
		c.Server, c.ServerPort, c.Local, c.LocalPort, c.Password, c.Method, c.Timeout, c.DNSServer, c.MultiServerMode)
}

// ParseConfig parses a config file
func ParseConfig(path string) (conf *Config, err error) {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return nil, ErrParesConfigfile
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, ErrParesConfigfile
	}

	c := &Config{}
	c.ServerList = make([]ServerEntry, 0, 1)
	if err = json.Unmarshal(data, c); err != nil {
		return nil, ErrParesConfigfile
	}

	switch c.MultiServerMode {
	case "fastest":
		fallthrough
	case "round-robin":
		fallthrough
	case "dissable":
		break
	default:
		c.MultiServerMode = "fastest"
	}

	c.ServerList = append(c.ServerList, ServerEntry{net.JoinHostPort(c.Server, c.ServerPort), c.Method, c.Password})
	c.lock = sync.Mutex{}

	if err := c.Check(); err != nil {
		return nil, err
	}

	return c, nil
}

// NewConfig use the option to generate the ss config
func NewConfig(opts ...ConfOption) (*Config, error) {
	var c = Config{
		ServerList: make([]ServerEntry, 0, 1),
	}
	for _, opt := range opts {
		opt(&c)
	}
	c.ServerList = append(c.ServerList, ServerEntry{net.JoinHostPort(c.Server, c.ServerPort), c.Method, c.Password})
	c.lock = sync.Mutex{}

	if err := c.Check(); err != nil {
		return nil, err
	}

	return &c, nil
}

// ConfOption define the config options
type ConfOption func(c *Config)

// WithRemoteServer add a remote server entry into serverlist
func WithRemoteServer(server, method, passwd string) ConfOption {
	return func(c *Config) {
		c.ServerList = append(c.ServerList, ServerEntry{server, method, passwd})
	}
}

// WithServer set the server address
func WithServer(server string) ConfOption {
	return func(c *Config) {
		c.Server = server
	}
}

// WithServerPort set the server port for server
func WithServerPort(port string) ConfOption {
	return func(c *Config) {
		c.ServerPort = port
	}
}

// WithPassword set the password for server
func WithPassword(pwd string) ConfOption {
	return func(c *Config) {
		c.Password = pwd
	}
}

// WithLocalAddr set the local socks5 address
func WithLocalAddr(addr string) ConfOption {
	return func(c *Config) {
		c.Local = addr
	}
}

// WithLocalPort set the local socks5 port
func WithLocalPort(port string) ConfOption {
	return func(c *Config) {
		c.LocalPort = port
	}
}

// WithEncryptMethod set the encrypt method
func WithEncryptMethod(method string) ConfOption {
	return func(c *Config) {
		c.Method = method
	}
}

// WithDNSServer set the DNS server address
func WithDNSServer(server string) ConfOption {
	return func(c *Config) {
		c.DNSServer = server
	}
}

// WithTimeOut set the timeout for ss connection
func WithTimeOut(t int) ConfOption {
	return func(c *Config) {
		c.Timeout = t
	}
}

// WithMultiServerMode choose the mode about multiserver
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

func (c *Config) GetServer() ServerEntry {
	return c.ServerList[0]
}

func (c *Config) GetServerRoundRobin() ServerEntry {
	defer c.lock.Unlock()
	defer func() { roundRobinIndex++ }()

	c.lock.Lock()
	return c.ServerList[roundRobinIndex%len(c.ServerList)]
}

// Detect used only when multi tcp based ss server is setted for the client
// Detect will try to dial each server to caculate a delay and sort server
func (c *Config) Detect() {
	type pair struct {
		server *ServerEntry
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

	ss := make([]pair, 0, len(c.ServerList))
	for _, v := range c.ServerList {
		t := ping(v.Address)
		ss = append(ss, pair{&v, t})
	}

	sort.Slice(ss, func(i, j int) bool { return ss[i].delay < ss[j].delay })

	sortedServerlist := make([]ServerEntry, 0, len(c.ServerList))

	for _, v := range ss {
		sortedServerlist = append(sortedServerlist, *v.server)
	}

	c.lock.Lock()
	c.ServerList = sortedServerlist
	c.lock.Unlock()

	Logger.Info("Detecting the server delay and sort the server in ascend", zap.Reflect("serverlist", c.ServerList))
}
