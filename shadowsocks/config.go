package shadowsocks

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Server     string `json:"server"` // deprecated
	ServerPort int    `json:"server_port"`
	LocalAddr  string `json:"local_address"`
	LocalPort  int    `json:"local_port"`
	Password   string `json:"password"`
	Method     string `json:"method"` // encryption method
	OTA        bool   `json:"auth"`   // one time auth

	// following options are only used by server
	PortPassword map[string]string `json:"port_password"`
	Timeout      int               `json:"timeout"`

	// following options are only used by client

	// The order of servers in the client config is significant, so use array
	// instead of map to preserve the order.
	ServerPassword [][]string `json:"server_password"`
}

type ConfOption func(c *Config)

func NewConfig(opts ...ConfOption) Config {
	var config Config

	for _, v := range opts {
		v(&config)
	}
	return config
}

func WithPortPassword(port, passwd string) ConfOption {
	return func(c *Config) {
		c.PortPassword[port] = passwd
	}
}

func WithServerPort(port int) ConfOption {
	return func(c *Config) {
		c.ServerPort = port
	}
}

func WithLocalAddr(addr string) ConfOption {
	return func(c *Config) {
		c.LocalAddr = addr
	}
}
func WithLocalPort(port int) ConfOption {
	return func(c *Config) {
		c.LocalPort = port
	}
}
func WithPassword(pwd string) ConfOption {
	return func(c *Config) {
		c.Password = pwd
	}
}
func WithEncryptMethod(method string) ConfOption {
	return func(c *Config) {
		c.Method = method
	}
}
func WithOTA() ConfOption {
	return func(c *Config) {
		c.OTA = true
	}
}

func WithTimeOut(t int) ConfOption {
	return func(c *Config) {
		c.Timeout = t
	}
}

// TODO
//ServerPassword [][]string `json:"server_password"`
//ServerPassword

// return the server addr list split by the ,
func (c *Config) getServerArray() []string {
	// Specifying multiple servers in the "server" options is deprecated.
	// But for backward compatiblity, keep this.
	if c.Server == "" {
		return nil
	}
	return strings.Split(c.Server, ",")
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

	postProcess(c)
	return c, nil
}

func postProcess(c *Config) {
	var host []string
	var local string
	if strings.HasSuffix(strings.ToLower(c.Method), "-auth") {
		c.Method = c.Method[:len(c.Method)-5]
		c.OTA = true
	}

	// parse server side listen address
	// port_password has higher priority over server_port
	if len(c.PortPassword) == 0 {
		if c.ServerPort != 0 {
			c.PortPassword = map[string]string{strconv.Itoa(c.ServerPort): c.Password}
		}
	}
	// apply the address binding if server option exists
	servers := c.getServerArray()
	if len(servers) > 0 {
		host = make([]string, len(servers))
		for index, v := range servers {
			if ip := net.ParseIP(v); ip != nil {
				if ipv4 := ip.To4(); ipv4 != nil {
					host[index] = ipv4.String()
				} else if ipv6 := ip.To16(); ipv6 != nil {
					host[index] = ipv6.String()
				}
			}
		}
	}

	portPass := map[string]string{}
	for port, password := range c.PortPassword {
		if len(host) > 0 {
			for _, ip := range host {
				laddr := net.JoinHostPort(ip, port)
				portPass[laddr] = password
			}
		} else {
			laddr := net.JoinHostPort("", port)
			portPass[laddr] = password
		}
	}
	c.PortPassword = portPass

	// for client
	// server_password has higher priority over server
	if len(c.ServerPassword) == 0 && c.ServerPort != 0 && len(servers) != 0 {
		c.ServerPassword = make([][]string, len(servers))
		for k := range c.ServerPassword {
			c.ServerPassword[k] = make([]string, 2)
			c.ServerPassword[k][0] = net.JoinHostPort(servers[k], strconv.Itoa(c.ServerPort))
			c.ServerPassword[k][1] = c.Password
		}
	}

	if len(c.LocalAddr) > 0 {
		if ip := net.ParseIP(c.LocalAddr); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				local = ipv4.String()
			} else if ipv6 := ip.To16(); ipv6 != nil {
				local = ipv6.String()
			}
		}
	}
	c.LocalAddr = net.JoinHostPort(local, strconv.Itoa(c.LocalPort))
}
