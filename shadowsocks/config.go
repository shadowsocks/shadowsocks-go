package shadowsocks

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
)

// Config is the interface for config.
// although shadowsocks package do not directly receive config now,
// it'a a basic structure containing all key elements for config.
type Config interface {
	// ServerAddrs is for server side, used to listen
	ServerAddrPasswords() map[string]string
	// RemoteAddrs is for client side, used to connect
	RemoteAddrPasswords() [][]string
	LocalAddr() string
	Method() string
	Password() string
	Timeout() int
	OTA() bool
}

// config is the struct for shadowsocks config
type config struct {
	JServer     interface{} `json:"server"` // deprecated
	JServerPort int         `json:"server_port"`
	JLocalAddr  string      `json:"local_address"`
	JLocalPort  int         `json:"local_port"`
	JPassword   string      `json:"password"`
	JMethod     string      `json:"method"` // encryption method
	JOTA        bool        `json:"auth"`   // one time auth

	// following options are only used by server
	JPortPassword map[string]string `json:"port_password"`
	JTimeout      int               `json:"timeout"`

	// following options are only used by client

	// The order of servers in the client config is significant, so use array
	// instead of map to preserve the order.
	JServerPassword [][]string `json:"server_password"`
}

func (c *config) ServerAddrPasswords() map[string]string {
	return c.JPortPassword
}

func (c *config) RemoteAddrPasswords() [][]string {
	return c.JServerPassword
}

func (c *config) LocalAddr() string {
	return c.JLocalAddr
}

func (c *config) OTA() bool {
	return c.JOTA
}

func (c *config) Password() string {
	return c.JPassword
}

func (c *config) Method() string {
	return c.JMethod
}

func (c *config) Timeout() int {
	return c.JTimeout
}

func (c *config) getServerArray() []string {
	// Specifying multiple servers in the "server" options is deprecated.
	// But for backward compatiblity, keep this.
	if c.JServer == nil {
		return nil
	}
	single, ok := c.JServer.(string)
	if ok {
		return []string{single}
	}
	arr, ok := c.JServer.([]interface{})
	if ok {
		/*
			if len(arr) > 1 {
				log.Println("Multiple servers in \"server\" option is deprecated. " +
					"Please use \"server_password\" instead.")
			}
		*/
		serverArr := make([]string, len(arr), len(arr))
		for i, s := range arr {
			serverArr[i], ok = s.(string)
			if !ok {
				return nil
			}
		}
		return serverArr
	}
	return nil
}

func postProcess(c *config) {
	var host []string
	var local string
	if strings.HasSuffix(strings.ToLower(c.JMethod), "-auth") {
		c.JMethod = c.JMethod[:len(c.JMethod)-5]
		c.JOTA = true
	}

	// parse server side listen address
	// port_password has higher priority over server_port
	if len(c.JPortPassword) == 0 {
		if c.JServerPort != 0 {
			c.JPortPassword = map[string]string{strconv.Itoa(c.JServerPort): c.JPassword}
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
	for port, password := range c.JPortPassword {
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
	c.JPortPassword = portPass
	// for client
	// server_password has higher priority over server
	if len(c.JServerPassword) == 0 && c.JServerPort != 0 && len(servers) != 0 {
		c.JServerPassword = make([][]string, len(servers))
		for k := range c.JServerPassword {
			c.JServerPassword[k] = make([]string, 2)
			c.JServerPassword[k][0] = net.JoinHostPort(servers[k], strconv.Itoa(c.JServerPort))
			c.JServerPassword[k][1] = c.JPassword
		}
	}

	if len(c.JLocalAddr) > 0 {
		if ip := net.ParseIP(c.JLocalAddr); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				local = ipv4.String()
			} else if ipv6 := ip.To16(); ipv6 != nil {
				local = ipv6.String()
			}
		}
	}
	c.JLocalAddr = net.JoinHostPort(local, strconv.Itoa(c.JLocalPort))
}

// ParseConfig parses a config file
func ParseConfig(path string) (conf Config, err error) {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}

	c := &config{}
	if err = json.Unmarshal(data, c); err != nil {
		return nil, err
	}

	postProcess(c)
	return c, nil
}

func SetDebug(d DebugLog) {
	Debug = d
}
