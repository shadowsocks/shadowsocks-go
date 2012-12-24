package shadowsocks

import (
	"testing"
)

func TestConfigJson(t *testing.T) {
	config, err := ParseConfig("testdata/config.json")
	if err != nil {
		t.Fatal("error parsing config.json:", err)
	}

	if config.Password != "barfoo!" {
		t.Error("wrong password from config")
	}
	if config.Timeout != 0 {
		t.Error("tiemout should default to 0")
	}
	srvArr := config.GetServerArray()
	if len(srvArr) != 1 || srvArr[0] != "127.0.0.1" {
		t.Error("server option is not set correctly")
	}
	if config.CacheEncTable {
		t.Error("cache_enctable should be false by default")
	}
}

func TestServerMultiPort(t *testing.T) {
	config, err := ParseConfig("testdata/server-multi-port.json")
	if err != nil {
		t.Fatal("error parsing multi server-multi-port.json:", err)
	}

	if config.PortPassword["8387"] != "foobar" {
		t.Error("wrong multiple password for port 8387")
	}
	if config.PortPassword["8388"] != "barfoo" {
		t.Error("wrong multiple password for port 8388")
	}
	if config.PortPassword["8389"] != "" {
		t.Error("should have no password for port 8389")
	}

	if !config.CacheEncTable {
		t.Error("cache_enctable should be true")
	}
}

func TestDeprecatedClientMultiServerArray(t *testing.T) {
	// This form of config is deprecated. Provided only for backward compatibility.
	config, err := ParseConfig("testdata/deprecated-client-multi-server.json")
	if err != nil {
		t.Fatal("error parsing deprecated-client-multi-server.json:", err)
	}

	srvArr := config.GetServerArray()
	if len(srvArr) != 2 {
		t.Error("server option is not set correctly")
	}
	if srvArr[0] != "127.0.0.1" {
		t.Error("1st server wrong, got %v", srvArr[0])
	}
	if srvArr[1] != "127.0.1.1" {
		t.Error("2nd server wrong, got %v", srvArr[0])
	}
}

func TestClientMultiServerArray(t *testing.T) {
	config, err := ParseConfig("testdata/client-multi-server.json")
	if err != nil {
		t.Fatal("error parsing client-multi-server.json:", err)
	}

	if config.ServerPassword["127.0.0.1:8387"] != "foobar" ||
		config.ServerPassword["127.0.0.1:8388"] != "barfoo" {
		t.Error("server_password parse error")
	}
}

func TestParseConfigEmpty(t *testing.T) {
	// make sure we will not crash
	config, err := ParseConfig("testdata/noserver.json")
	if err != nil {
		t.Fatal("error parsing noserver config:", err)
	}

	srvArr := config.GetServerArray()
	if srvArr != nil {
		t.Error("GetServerArray should return nil if no server option is given")
	}
}
