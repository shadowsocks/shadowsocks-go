package shadowsocks

import (
	"testing"
)

func TestParseConfig1Password(t *testing.T) {
	config, err := ParseConfig("testdata/config-one-passwd.json")
	if err != nil {
		t.Error("error parsing single password config:", err)
	}

	if config.Password != "barfoo!" {
		t.Error("wrong password from config")
	}
	if config.Timeout != 60 {
		t.Error("tiemout wrong")
	}
	if !config.CacheEncTable {
		t.Error("cache_enctable should be true")
	}
	srvArr := config.GetServerArray()
	if len(srvArr) != 1 || srvArr[0] != "127.0.0.1" {
		t.Error("server option is not set correctly")
	}
}

func TestParseConfigMultiPassword(t *testing.T) {
	config, err := ParseConfig("testdata/config-multi-passwd.json")
	if err != nil {
		t.Error("error parsing multi password config:", err)
	}

	if config.Password != "barfoo!" {
		t.Error("wrong password from config")
	}
	if config.PortPassword["8387"] != "foobar" {
		t.Error("wrong multiple password for port 8387")
	}

	srvArr := config.GetServerArray()
	if len(srvArr) != 2 {
		t.Error("server option is not set correctly")
	}
	if srvArr[0] != "127.0.0.1" {
		t.Error("1st server wrong")
	}
	if srvArr[1] != "127.0.1.1" {
		t.Error("2nd server wrong")
	}
}

func TestParseConfigEmpty(t *testing.T) {
	// make sure we will not crash
	config, err := ParseConfig("testdata/noserver.json")
	if err != nil {
		t.Error("error parsing noserver config:", err)
	}

	srvArr := config.GetServerArray()
	if srvArr != nil {
		t.Error("GetServerArray should return nil if no server option is given")
	}
}
