package shadowsocks

import (
	"testing"
)

func TestParseConfig1Password(t *testing.T) {
	config := ParseConfig("testdata/config-one-passwd.json")

	if config.Password != "barfoo!" {
		t.Error("wrong password from config")
	}
	if config.Debug != true {
		t.Error("debug option wrong")
	}
}

func TestParseConfigMultiPassword(t *testing.T) {
	config := ParseConfig("testdata/config-multi-passwd.json")

	if config.Password != "barfoo!" {
		t.Error("wrong password from config")
	}
	if config.PortPassword["8387"] != "foobar" {
		t.Error("wrong multiple password for port 8387")
	}
}
