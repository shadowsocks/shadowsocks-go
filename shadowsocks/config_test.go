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
}
