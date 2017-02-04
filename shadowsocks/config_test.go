package shadowsocks

import (
	"testing"
)

func TestConfigJson(t *testing.T) {
	config, err := ParseConfig("../config.json")
	if err != nil {
		t.Fatal("error parsing config.json:", err)
	}

	if config.Password() != "barfoo!" {
		t.Error("wrong password from config")
	}
	if config.Timeout() != 600 {
		t.Error("timeout should be 600")
	}
	if config.Method() != "aes-128-cfb" {
		t.Error("method should be aes-128-cfb")
	}

	addrPass := config.ServerAddrPasswords()
	if len(addrPass) != 1 || addrPass["127.0.0.1:8388"] != "barfoo!" {
		t.Error("server option is not set correctly")
	}

	remotePass := config.RemoteAddrPasswords()
	if len(remotePass) != 1 || remotePass[0][0] != "127.0.0.1:8388" || remotePass[0][1] != "barfoo!" {
		t.Error("remote server option is not set correctly")
	}
}

func TestServerMultiPort(t *testing.T) {
	config, err := ParseConfig("../sample-config/server-multi-port.json")
	if err != nil {
		t.Fatal("error parsing ../sample-config/server-multi-port.json:", err)
	}
	addrPass := config.ServerAddrPasswords()
	if len(addrPass) != 2 {
		t.Error("wrong number of multiple password configs")
	}

	if addrPass[":8387"] != "foobar" {
		t.Error("wrong multiple password for port 8387")
	}

	if addrPass[":8388"] != "barfoo" {
		t.Error("wrong multiple password for port 8388")
	}
	if addrPass["8389"] != "" {
		t.Error("should have no password for port 8389")
	}
}

func TestDeprecatedClientMultiServerArray(t *testing.T) {
	// This form of config is deprecated. Provided only for backward compatibility.
	config, err := ParseConfig("testdata/deprecated-client-multi-server.json")
	if err != nil {
		t.Fatal("error parsing deprecated-client-multi-server.json:", err)
	}
	addrPass := config.ServerAddrPasswords()
	if len(addrPass) != 2 {
		t.Error("server option is not set correctly")
	}

	if addrPass["127.0.0.1:8388"] != "barfoo!" {
		t.Errorf("1st server wrong, got %v", addrPass["127.0.0.1:8388"])
	}

	if addrPass["127.0.1.1:8388"] != "barfoo!" {
		t.Errorf("2ed server wrong, got %v", addrPass["127.0.1.1:8388"])
	}

}

func TestClientMultiServerArray(t *testing.T) {
	config, err := ParseConfig("../sample-config/client-multi-server.json")
	if err != nil {
		t.Fatal("error parsing client-multi-server.json:", err)
	}
	servers := config.RemoteAddrPasswords()
	if len(servers) != 2 {
		t.Error("wrong number of multiple server configs")
	}

	sv := servers[0]
	if len(sv) != 2 {
		t.Fatalf("server_password 1st server wrong, have %d items\n", len(sv[0]))
	}
	if sv[0] != "127.0.0.1:8387" {
		t.Error("server_password 1st server wrong")
	}
	if sv[1] != "foobar" {
		t.Error("server_password 1st server passwd wrong")
	}

	sv = servers[1]
	if len(sv) != 3 {
		t.Fatalf("server_password 2nd server wrong, have %d items\n", len(sv[0]))
	}
	if sv[0] != "127.0.0.1:8388" {
		t.Error("server_password 2nd server wrong")
	}
	if sv[1] != "barfoo" {
		t.Error("server_password 2nd server passwd wrong")
	}
	if sv[2] != "aes-128-cfb" {
		t.Error("server_password 2nd server enc method wrong")
	}
}

func TestParseConfigEmpty(t *testing.T) {
	// make sure we will not crash
	config, err := ParseConfig("testdata/noserver.json")
	if err != nil {
		t.Fatal("error parsing noserver config:", err)
	}

	servers := config.RemoteAddrPasswords()
	if servers != nil {
		t.Error("GetServerArray should return nil if no server option is given")
	}
}
