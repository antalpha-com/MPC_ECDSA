// Copyright © 2023 Antalpha
//
// This file is part of Antalpha. The full Antalpha copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package communication

import (
	"os"
	"testing"
)

func Chdir() (err error) {
	err = os.Chdir("../")
	return
}

func TestLoadConfig(t *testing.T) {
	Chdir()
	var conn LocalConn
	err := conn.LoadConnConfig()
	if err != nil {
		println("fail to load conn config")
	}
	err = conn.LoadKeyGenConfig()
	if err != nil {
		println("fail to load keygen config")
	}
	err = conn.LoadRefreshConfig()
	if err != nil {
		println("fail to load refresh config")
	}
	err = conn.LoadSignConfig()
	if err != nil {
		println("fail to load sign config")
	}
}
