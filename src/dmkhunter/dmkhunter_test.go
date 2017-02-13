package main

import (
	"testing"
	"fmt"
	"strings"
)

func TestScanPath(t *testing.T) {
	testfile := "./fixture_filelist.txt"
	list, ignores := checkFilelist(testfile)

	if len(list) != 1 {
		t.Errorf("list should not be empty %T", list)
	}

	if len(ignores) > 0 {
		t.Errorf("ignores should be empty %T", ignores)
	}

	for key, val := range list {
		fmt.Print(key, val)
		if !strings.HasSuffix(val, "/fixture_filelist.txt") {
			t.Errorf("file is not in list %s", key)
		}

		if val != "a4c37b105d920bae452805cd48575a2a" {
			t.Errorf("md5 is not correct: %s", val)
		}
		break
	}
}
