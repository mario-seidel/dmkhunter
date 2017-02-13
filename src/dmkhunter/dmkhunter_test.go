package main

import (
	"testing"
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
		if !strings.HasSuffix(val, "/fixture_filelist.txt") {
			t.Errorf("file is not in list %s", key)
		}
		break
	}
}

func TestMd5Calc(t *testing.T) {
	testfile := "./fixture_filelist.txt"
	list, _ := checkFilelist(testfile)
	ignores := make([]string, 0)


	md5list := scanPath(list[0], &ignores)

	md5Info := <-md5list

	if <-md5Info.hash != "a4c37b105d920bae452805cd48575a2a" {
		t.Errorf("md5 is not correct: %T", md5Info)
	}
}