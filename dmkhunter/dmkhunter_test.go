package dmkhunter

import (
	"testing"
	"strings"
	"os"
)

const FIXTUREFILELIST = "../fixtures/fixture_filelist.txt"

func TestScanPath(t *testing.T) {
	testfile := FIXTUREFILELIST
	list, ignores := checkFilelist(testfile)

	if len(list) != 1 {
		t.Errorf("list should not be empty %T", list)
	}

	if len(ignores) > 0 {
		t.Errorf("ignores should be empty %T", ignores)
	}

	for _, val := range list {
		if !strings.HasSuffix(val.path, FIXTUREFILELIST) {
			t.Errorf("file is not in list %s", val)
		}
		break
	}
}

func TestMd5Calc(t *testing.T) {
	testfile := FIXTUREFILELIST
	list, _ := checkFilelist(testfile)
	ignores := make([]string, 0)


	md5list := scanPath(list[0].path, &ignores, false)

	md5Info := <-md5list

	if <-md5Info.hash != "9fbf3128ce489b0aef2eabfb717b84fe" {
		t.Errorf("md5 is not correct: %v", md5Info)
	}

	if fstat, _ := os.Stat(FIXTUREFILELIST); md5Info.filesize != fstat.Size() {
		t.Errorf("filesize is not correct: %v", md5Info.filesize)
	}
}
