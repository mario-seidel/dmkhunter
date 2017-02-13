package main

import "fmt"
import "os"
import "io"
import "bufio"
import "log"
import "crypto/md5"
import (
	"encoding/hex"
	//"io/ioutil"
	"time"
	"runtime"
	"path/filepath"
	"gopkg.in/alecthomas/kingpin.v2"
	"regexp"
)

const VERSION = "0.0.5"
const VARDIR = "." //"/var/run/dmkhunter"
const LOGFILE = "/var/log/dmkhunter.log"
const LOCKFILE = "hunt.lock"
const SENDMAIL = "$( which sendmail 2> /dev/null )"
const LOGROTATE_EXECUTABLE = "$( which logrotate 2> /dev/null )"

var (
	pathToScan = kingpin.Arg("path", "root path to scan").Required().String()
	fileList = kingpin.Flag("file-list", "a list of files to scan for").Short('f').Required().String()
	debug = kingpin.Flag("debug", "set debug mode").Short('d').Default("false").Bool()
)

type Md5Info struct {
	filepath string
	hash string
}

type Md5List []*Md5Info

type MyFileinfo struct {
	os.FileInfo
}

func main() {
	cpuUse := runtime.NumCPU()
	//use half CPUs
	runtime.GOMAXPROCS(cpuUse)
	fmt.Println("run on cpu count: ", cpuUse)

	//debug
	startTime := time.Now()

	kingpin.Parse()

	rootPath := *pathToScan

	checkOptions()
	startScan(rootPath)

	stopTime := time.Since(startTime)
	log.Printf("%s", stopTime)
}

func checkOptions() {
	//check filelist exists
	if _, err := os.Stat(*fileList); err != nil {
		log.Fatal(err)
	}
}

func startScan(rootPath string) {
	files, ignores := checkFilelist(*fileList)

	fmt.Println(files, ignores)
	for _,f := range files {
		path := rootPath

		//otherwise Lstat fail if path ends with *
		if f != "*" {
			path += "/" +f
		}
		mdChan := scanPath(path)
		saveToFile(VARDIR + "/newstamp.dat", mdChan)
	}

	//saveToFile(VARDIR + "/newstamp.dat", files)
}

//reads a filelist and start scanning all files recursive
func checkFilelist(filename string) ([]string, []string) {
	var scanList, ignoreList []string

	file, err := os.Open(filename)
	check(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	fileChan := make(chan string)
	ignoreChan := make(chan string)
	quitChan := make(chan int)

	fileCount := 0
	for scanner.Scan() {
		fileCount++
		scanFilePath := scanner.Text()
		go splitFileList(scanFilePath, fileChan, ignoreChan, quitChan)
	}

	for j := 0; j < fileCount; {
		select {
		case f := <-fileChan:
			scanList = append(scanList, f)
			j++
		case i := <-ignoreChan:
			ignoreList = append(ignoreList, i)
			j++
		default:
			//fmt.Print(".")
		}
	}

	return scanList, ignoreList
}

//split filelist in files to scan and files to ignore
func splitFileList(filePath string, files chan string, ignores chan string, quitChan chan int) {
	if (filePath == "") {
		ignores <- ""
		return
	}

	re := regexp.MustCompile("(.+);.*i")
	matchedIgnores := re.FindStringSubmatch(filePath)

	reFiles := regexp.MustCompile("(.+);.*r")
	matchedFiles := reFiles.FindStringSubmatch(filePath)

	switch {
	case len(matchedIgnores) > 1:
		ignores <- matchedIgnores[1]
	case len(matchedFiles) > 1:
		files <- matchedFiles[1]
	default:
		fmt.Println("sendquit")
		files <- ""
	}
}

func scanPath(path string) <- chan *Md5Info {
	//var md5List = Md5List{}
	out := make(chan *Md5Info)

	go func(out chan<- *Md5Info) {
		defer close(out)
		c := make(chan string)
		filepath.Walk(path, func(path string, f os.FileInfo, err error) error {

			if err != nil {
				log.Fatal(err)
			}
			//fileList = append(fileList, path)
			fileI := MyFileinfo{f}
			if !f.IsDir() && !fileI.isSymlink() {
				go hashfile(path, f, c)
				out <- &Md5Info{filepath:path, hash: <-c}
			}
			out <- &Md5Info{filepath:"", hash:""}
			return nil
		})
	}(out)

	return out
}

func hashfile(scanFilePath string, filePath os.FileInfo, c chan string)  {
	//Initialize variable returnMD5String now in case an error has to be returned
	var returnMD5String string

	fullPath := scanFilePath
	file, err := os.Open(fullPath)
	check(err)
	defer file.Close()

	hash := md5.New()

	if _, err := io.Copy(hash, file); err != nil {
		log.Fatal(err)
	}

	hashInBytes := hash.Sum(nil)[:16]

	returnMD5String = hex.EncodeToString(hashInBytes)

	c <- returnMD5String
}

func (f MyFileinfo) isSymlink() bool {
	return (f.FileInfo.Mode() & os.ModeSymlink) == os.ModeSymlink
}

// append to a log file
func appendFile(filePath string, text string) {
	f, err := os.OpenFile(filePath, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	check(err)

	defer f.Close()

	if _, err = f.WriteString(text + "\n"); err != nil {
		panic(err)
	}
}

//saves a map to a file
func saveToFile(filePath string, data <-chan *Md5Info) {
	for info := range data {
		if (*info).hash != "" {
			if *debug {
				log.Println("Key:", (*info).hash, "Value:", (*info).filepath)
			}
			appendFile(filePath, (*info).filepath + ":" + (*info).hash)
		}
	}
}

func buildIgnoreList() {
	//ignoreList = make([]string, 0)

}

func help() {
	fmt.Println("DMKHunter Version", VERSION)
}

//check for an error
func check(err error) {
    if err != nil {
        log.Print(err)
    }
}


