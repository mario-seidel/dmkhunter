package dmkhunter

import "fmt"
import "os"
import "io"
import "bufio"
import "log"
import "crypto/md5"
import (
	"encoding/hex"
	"time"
	"path/filepath"
	"regexp"
	"strings"
	"strconv"
	"errors"
	"bytes"
	"net/smtp"
)

const VERSION = "0.0.1"
const VARDIR = "." //"/var/run/dmkhunter"
const STAMPFILE string = VARDIR + "/stamp.dat"
const OLDSTAMPFILE = VARDIR + "/oldstamp.dat"
const LOGFILE = "/var/log/dmkhunter.log"
const LOCKFILE = "hunt.lock"
const SENDMAIL = "$( which sendmail 2> /dev/null )"
const LOGROTATE_EXECUTABLE = "$( which logrotate 2> /dev/null )"

var (
	fileCount int = 0
	debug bool = false
)

//The md5 info for a file with file size.
type Md5Info struct {
	filepath string
	filesize int64
	hash     chan string
}

//List of all MD5 infos.
type Md5List []*Md5Info

//To extend FileInfo with symlink check func.
type MyFileinfo struct {
	os.FileInfo
}

//Path to scan with recursive info.
type ScanPath struct {
	path      string
	recursive bool
}

//Result after file has been checked.
type CheckResult struct {
	md5Info *Md5Info
	equal   bool
	err     error
}

//Start the scan process from a given root path
func StartScan(rootPath string, updateFile bool, fileList string) {
	files, ignores := checkFilelist(fileList)

	//read md5 hash list from channel (old stamp file)
	md5CompareList := <-readHashfile(STAMPFILE)
	var fileTextBuffer bytes.Buffer

	for _, f := range files {
		path := rootPath

		//otherwise Lstat fail if path ends with *
		if f.path != "*" {
			path += "/" + f.path
		}

		md5InfoChan := scanPath(path, &ignores, f.recursive)
		checkResultChan := compareDir(md5InfoChan, &md5CompareList)

		for checkResult := range checkResultChan {

			if !updateFile && debug && checkResult.equal == false {
				log.Println("File change detected:", checkResult.err)
			}

			info := checkResult.md5Info
			fileHash := <-(*info).hash
			fileTextBuffer.WriteString(
				fmt.Sprintf("%s:%d:%s\n", (*info).filepath, (*info).filesize, fileHash))
		}
	}
	if updateFile == true && fileTextBuffer.Len() > 0 {
		//rotateStampFiles(OLDSTAMPFILE, STAMPFILE)
		writeToFile(STAMPFILE, &fileTextBuffer)
	}
}

func SetDebug(isDebug bool) {
	debug = isDebug
}

func GetFilesScanned() int {
	return fileCount
}

func init() {
	//var out, err = os.OpenFile("logdmk.txt", os.O_CREATE | os.O_WRONLY, os.ModePerm | os.ModeAppend)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//defer out.Close()
	//log.SetOutput(out)
}

//TODO: we dont need to rotate, cause only one stamp file is needed
func rotateStampFiles(oldStampFile string, stampFile string) {
	if _, err := os.Stat(oldStampFile); err != nil {
		if fileErr := os.Remove(oldStampFile); fileErr != nil && !os.IsNotExist(fileErr) {
			log.Fatal("error remove " + oldStampFile)
		}
	}
	if _, err := os.Stat(stampFile); err == nil {
		if fileErr := os.Rename(stampFile, oldStampFile); fileErr != nil {
			log.Fatal("error move stamp to oldstamp")
		}
	}
}

// test if path is in ignore list
func readHashfile(hashfile string) <- chan Md5List {
	sf, err := os.Open(hashfile)
	if err != nil {
		log.Println(err)
	}

	scan := bufio.NewScanner(sf)
	md5List := Md5List{}

	md5ListChan := make(chan Md5List)

	go func() {
		defer sf.Close()
		defer close(md5ListChan)
		for scan.Scan() {
			line := scan.Text()
			s := strings.SplitN(line, ":", 3)
			if len(s) != 3 {
				log.Fatal("could not read line from stamp file: ", line)
			}
			hashChan := make(chan string)
			path, size, hash := s[0], s[1], s[2]

			sizeByte, _ := strconv.ParseInt(size, 10, 64)

			//send hash to hashChan
			go func() { hashChan <- hash }()

			fileInfo := Md5Info{filepath:path, filesize: sizeByte, hash: hashChan}
			md5List = append(md5List, &fileInfo)
		}
		md5ListChan <- md5List
	}()

	return md5ListChan
}

//reads a filelist and start scanning all files recursive
func isPathAllowed(path string, patterns *[]string) bool {
	for _, pattern := range *patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Fatal(err)
		}
		if re.MatchString(path) {
			return false
		}
	}
	return true
}

//split filelist in files to scan and files to ignore
func checkFilelist(filename string) ([]ScanPath, []string) {
	var scanList []ScanPath
	var ignoreList []string

	//open filelist
	file, err := os.Open(filename)
	if err != nil {
		log.Println("no filelist, scan all")
		scanList = append(scanList, ScanPath{path:"", recursive: true})
		return scanList, ignoreList
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	fileChan := make(chan ScanPath)
	ignoreChan := make(chan string)

	//read each line
	fileCount := 0
	for scanner.Scan() {
		scanFilePath := scanner.Text()
		if !strings.HasPrefix(scanFilePath, "#") && scanFilePath != "" {
			fileCount++
			//seperate files to scan and files to ignore
			go splitFileList(scanFilePath, fileChan, ignoreChan)
		}
	}

	for j := 0; j < fileCount; {
		select {
		case f := <-fileChan:
			scanList = append(scanList, f)
			j++
		case i := <-ignoreChan:
			ignoreList = append(ignoreList, i)
			j++
		case <-time.After(time.Minute * 1):
			log.Fatal("Error: timeout reading filelist")
		}
	}

	return scanList, ignoreList
}

// walk through a path an go deep if recursive flag is set
// return a channel of Md5Info with the concurrent calculated hash infos
func splitFileList(scanPath string, files chan ScanPath, ignores chan string) {

	split := strings.Split(scanPath, ";")

	if len(split) > 0 {
		switch {
		case len(split) == 1 && len(split[0]) > 0 :
			files <- ScanPath{path: split[0], recursive: false}
		case strings.Contains(split[1], "i"):
			ignores <- split[0]
		case strings.Contains(split[1], "r"):
			files <- ScanPath{path: split[0], recursive: true}
		default:
			log.Fatal("error reading line in filelist: ", scanPath)
		}
	} else {
		log.Fatal("error parse line", scanPath)
	}
}

// hashes the content of a given path and return the result to a channel of string
func scanPath(rootPath string, ignores *[]string, recursive bool) <- chan *Md5Info {
	//var md5List = Md5List{}
	out := make(chan *Md5Info)

	go func() {
		defer close(out)
		filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {

			if err != nil {
				log.Fatal(err)
			}

			if (!recursive && info.IsDir() && path != rootPath) {
				return filepath.SkipDir
			}
			hashChan := make(chan string)
			if isPathAllowed(path, ignores) {
				fileI := MyFileinfo{info}

				if !info.IsDir() && !fileI.isSymlink()  {
					fileCount++

					go hashfile(path, hashChan)
					out <- &Md5Info{filepath:path, filesize: fileI.Size(), hash: hashChan}
				}
			} else {
				//log.Printf("%s is not allowed skip dir %s", path, ignores)
				//should we skip if ignore pattern match?
				//if f.IsDir() {
				//	return filepath.SkipDir
				//}
				//out <- &Md5Info{filepath:"", hash: c}
			}

			return nil
		})
	}()

	return out
}

// calculate the md5 hash of a file and return the result to a channel
func hashfile(scanFilePath string, c chan string) {
	//Initialize variable returnMD5String now in case an error has to be returned
	var returnMD5String string

	file, err := os.Open(scanFilePath)
	if err != nil {
		log.Println("cannot open file", scanFilePath)
		c <- ""
		return
	}
	defer file.Close()

	hash := md5.New()

	if _, err := io.Copy(hash, file); err != nil {
		log.Fatal(err)
	}

	hashInBytes := hash.Sum(nil)[:16]

	returnMD5String = hex.EncodeToString(hashInBytes)

	c <- returnMD5String
}

// compare a Md5Info from a stream with a list of Md5Infos given from the oldstamp file
// return a channel with the check result streamed to it
func (f MyFileinfo) isSymlink() bool {
	return (f.FileInfo.Mode() & os.ModeSymlink) == os.ModeSymlink
}

//saves a map to a file
func compareDir(data <-chan *Md5Info, compare *Md5List) <- chan CheckResult {

	checkResultChan := make(chan CheckResult)

	go func() {
		defer close(checkResultChan)
		for info := range data {
			result, checkError := checkFileChange(info, compare)
			checkResultChan <- CheckResult{md5Info: info, equal: result, err: checkError}
		}
	}()

	return checkResultChan
}

// test if a md5 hash is in oldstamp an is correct
// returns false if the hash or filesize is not the same an an error with description
func writeToFile(filePath string, text *bytes.Buffer) {
	f, err := os.OpenFile(filePath, os.O_RDWR | os.O_CREATE, 0600)
	if err != nil {
		log.Fatal("could not write file", err)
	}

	defer f.Close()

	if _, err = f.WriteString((*text).String()); err != nil {
		log.Panic(err)
	}
}

// compare two Md5Info structs and test md5 hash and filesize
// return error if not equal
func checkFileChange(info *Md5Info, compareList *Md5List) (bool, error) {

	for _, compareFile := range *compareList {
		if info.filepath == compareFile.filepath {
			result := compareFileInfo(info, compareFile)

			return (result == nil), result
		}
	}

	return false, errors.New("new file: " + (*info).filepath)
}

func compareFileInfo(info *Md5Info, compare *Md5Info) (checkError error) {
	fileHash := <-(*info).hash
	//resend hash, because we need them later
	go func() {
		(*info).hash <- fileHash
	}()
	compareHash := <-compare.hash

	if info.filesize != compare.filesize {
		checkError = errors.New("filesize is not the same " + (*info).filepath)
	}

	if fileHash != compareHash {
		errString := fmt.Sprintf(
			"hash diff %s: \n%s<->%s",
			info.filepath, fileHash, compareHash)
		checkError = errors.New(errString)
	}

	return
}

//TODO: testing
func sendMail(receiver string, message *string) {
	auth := smtp.PlainAuth("", "mario", "", "localhost")

	to := []string{receiver}
	msg := []byte(*message)

	err := smtp.SendMail("localhost:1025", auth, "mario@localhost", to, msg)

	if err != nil {
		log.Fatal(err)
	}
}
