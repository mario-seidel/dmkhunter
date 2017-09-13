package main

import (
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"runtime"
	"fmt"
	"time"
	"os"
	"./dmkhunter"
)

var (
	pathToScan = kingpin.Arg("path", "root path to scan").Required().String()
	fileList = kingpin.Flag("file-list", "a list of files to scan for").Short('f').Required().String()
	updateFlag = kingpin.Flag("update", "a list of files to scan for").Short('u').Bool()
	debug = kingpin.Flag("debug", "set debug mode").Short('d').Default("false").Bool()
)

func main() {
	//use half CPUs here if needed
	cpuUse := runtime.NumCPU()
	runtime.GOMAXPROCS(cpuUse)
	fmt.Println("run on cpu count: ", cpuUse)

	//debug
	startTime := time.Now()

	//parse commandline arguments
	kingpin.Parse()

	checkOptions()

	dmkhunter.SetDebug(*debug)

	//do the work
	dmkhunter.StartScan(*pathToScan, *updateFlag, *fileList)

	//msg := "test"
	//sendMail("mario@maniox.de", &msg)

	stopTime := time.Since(startTime)
	log.Printf("runtime: %s", stopTime)
	log.Printf("hashes: %d", dmkhunter.GetFilesScanned())
}

//test if all parrameters given are correct
func checkOptions() {
	//check filelist exists
	if _, err := os.Stat(*pathToScan); err != nil {
		log.Println("no scan path given")
	}
}