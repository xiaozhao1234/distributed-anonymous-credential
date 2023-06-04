package utils

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"unsafe"
)

// BytesToHex converts from an array of bytes to a hex encoded string
func BytesToHex(bytesArray []byte) string {
	r := "0x"
	h := hex.EncodeToString(bytesArray)
	r = r + h
	return r
}

// HexToBytes converts from a hex string into an array of bytes
func HexToBytes(h string) ([]byte, error) {
	b, err := hex.DecodeString(h[2:])
	return b, err
}

func BytesToString(data []byte) string {
	return *(*string)(unsafe.Pointer(&data))
}

func StringToBytes(data string) []byte {
	return *(*[]byte)(unsafe.Pointer(&data))
}

func CheckFileExist(fileName string) bool {
	_, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func FileRead(filename string) []byte {
	f, err := os.Open(filename)
	if err != nil {
		fmt.Println("read file fail", err)
		return StringToBytes("")
	}
	defer f.Close()

	fd, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Println("read to fd fail", err)
		return StringToBytes("")
	}
	a := string(fd)
	ssh := *(*reflect.StringHeader)(unsafe.Pointer(&a))
	b := *(*[]byte)(unsafe.Pointer(&ssh))

	return b
}

func FileWrite(filename string, str string, flag bool) {
	fileName := filename
	strTest := str

	var f *os.File
	var err error

	if flag == true {
		if CheckFileExist(fileName) { //文件存在
			f, err = os.OpenFile(fileName, os.O_APPEND, 0666) //打开文件
			if err != nil {
				fmt.Println("file open fail", err)
				return
			}
		} else { //文件不存在
			f, err = os.Create(fileName) //创建文件
			if err != nil {
				fmt.Println("file create fail")
				return
			}
		}
	} else {
		if CheckFileExist(fileName) { //文件存在
			f, err = os.OpenFile(fileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644) //打开文件
			if err != nil {
				fmt.Println("file open fail", err)
				return
			}
		} else { //文件不存在
			f, err = os.Create(fileName) //创建文件
			if err != nil {
				fmt.Println("file create fail")
				return
			}
		}
	}

	//将文件写进去
	n, err1 := io.WriteString(f, strTest)
	//n, err1 := f.Write(strTest)
	if err1 != nil {
		fmt.Println("write error", err1)
		return
	}
	n = int(n)
}

func FileWriteBytes(filename string, content []byte, flag bool) {
	fileName := filename
	strTest := content

	var f *os.File
	var err error

	if flag == true {
		if CheckFileExist(fileName) { //文件存在
			f, err = os.OpenFile(fileName, os.O_APPEND, 0666) //打开文件
			if err != nil {
				fmt.Println("file open fail", err)
				return
			}
		} else { //文件不存在
			f, err = os.Create(fileName) //创建文件
			if err != nil {
				fmt.Println("file create fail")
				return
			}
		}
	} else {
		if CheckFileExist(fileName) { //文件存在
			f, err = os.OpenFile(fileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644) //打开文件
			if err != nil {
				fmt.Println("file open fail", err)
				return
			}
		} else { //文件不存在
			f, err = os.Create(fileName) //创建文件
			if err != nil {
				fmt.Println("file create fail")
				return
			}
		}
	}

	//将文件写进去
	//n, err1 := io.WriteString(f, strTest)
	fmt.Println("size:", len(strTest))
	n, err1 := f.Write(strTest)
	if err1 != nil {
		fmt.Println("write error", err1)
		return
	}
	n = int(n)
}
