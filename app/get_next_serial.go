package app

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"time"

	"certgen"
	"certgen/lib/cher"
)

// getNextSerial gets the next serial number to issue, but does not save it yet
func (a *App) getNextSerial(certType certgen.CertificateType, name string) (*big.Int, error) {
	history, err := a.loadSerialFile()
	if err != nil {
		return nil, err
	}

	var next *big.Int

	for {
		next, err = rand.Int(rand.Reader, big.NewInt(big.MaxExp))
		if err != nil {
			return nil, err
		}

		if _, ok := history[next.String()]; !ok {
			break
		}
	}

	return next, nil
}

// loadSerialFile loads the contents of the serial file into a map
func (a *App) loadSerialFile() (map[string]struct{}, error) {
	serialFilePath := path.Join(a.RootDirectory, "serial_history.txt")

	if _, err := os.Stat(serialFilePath); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		err = ioutil.WriteFile(serialFilePath, []byte{}, 0644)
		if err != nil {
			return nil, err
		}

		return map[string]struct{}{}, nil
	}

	file, err := os.Open(serialFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	set := map[string]struct{}{}

	for {
		line, prefix, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, err
		}

		if prefix {
			return nil, cher.New("line_too_long", cher.M{
				"path": serialFilePath,
			})
		}

		parts := bytes.Split(line, []byte(":"))

		i := big.Int{}

		i.SetBytes(parts[0])

		set[i.String()] = struct{}{}
	}

	return set, nil
}

// writeSerialFile writes to the serial file
func (a *App) writeSerialFile(next *big.Int, key string) error {
	serialFilePath := path.Join(a.RootDirectory, "serial_history.txt")

	f, err := os.OpenFile(serialFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	now := time.Now().Format(time.RFC3339)

	if _, err := f.WriteString(fmt.Sprintf("%s:%s:%s\n", next.String(), now, key)); err != nil {
		return err
	}

	return nil
}
