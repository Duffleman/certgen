package certserial

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

	"certgen/lib/cher"

	"github.com/spf13/viper"
)

var filename = "serial_history.txt"

func GetNextSerial(name string) (*big.Int, error) {
	rootDirectory := viper.GetString("SECERTS_ROOT_DIR")
	serialFileName := path.Join(rootDirectory, filename)

	history, err := loadHistory(serialFileName)
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

	err = writeHistory(serialFileName, next, name)
	if err != nil {
		return nil, err
	}

	return next, nil
}

func loadHistory(serialFileName string) (map[string]struct{}, error) {
	if _, err := os.Stat(serialFileName); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		err = ioutil.WriteFile(serialFileName, []byte{}, 0644)
		if err != nil {
			return nil, err
		}

		return map[string]struct{}{}, nil
	}

	file, err := os.Open(serialFileName)
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
				"path": serialFileName,
			})
		}

		parts := bytes.Split(line, []byte(":"))

		i := big.Int{}

		i.SetBytes(parts[0])

		set[i.String()] = struct{}{}
	}

	return set, nil
}

func writeHistory(serialFileName string, next *big.Int, name string) error {
	f, err := os.OpenFile(serialFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	now := time.Now().Format(time.RFC3339)

	if _, err := f.WriteString(fmt.Sprintf("%s:%s:%s\n", next.String(), now, name)); err != nil {
		return err
	}

	return nil
}
