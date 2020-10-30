package certserial

import (
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

func GetNextSerial() (*big.Int, error) {
	bytes, err := ioutil.ReadFile("./serial.txt")
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		bytes = []byte("1")
	}

	base := &big.Int{}
	contents := strings.TrimSpace(string(bytes))

	returnInt, ok := base.SetString(contents, 10)
	if !ok {
		return nil, errors.New("cannot set big int")
	}

	newInt := returnInt.Add(returnInt, big.NewInt(1))

	err = ioutil.WriteFile("./serial.txt", []byte(newInt.String()), 0600)
	if err != nil {
		return nil, err
	}

	return returnInt, nil
}
