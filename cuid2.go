package cuid2

import (
	"crypto/rand"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"
)

const (
	DefaultLength = 24
	BigLength     = 32
)

var (
	big36   = big.NewInt(36)
	big26   = big.NewInt(26)
	big2063 = big.NewInt(2063)

	initialCountMax = big.NewInt(476782367)
)

func createEntropy(length int, random io.Reader) (string, error) {
	var entropy string

	for len(entropy) < length {
		n, err := rand.Int(random, big36)
		if err != nil {
			return "", err
		}
		entropy += n.Text(36)
	}

	return entropy, nil
}

func bufToBigInt(buf [64]byte) *big.Int {
	const bits = 8
	var value = big.NewInt(0)

	for _, i := range buf {
		var bi = big.NewInt(int64(i))
		// using Or instead of Add should be equivalent
		value.Or(value.Lsh(value, bits), bi)
	}

	return value
}

func hash(input string, length int) (string, error) {
	return bufToBigInt(sha3.Sum512([]byte(input))).Text(36)[1:], nil
}

func randomLetter(random io.Reader) (string, error) {
	i, err := rand.Int(random, big26)
	if err != nil {
		return "", err
	}
	return string(rune(i.Int64() + 97)), nil
}

func createFingerprint(env []string, random io.Reader) (string, error) {
	if env == nil {
		env = os.Environ()

		hostname, err := os.Hostname()
		if err != nil {
			return "", err
		}

		env = append(env, hostname, strconv.Itoa(os.Getpid()))
	}

	salt, err := createEntropy(BigLength, random)
	if err != nil {
		return "", err
	}

	fingerprint, err := hash(strings.Join(env, ",")+salt, BigLength)
	if err != nil {
		return "", err
	}

	return fingerprint[:BigLength], nil
}

func createCounter(count int64) func() int64 {
	return func() int64 {
		defer func() {
			count++
		}()
		return count
	}
}

type Options struct {
	Rand        io.Reader
	Counter     func() int64
	Length      int
	Fingerprint string
}

func Init(options Options) (func() (string, error), error) {
	var random = options.Rand
	if random == nil {
		random = rand.Reader
	}

	var counter = options.Counter
	if counter == nil {
		count, err := rand.Int(random, initialCountMax)
		if err != nil {
			return nil, err
		}
		counter = createCounter(count.Int64())
	}

	var length = options.Length
	if length == 0 {
		length = DefaultLength
	}

	var fingerprint = options.Fingerprint
	if fingerprint == "" {
		var err error
		fingerprint, err = createFingerprint(nil, random)
		if err != nil {
			return nil, err
		}
	}

	return func() (string, error) {
		firstLetter, err := randomLetter(random)

		time := strconv.FormatInt(time.Now().UnixMilli(), 36)

		count := strconv.FormatInt(counter(), 36)
		if err != nil {
			return "", err
		}

		salt, err := createEntropy(length, random)
		if err != nil {
			return "", err
		}

		hashInput := time + salt + count + fingerprint

		hashOutput, err := hash(hashInput, length)
		if err != nil {
			return "", err
		}

		return firstLetter + hashOutput[1:length], nil
	}, nil
}

var createId func() (string, error)

func init() {
	var err error
	createId, err = Init(Options{})
	if err != nil {
		panic(err)
	}
}

func CreateId() (string, error) {
	return createId()
}
