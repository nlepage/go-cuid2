package cuid2

import (
	"crypto/rand"
	"io"
	"math/big"
	"strconv"
	"time"

	"golang.org/x/crypto/sha3"
)

const (
	DefaultLength = 24
	BigLength     = 32

	primeBits = 17
)

func createEntropy(length int, random io.Reader) (string, error) {
	var entropy string

	for len(entropy) < length {
		// generating a random prime instead of using predefined ones
		randomPrime, err := rand.Prime(random, primeBits)
		if err != nil {
			return "", err
		}
		n, err := rand.Int(random, randomPrime)
		if err != nil {
			return "", err
		}
		entropy += n.Text(36)
	}

	return entropy[:length], nil
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
	salt, err := createEntropy(length, rand.Reader)
	if err != nil {
		return "", err
	}

	var text = input + salt

	return bufToBigInt(sha3.Sum512([]byte(text))).Text(36)[1:], nil
}

func randomLetter(random io.Reader) (string, error) {
	i, err := rand.Int(random, big.NewInt(26))
	if err != nil {
		return "", err
	}
	return string(rune(i.Int64() + 97)), nil
}

func createFingerprint(random io.Reader) (string, error) {
	i, err := rand.Int(random, big.NewInt(2063))
	if err != nil {
		return "", err
	}
	// no global object keys to give here...
	return hash(i.String(), 4)
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
		count, err := rand.Int(random, big.NewInt(2057))
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
		fingerprint, err = createFingerprint(random)
		if err != nil {
			return nil, err
		}
	}

	return func() (string, error) {
		time := strconv.FormatInt(time.Now().UnixMilli(), 36)
		randomEntropy, err := createEntropy(length, random)
		if err != nil {
			return "", err
		}
		count := strconv.FormatInt(counter(), 36)
		firstLetter, err := randomLetter(random)
		if err != nil {
			return "", err
		}
		hashInput := time + randomEntropy + count + fingerprint

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
