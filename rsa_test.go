package rsa

import (
	"crypto"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type RSATestSuite struct {
	suite.Suite
	pkcs1PrivateKey []byte
	pkcs1PublicKey  []byte
	pkcs8PrivateKey []byte
	pkcs8PublicKey  []byte
}

// TestRSATestSuite runs the RSA test suite
func TestRSATestSuite(t *testing.T) {
	suite.Run(t, new(RSATestSuite))
}

// SetupSuite run once at the very start of the testing suite, before any tests are run.
func (ts *RSATestSuite) SetupSuite() {
	ts.pkcs1PublicKey, ts.pkcs1PrivateKey = GenKeyPair(PKCS1, 1024)
	ts.pkcs8PublicKey, ts.pkcs8PrivateKey = GenKeyPair(PKCS8, 2048)
	fmt.Println(string(ts.pkcs8PublicKey))
}

// TearDownSuite run once at the very end of the testing suite, after all tests have been run.
func (ts *RSATestSuite) TearDownSuite() {

}

func (ts *RSATestSuite) VerifyKeyPair() {
	should := require.New(ts.T())
	should.True(VerifyKeyPair(ts.pkcs1PublicKey, ts.pkcs1PrivateKey))
	should.True(VerifyKeyPair(ts.pkcs8PublicKey, ts.pkcs8PrivateKey))
}

func (ts *RSATestSuite) TestIsPublicKey() {
	should := require.New(ts.T())

	invalidKey := "abc"
	should.False(IsPublicKey([]byte(invalidKey)))

	should.True(IsPublicKey(ts.pkcs1PublicKey))
	should.True(IsPublicKey(ts.pkcs8PublicKey))
}

func (ts *RSATestSuite) TestIsPrivateKey() {
	should := require.New(ts.T())

	invalidKey := "abc"
	should.False(IsPrivateKey([]byte(invalidKey)))

	should.True(IsPrivateKey(ts.pkcs1PrivateKey))
	should.True(IsPrivateKey(ts.pkcs8PrivateKey))
}

func (ts *RSATestSuite) TestCompressAndFormat() {
	should := require.New(ts.T())

	_, err := CompressKey([]byte("xxx"))
	should.Equal(invalidRSAKeyError(), err)

	compressed, err := CompressKey(ts.pkcs1PrivateKey)
	should.NoError(err)
	origin := FormatPrivateKey(PKCS1, compressed)
	should.Equal(ts.pkcs1PrivateKey, origin)

	compressed, err = CompressKey(ts.pkcs1PublicKey)
	should.NoError(err)
	origin = FormatPublicKey(PKCS1, compressed)
	should.Equal(ts.pkcs1PublicKey, origin)

	compressed, err = CompressKey(ts.pkcs8PrivateKey)
	should.NoError(err)
	origin = FormatPrivateKey(PKCS8, compressed)
	should.Equal(ts.pkcs8PrivateKey, origin)

	compressed, err = CompressKey(ts.pkcs8PublicKey)
	should.NoError(err)
	origin = FormatPublicKey(PKCS8, compressed)
	should.Equal(ts.pkcs8PublicKey, origin)
}

func (ts *RSATestSuite) TestParseKeys() {
	should := require.New(ts.T())

	invalidKey := "abc"
	_, err := ParsePublicKey([]byte(invalidKey))
	should.Error(err)

	pub, err := ParsePublicKey(ts.pkcs1PublicKey)
	should.NoError(err)
	should.NotNil(pub)

	pub, err = ParsePublicKey(ts.pkcs8PublicKey)
	should.NoError(err)
	should.NotNil(pub)

	_, err = ParsePrivateKey([]byte(invalidKey))
	should.Error(err)

	pri, err := ParsePrivateKey(ts.pkcs1PrivateKey)
	should.NoError(err)
	should.NotNil(pri)

	pri, err = ParsePrivateKey(ts.pkcs8PrivateKey)
	should.NoError(err)
	should.NotNil(pri)
}

func (ts *RSATestSuite) TestExportPublicKey() {
	should := require.New(ts.T())

	_, err := ExportPublicKey([]byte("invalid key"))
	should.Error(err)

	pub, err := ExportPublicKey(ts.pkcs1PrivateKey)
	should.NoError(err)
	should.Equal(ts.pkcs1PublicKey, pub)

	pub, err = ExportPublicKey(ts.pkcs8PrivateKey)
	should.NoError(err)
	should.Equal(ts.pkcs8PublicKey, pub)
}

func (ts *RSATestSuite) TestEncryptAndDecrypt() {
	should := require.New(ts.T())

	src := []byte("some data to encrypt")

	// pkcs1 encrypt & decrypt
	dst, err := EncryptByPublicKey(src, ts.pkcs1PublicKey)
	should.NoError(err)
	should.NotEmpty(dst)

	src2, err := DecryptByPrivateKey(dst, ts.pkcs1PrivateKey)
	should.NoError(err)
	should.Equal(src, src2)

	dst, err = EncryptByPrivateKey(src, ts.pkcs1PrivateKey)
	should.NoError(err)
	should.NotEmpty(dst)

	src2, err = DecryptByPublicKey(dst, ts.pkcs1PublicKey)
	should.NoError(err)
	should.Equal(src, src2)

	// pkcs8 encrypt & decrypt
	dst, err = EncryptByPublicKey(src, ts.pkcs8PublicKey)
	should.NoError(err)
	should.NotEmpty(dst)

	src2, err = DecryptByPrivateKey(dst, ts.pkcs8PrivateKey)
	should.NoError(err)
	should.Equal(src, src2)

	dst, err = EncryptByPrivateKey(src, ts.pkcs8PrivateKey)
	should.NoError(err)
	should.NotEmpty(dst)

	src2, err = DecryptByPublicKey(dst, ts.pkcs8PublicKey)
	should.NoError(err)
	should.Equal(src, src2)
}

func (ts *RSATestSuite) TestSignAndVerify() {
	should := require.New(ts.T())

	src := []byte("some data to sign")

	// pkcs1 sign & verify
	dst, err := SignByPrivateKey(src, ts.pkcs1PrivateKey, crypto.SHA1)
	should.NoError(err)
	should.NotEmpty(dst)

	err = VerifyByPublicKey(src, dst, ts.pkcs1PublicKey, crypto.SHA1)
	should.NoError(err)

	// pkcs8 sign & verify
	dst, err = SignByPrivateKey(src, ts.pkcs8PrivateKey, crypto.SHA256)
	should.NoError(err)
	should.NotEmpty(dst)

	err = VerifyByPublicKey(src, dst, ts.pkcs8PublicKey, crypto.SHA256)
	should.NoError(err)
}

func (ts *RSATestSuite) TestVerifyKeyPair() {
	should := require.New(ts.T())

	should.True(VerifyKeyPair(ts.pkcs1PublicKey, ts.pkcs1PrivateKey))
	should.True(VerifyKeyPair(ts.pkcs8PublicKey, ts.pkcs8PrivateKey))
}
