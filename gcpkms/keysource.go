package gcpkms //import "go.mozilla.org/sops/v3/gcpkms"

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"os"
	"regexp"
	"strings"
	"time"

	"go.mozilla.org/sops/v3/logging"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

var log *logrus.Logger

func init() {
	log = logging.NewLogger("GCPKMS")
}

// MasterKey is a GCP KMS key used to encrypt and decrypt sops' data key.
type MasterKey struct {
	ResourceID   string
	EncryptedKey string
	CreationDate time.Time
}

// EncryptedDataKey returns the encrypted data key this master key holds
func (key *MasterKey) EncryptedDataKey() []byte {
	return []byte(key.EncryptedKey)
}

// SetEncryptedDataKey sets the encrypted data key for this master key
func (key *MasterKey) SetEncryptedDataKey(enc []byte) {
	key.EncryptedKey = string(enc)
}

// Encrypt takes a sops data key, encrypts it with GCP KMS and stores the result in the EncryptedKey field
func (key *MasterKey) Encrypt(dataKey []byte) error {
	cloudkmsService, err := key.createCloudKMSService()
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Encryption failed")
		return fmt.Errorf("Cannot create GCP KMS service: %w", err)
	}

	purpose, err := key.purpose(cloudkmsService)
	if err != nil {
		return err
	}

	switch purpose {
	case "ENCRYPT_DECRYPT":
		return key.encryptSymmetric(cloudkmsService, dataKey)
	case "ASYMMETRIC_DECRYPT":
		return key.encryptAsymmetric(cloudkmsService, dataKey)
	}

	log.WithField("resourceID", key.ResourceID).WithField("purpose", purpose).Info("This key cannot be used for encryption")
	return fmt.Errorf("This key cannot be used for encryption, purpose: %s", purpose)
}

func (key *MasterKey) purpose(cloudkmsService *cloudkms.Service) (string, error) {
	// It needs to use `projects/project-id/locations/location/keyRings/keyring/cryptoKeys/key` to request.
	// If request with format `projects/project-id/locations/location/keyRings/keyring/cryptoKeys/key/cryptoKeyVersions/version`,
	// KMS will response without `purpose`.
	resp, err := cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Get(key.resourceIDWithoutVersion()).Do()
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Get key info failed")
		return "", fmt.Errorf("Get key from GCP KMS failed: %w", err)
	}

	return resp.Purpose, nil
}

func (key *MasterKey) encryptSymmetric(cloudkmsService *cloudkms.Service, dataKey []byte) error {
	req := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(dataKey),
	}
	resp, err := cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(key.ResourceID, req).Do()
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Encryption failed")
		return fmt.Errorf("Failed to call GCP KMS encryption service: %w", err)
	}
	log.WithField("resourceID", key.ResourceID).Info("Encryption succeeded")
	key.EncryptedKey = resp.Ciphertext
	return nil
}

func (key *MasterKey) encryptAsymmetric(cloudkmsService *cloudkms.Service, dataKey []byte) error {
	resp, err := cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.GetPublicKey(key.ResourceID).Do()
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Get public key failed")
		return fmt.Errorf("Get public key from GCP KMS failed: %w", err)
	}

	if resp.PemCrc32c != int64(crc32c([]byte(resp.Pem))) {
		log.WithField("resourceID", key.ResourceID).Info("Get public key response corrupted in-transit")
		return errors.New("Get public key response corrupted in-transit")
	}

	block, _ := pem.Decode([]byte(resp.Pem))
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Failed to parse public key")
		return fmt.Errorf("Failed to parse public key: %w", err)
	}
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		log.WithField("resourceID", key.ResourceID).Info("Public key is not RSA")
		return errors.New("Public key is not RSA")
	}

	var hash hash.Hash

	switch resp.Algorithm {
	case "RSA_DECRYPT_OAEP_2048_SHA256":
		hash = sha256.New()
	case "RSA_DECRYPT_OAEP_3072_SHA256":
		hash = sha256.New()
	case "RSA_DECRYPT_OAEP_4096_SHA256":
		hash = sha256.New()
	case "RSA_DECRYPT_OAEP_4096_SHA512":
		hash = sha512.New()
	case "RSA_DECRYPT_OAEP_2048_SHA1":
		hash = sha1.New()
	case "RSA_DECRYPT_OAEP_3072_SHA1":
		hash = sha1.New()
	case "RSA_DECRYPT_OAEP_4096_SHA1":
		hash = sha1.New()
	default:
		log.WithField("resourceID", key.ResourceID).WithField("algorithm", resp.Algorithm).Info("Unsupported algorithm")
		return fmt.Errorf("Key with unsupported algorithm: %s", resp.Algorithm)
	}

	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, rsaKey, dataKey, nil)
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("rsa.EncryptOAEP() error")
		return fmt.Errorf("rsa.EncryptOAEP: %w", err)
	}

	key.EncryptedKey = base64.StdEncoding.EncodeToString(ciphertext)

	return nil
}

// EncryptIfNeeded encrypts the provided sops' data key and encrypts it if it hasn't been encrypted yet
func (key *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if key.EncryptedKey == "" {
		return key.Encrypt(dataKey)
	}
	return nil
}

// Decrypt decrypts the EncryptedKey field with CGP KMS and returns the result.
func (key *MasterKey) Decrypt() ([]byte, error) {
	cloudkmsService, err := key.createCloudKMSService()
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Decryption failed")
		return nil, fmt.Errorf("Cannot create GCP KMS service: %w", err)
	}

	purpose, err := key.purpose(cloudkmsService)
	if err != nil {
		return nil, err
	}

	switch purpose {
	case "ENCRYPT_DECRYPT":
		return key.decryptSymmetric(cloudkmsService)
	case "ASYMMETRIC_DECRYPT":
		return key.decryptAsymmetric(cloudkmsService)
	default:
		log.WithField("resourceID", key.ResourceID).WithField("purpose", purpose).Info("This key cannot be used for decryption")
		return nil, fmt.Errorf("This key cannot be used for decryption, purpose: %s", purpose)
	}
}

func (key *MasterKey) decryptSymmetric(cloudkmsService *cloudkms.Service) ([]byte, error) {
	req := &cloudkms.DecryptRequest{
		Ciphertext: key.EncryptedKey,
	}
	resp, err := cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(key.ResourceID, req).Do()
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Decryption failed")
		return nil, fmt.Errorf("Error decrypting key: %w", err)
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Decryption failed")
		return nil, err
	}
	log.WithField("resourceID", key.ResourceID).Info("Decryption succeeded")
	return encryptedKey, nil
}

func (key *MasterKey) decryptAsymmetric(cloudkmsService *cloudkms.Service) ([]byte, error) {
	req := &cloudkms.AsymmetricDecryptRequest{
		Ciphertext: key.EncryptedKey,
	}
	resp, err := cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.AsymmetricDecrypt(key.ResourceID, req).Do()
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Asymmetric decryption failed")
		return nil, fmt.Errorf("Error decrypting key: %w", err)
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		log.WithField("resourceID", key.ResourceID).Info("Asymmetric decryption failed")
		return nil, err
	}
	log.WithField("resourceID", key.ResourceID).Info("Asymmetric decryption succeeded")
	return encryptedKey, nil
}

// NeedsRotation returns whether the data key needs to be rotated or not.
func (key *MasterKey) NeedsRotation() bool {
	return time.Since(key.CreationDate) > (time.Hour * 24 * 30 * 6)
}

// ToString converts the key to a string representation
func (key *MasterKey) ToString() string {
	return key.ResourceID
}

// NewMasterKeyFromResourceID takes a GCP KMS resource ID string and returns a new MasterKey for that
func NewMasterKeyFromResourceID(resourceID string) *MasterKey {
	k := &MasterKey{}
	resourceID = strings.Replace(resourceID, " ", "", -1)
	k.ResourceID = resourceID
	k.CreationDate = time.Now().UTC()
	return k
}

// MasterKeysFromResourceIDString takes a comma separated list of GCP KMS resource IDs and returns a slice of new MasterKeys for them
func MasterKeysFromResourceIDString(resourceID string) []*MasterKey {
	var keys []*MasterKey
	if resourceID == "" {
		return keys
	}
	for _, s := range strings.Split(resourceID, ",") {
		keys = append(keys, NewMasterKeyFromResourceID(s))
	}
	return keys
}

func (key MasterKey) createCloudKMSService() (*cloudkms.Service, error) {
	re := regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+(?:/cryptoKeyVersions/[^/]+)?$`)
	matches := re.FindStringSubmatch(key.ResourceID)
	if matches == nil {
		return nil, fmt.Errorf("No valid resourceId found in %q", key.ResourceID)
	}

	ctx := context.Background()
	var options []option.ClientOption

	if credentials, err := getGoogleCredentials(); err != nil {
		return nil, err
	} else if len(credentials) > 0 {
		options = append(options, option.WithCredentialsJSON(credentials))
	}

	cloudkmsService, err := cloudkms.NewService(ctx, options...)
	if err != nil {
		return nil, err
	}
	return cloudkmsService, nil
}

// ToMap converts the MasterKey to a map for serialization purposes
func (key MasterKey) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	out["resource_id"] = key.ResourceID
	out["enc"] = key.EncryptedKey
	out["created_at"] = key.CreationDate.UTC().Format(time.RFC3339)
	return out
}

// assume key.ResourceID is in following format
//   - `projects/project-id/locations/location/keyRings/keyring/cryptoKeys/key`
//   - `projects/project-id/locations/location/keyRings/keyring/cryptoKeys/key/cryptoKeyVersions/version`
func (key MasterKey) resourceIDWithoutVersion() string {
	re := regexp.MustCompile(`^(projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+)(?:/cryptoKeyVersions/[^/]+)?$`)
	matches := re.FindStringSubmatch(key.ResourceID)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// getGoogleCredentials looks for a GCP Service Account in the environment
// variable: GOOGLE_CREDENTIALS, set as either a path to a credentials file or directly as the
// variable's value in JSON format.
//
// If not set, will default to use GOOGLE_APPLICATION_CREDENTIALS
func getGoogleCredentials() ([]byte, error) {
	defaultCredentials := os.Getenv("GOOGLE_CREDENTIALS")
	if _, err := os.Stat(defaultCredentials); err == nil {
		return os.ReadFile(defaultCredentials)
	}
	return []byte(defaultCredentials), nil
}

func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}
