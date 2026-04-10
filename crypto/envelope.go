package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	FormatV0 = 0 // Direct AES-256-GCM: version(1) + IV(12) + ciphertext (key used directly)
	FormatV1 = 1 // Envelope: version(1) + header + key slots + IV(12) + ciphertext (DEK wrapped)

	KeySize   = 32 // AES-256
	NonceSize = 12 // AES-GCM standard nonce
	TagSize   = 16 // AES-GCM authentication tag

	KeyIDSize       = 32                           // SHA-256 of user key
	EncryptedDEKLen = NonceSize + KeySize + TagSize // IV + encrypted DEK + tag
	KeySlotSize     = KeyIDSize + EncryptedDEKLen   // 32 + 60 = 92 bytes
	V1HeaderSize    = 1 + 2 + 8 + 8                // format(1) + numSlots(2) + createdAt(8) + version(8) = 19 bytes
	V0HeaderSize    = 1                             // format(1) only
	V0MinSize       = V0HeaderSize + NonceSize + TagSize
)

var (
	ErrInvalidKeySize    = errors.New("encryption key must be 32 bytes")
	ErrNoKeySlots        = errors.New("at least one encryption key is required")
	ErrKeyNotFound       = errors.New("no matching key slot found")
	ErrInvalidEnvelope   = errors.New("invalid envelope format")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrUnsupportedFormat = errors.New("unsupported envelope format version")
	ErrDuplicateKey      = errors.New("key already exists in envelope")
	ErrLastKey           = errors.New("cannot remove the last key slot")
	ErrV0NoKeySlots      = errors.New("v0 format does not support key slot operations")
)

// Envelope represents the encrypted blob stored in R2.
type Envelope struct {
	FormatVersion uint8
	CreatedAt     time.Time
	ValueVersion  uint64
	KeySlots      []KeySlot
	Nonce         [NonceSize]byte
	Ciphertext    []byte // includes GCM tag
}

// KeySlot holds an encrypted copy of the DEK for one user key.
type KeySlot struct {
	KeyID        [KeyIDSize]byte
	EncryptedDEK [EncryptedDEKLen]byte
}

// KeyID computes the SHA-256 fingerprint used to identify a key slot.
func KeyID(userKey []byte) [KeyIDSize]byte {
	return sha256.Sum256(userKey)
}

// DetectFormat returns the format version of a blob without fully parsing it.
func DetectFormat(data []byte) (uint8, error) {
	if len(data) == 0 {
		return 0, ErrInvalidEnvelope
	}
	return data[0], nil
}

// SealV0 encrypts a plaintext value directly with the provided key (no DEK, no key slots).
// Format: 0x00 || IV(12) || AES-GCM(key, plaintext)
func SealV0(value []byte, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, value, nil)

	buf := make([]byte, V0HeaderSize+NonceSize+len(ciphertext))
	buf[0] = FormatV0
	copy(buf[V0HeaderSize:], nonce)
	copy(buf[V0HeaderSize+NonceSize:], ciphertext)

	return buf, nil
}

// OpenV0 decrypts a v0 blob directly with the provided key.
func OpenV0(data []byte, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	if len(data) < V0MinSize {
		return nil, ErrInvalidEnvelope
	}
	if data[0] != FormatV0 {
		return nil, fmt.Errorf("%w: expected v0, got v%d", ErrUnsupportedFormat, data[0])
	}

	nonce := data[V0HeaderSize : V0HeaderSize+NonceSize]
	ciphertext := data[V0HeaderSize+NonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// Open decrypts a blob, auto-detecting the format version.
func Open(data []byte, userKey []byte) ([]byte, *Envelope, error) {
	if len(data) == 0 {
		return nil, nil, ErrInvalidEnvelope
	}

	switch data[0] {
	case FormatV0:
		plaintext, err := OpenV0(data, userKey)
		if err != nil {
			return nil, nil, err
		}
		return plaintext, &Envelope{FormatVersion: FormatV0}, nil
	case FormatV1:
		return openV1(data, userKey)
	default:
		return nil, nil, fmt.Errorf("%w: got %d", ErrUnsupportedFormat, data[0])
	}
}

// Seal encrypts a plaintext value using v1 envelope format, wrapping the DEK under each provided user key.
func Seal(value []byte, userKeys [][]byte, createdAt time.Time, valueVersion uint64) ([]byte, error) {
	if len(userKeys) == 0 {
		return nil, ErrNoKeySlots
	}
	for _, k := range userKeys {
		if len(k) != KeySize {
			return nil, ErrInvalidKeySize
		}
	}

	// Generate random DEK
	dek := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generating DEK: %w", err)
	}

	// Encrypt value with DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, value, nil)

	// Wrap DEK under each user key
	slots := make([]KeySlot, len(userKeys))
	for i, uk := range userKeys {
		slot, err := wrapDEK(dek, uk)
		if err != nil {
			return nil, fmt.Errorf("wrapping DEK for key %d: %w", i, err)
		}
		slots[i] = slot
	}

	env := &Envelope{
		FormatVersion: FormatV1,
		CreatedAt:     createdAt,
		ValueVersion:  valueVersion,
		KeySlots:      slots,
		Ciphertext:    ciphertext,
	}
	copy(env.Nonce[:], nonce)

	return env.Marshal()
}

// openV1 decrypts a v1 envelope using the provided user key.
func openV1(data []byte, userKey []byte) ([]byte, *Envelope, error) {
	if len(userKey) != KeySize {
		return nil, nil, ErrInvalidKeySize
	}

	env, err := Unmarshal(data)
	if err != nil {
		return nil, nil, err
	}

	dek, err := unwrapDEK(env, userKey)
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, env.Nonce[:], env.Ciphertext, nil)
	if err != nil {
		return nil, nil, ErrDecryptionFailed
	}

	return plaintext, env, nil
}

// AddKeySlot adds a new key slot to an existing v1 envelope without re-encrypting the value.
func AddKeySlot(data []byte, existingKey, newKey []byte) ([]byte, error) {
	if len(data) > 0 && data[0] == FormatV0 {
		return nil, ErrV0NoKeySlots
	}
	if len(existingKey) != KeySize || len(newKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	env, err := Unmarshal(data)
	if err != nil {
		return nil, err
	}

	// Check for duplicate
	newKeyID := KeyID(newKey)
	for _, slot := range env.KeySlots {
		if slot.KeyID == newKeyID {
			return nil, ErrDuplicateKey
		}
	}

	dek, err := unwrapDEK(env, existingKey)
	if err != nil {
		return nil, err
	}

	slot, err := wrapDEK(dek, newKey)
	if err != nil {
		return nil, fmt.Errorf("wrapping DEK for new key: %w", err)
	}

	env.KeySlots = append(env.KeySlots, slot)
	return env.Marshal()
}

// RemoveKeySlot removes a key slot from an existing v1 envelope.
func RemoveKeySlot(data []byte, existingKey, removeKey []byte) ([]byte, error) {
	if len(data) > 0 && data[0] == FormatV0 {
		return nil, ErrV0NoKeySlots
	}
	if len(existingKey) != KeySize || len(removeKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	env, err := Unmarshal(data)
	if err != nil {
		return nil, err
	}

	if len(env.KeySlots) <= 1 {
		return nil, ErrLastKey
	}

	// Verify the caller has access
	if _, err := unwrapDEK(env, existingKey); err != nil {
		return nil, err
	}

	removeKeyID := KeyID(removeKey)
	found := false
	filtered := make([]KeySlot, 0, len(env.KeySlots)-1)
	for _, slot := range env.KeySlots {
		if slot.KeyID == removeKeyID {
			found = true
			continue
		}
		filtered = append(filtered, slot)
	}

	if !found {
		return nil, ErrKeyNotFound
	}

	env.KeySlots = filtered
	return env.Marshal()
}

// Metadata returns envelope metadata without decrypting the value.
// For v0, returns a minimal Envelope with only FormatVersion set.
func Metadata(data []byte) (*Envelope, error) {
	if len(data) == 0 {
		return nil, ErrInvalidEnvelope
	}
	if data[0] == FormatV0 {
		return &Envelope{FormatVersion: FormatV0}, nil
	}
	return Unmarshal(data)
}

// Marshal serializes a v1 Envelope to binary.
func (e *Envelope) Marshal() ([]byte, error) {
	size := V1HeaderSize + len(e.KeySlots)*KeySlotSize + NonceSize + len(e.Ciphertext)
	buf := make([]byte, size)
	offset := 0

	buf[offset] = e.FormatVersion
	offset++

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(e.KeySlots)))
	offset += 2

	binary.BigEndian.PutUint64(buf[offset:], uint64(e.CreatedAt.UnixMilli()))
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], e.ValueVersion)
	offset += 8

	for _, slot := range e.KeySlots {
		copy(buf[offset:], slot.KeyID[:])
		offset += KeyIDSize
		copy(buf[offset:], slot.EncryptedDEK[:])
		offset += EncryptedDEKLen
	}

	copy(buf[offset:], e.Nonce[:])
	offset += NonceSize

	copy(buf[offset:], e.Ciphertext)

	return buf, nil
}

// Unmarshal deserializes binary data into a v1 Envelope.
func Unmarshal(data []byte) (*Envelope, error) {
	if len(data) < V1HeaderSize {
		return nil, ErrInvalidEnvelope
	}

	offset := 0
	formatVersion := data[offset]
	offset++

	if formatVersion != FormatV1 {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrUnsupportedFormat, formatVersion, FormatV1)
	}

	numSlots := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	createdAtMs := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	valueVersion := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	expectedMinSize := V1HeaderSize + int(numSlots)*KeySlotSize + NonceSize + TagSize
	if len(data) < expectedMinSize {
		return nil, ErrInvalidEnvelope
	}

	slots := make([]KeySlot, numSlots)
	for i := range slots {
		copy(slots[i].KeyID[:], data[offset:offset+KeyIDSize])
		offset += KeyIDSize
		copy(slots[i].EncryptedDEK[:], data[offset:offset+EncryptedDEKLen])
		offset += EncryptedDEKLen
	}

	var nonce [NonceSize]byte
	copy(nonce[:], data[offset:offset+NonceSize])
	offset += NonceSize

	ciphertext := make([]byte, len(data)-offset)
	copy(ciphertext, data[offset:])

	return &Envelope{
		FormatVersion: formatVersion,
		CreatedAt:     time.UnixMilli(int64(createdAtMs)),
		ValueVersion:  valueVersion,
		KeySlots:      slots,
		Nonce:         nonce,
		Ciphertext:    ciphertext,
	}, nil
}

func wrapDEK(dek, userKey []byte) (KeySlot, error) {
	block, err := aes.NewCipher(userKey)
	if err != nil {
		return KeySlot{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return KeySlot{}, err
	}

	iv := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return KeySlot{}, err
	}

	encrypted := gcm.Seal(nil, iv, dek, nil)

	var slot KeySlot
	slot.KeyID = KeyID(userKey)
	copy(slot.EncryptedDEK[:NonceSize], iv)
	copy(slot.EncryptedDEK[NonceSize:], encrypted)

	return slot, nil
}

func unwrapDEK(env *Envelope, userKey []byte) ([]byte, error) {
	keyID := KeyID(userKey)

	for _, slot := range env.KeySlots {
		if slot.KeyID != keyID {
			continue
		}

		block, err := aes.NewCipher(userKey)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		iv := slot.EncryptedDEK[:NonceSize]
		encrypted := slot.EncryptedDEK[NonceSize:]

		dek, err := gcm.Open(nil, iv, encrypted, nil)
		if err != nil {
			return nil, ErrDecryptionFailed
		}

		return dek, nil
	}

	return nil, ErrKeyNotFound
}
