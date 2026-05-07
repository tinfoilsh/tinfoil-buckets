package main

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSealAndOpen(t *testing.T) {
	key := randomKey(t)
	value := []byte("hello world")
	now := time.Now()

	envelope, err := Seal(value, [][]byte{key}, now, 1)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	plaintext, meta, err := Open(envelope, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if !bytes.Equal(plaintext, value) {
		t.Fatalf("got %q, want %q", plaintext, value)
	}
	if meta.ValueVersion != 1 {
		t.Fatalf("version: got %d, want 1", meta.ValueVersion)
	}
	if meta.CreatedAt.UnixMilli() != now.UnixMilli() {
		t.Fatalf("createdAt mismatch")
	}
}

func TestMultipleKeys(t *testing.T) {
	key1 := randomKey(t)
	key2 := randomKey(t)
	key3 := randomKey(t)
	value := []byte("secret data")

	envelope, err := Seal(value, [][]byte{key1, key2, key3}, time.Now(), 1)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for i, k := range [][]byte{key1, key2, key3} {
		plaintext, _, err := Open(envelope, k)
		if err != nil {
			t.Fatalf("Open with key %d: %v", i, err)
		}
		if !bytes.Equal(plaintext, value) {
			t.Fatalf("key %d: got %q, want %q", i, plaintext, value)
		}
	}
}

func TestWrongKey(t *testing.T) {
	key := randomKey(t)
	wrongKey := randomKey(t)
	value := []byte("secret")

	envelope, err := Seal(value, [][]byte{key}, time.Now(), 1)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, _, err = Open(envelope, wrongKey)
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestInvalidKeySize(t *testing.T) {
	_, err := Seal([]byte("data"), [][]byte{[]byte("short")}, time.Now(), 1)
	if err != ErrInvalidKeySize {
		t.Fatalf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestNoKeys(t *testing.T) {
	_, err := Seal([]byte("data"), nil, time.Now(), 1)
	if err != ErrNoKeySlots {
		t.Fatalf("expected ErrNoKeySlots, got %v", err)
	}
}

func TestAddKeySlot(t *testing.T) {
	key1 := randomKey(t)
	key2 := randomKey(t)
	value := []byte("test value")

	envelope, err := Seal(value, [][]byte{key1}, time.Now(), 1)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// key2 should not work yet
	_, _, err = Open(envelope, key2)
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}

	envelope, err = AddKeySlot(envelope, key1, key2)
	if err != nil {
		t.Fatalf("AddKeySlot: %v", err)
	}

	// Both keys should work now
	for i, k := range [][]byte{key1, key2} {
		plaintext, _, err := Open(envelope, k)
		if err != nil {
			t.Fatalf("Open with key %d after add: %v", i, err)
		}
		if !bytes.Equal(plaintext, value) {
			t.Fatalf("key %d: got %q, want %q", i, plaintext, value)
		}
	}
}

func TestAddDuplicateKey(t *testing.T) {
	key := randomKey(t)
	envelope, err := Seal([]byte("data"), [][]byte{key}, time.Now(), 1)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = AddKeySlot(envelope, key, key)
	if err != ErrDuplicateKey {
		t.Fatalf("expected ErrDuplicateKey, got %v", err)
	}
}

func TestRemoveKeySlot(t *testing.T) {
	key1 := randomKey(t)
	key2 := randomKey(t)
	value := []byte("test value")

	envelope, err := Seal(value, [][]byte{key1, key2}, time.Now(), 1)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	envelope, err = RemoveKeySlot(envelope, key1, key2)
	if err != nil {
		t.Fatalf("RemoveKeySlot: %v", err)
	}

	// key1 should still work
	plaintext, _, err := Open(envelope, key1)
	if err != nil {
		t.Fatalf("Open with key1 after remove: %v", err)
	}
	if !bytes.Equal(plaintext, value) {
		t.Fatalf("got %q, want %q", plaintext, value)
	}

	// key2 should no longer work
	_, _, err = Open(envelope, key2)
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestRemoveLastKey(t *testing.T) {
	key := randomKey(t)
	envelope, err := Seal([]byte("data"), [][]byte{key}, time.Now(), 1)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = RemoveKeySlot(envelope, key, key)
	if err != ErrLastKey {
		t.Fatalf("expected ErrLastKey, got %v", err)
	}
}

func TestCorruptEnvelope(t *testing.T) {
	_, err := Unmarshal([]byte("too short"))
	if err != ErrInvalidEnvelope {
		t.Fatalf("expected ErrInvalidEnvelope, got %v", err)
	}
}

func TestEmptyValue(t *testing.T) {
	key := randomKey(t)

	envelope, err := Seal([]byte{}, [][]byte{key}, time.Now(), 1)
	if err != nil {
		t.Fatalf("Seal empty: %v", err)
	}

	plaintext, _, err := Open(envelope, key)
	if err != nil {
		t.Fatalf("Open empty: %v", err)
	}
	if len(plaintext) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(plaintext))
	}
}

func TestLargeValue(t *testing.T) {
	key := randomKey(t)
	value := make([]byte, 10*1024*1024) // 10 MB
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}

	envelope, err := Seal(value, [][]byte{key}, time.Now(), 1)
	if err != nil {
		t.Fatalf("Seal large: %v", err)
	}

	plaintext, _, err := Open(envelope, key)
	if err != nil {
		t.Fatalf("Open large: %v", err)
	}
	if !bytes.Equal(plaintext, value) {
		t.Fatal("large value mismatch")
	}
}

func TestMetadata(t *testing.T) {
	key := randomKey(t)
	now := time.Now()

	envelope, err := Seal([]byte("data"), [][]byte{key}, now, 42)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	meta, err := Metadata(envelope)
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}

	if meta.FormatVersion != FormatV1 {
		t.Fatalf("format: got %d, want %d", meta.FormatVersion, FormatV1)
	}
	if meta.ValueVersion != 42 {
		t.Fatalf("version: got %d, want 42", meta.ValueVersion)
	}
	if meta.CreatedAt.UnixMilli() != now.UnixMilli() {
		t.Fatal("createdAt mismatch")
	}
	if len(meta.KeySlots) != 1 {
		t.Fatalf("slots: got %d, want 1", len(meta.KeySlots))
	}
}

func TestMarshalUnmarshalRoundtrip(t *testing.T) {
	key := randomKey(t)

	original, err := Seal([]byte("roundtrip"), [][]byte{key}, time.Now(), 7)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	env, err := Unmarshal(original)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	remarshaled, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if !bytes.Equal(original, remarshaled) {
		t.Fatal("marshal roundtrip mismatch")
	}
}

// --- v0 tests ---

func TestV0SealAndOpen(t *testing.T) {
	key := randomKey(t)
	value := []byte("hello v0")

	blob, err := SealV0(value, key)
	if err != nil {
		t.Fatalf("SealV0: %v", err)
	}

	if blob[0] != FormatV0 {
		t.Fatalf("first byte: got %d, want %d", blob[0], FormatV0)
	}

	plaintext, err := OpenV0(blob, key)
	if err != nil {
		t.Fatalf("OpenV0: %v", err)
	}

	if !bytes.Equal(plaintext, value) {
		t.Fatalf("got %q, want %q", plaintext, value)
	}
}

func TestV0WrongKey(t *testing.T) {
	key := randomKey(t)
	wrongKey := randomKey(t)

	blob, err := SealV0([]byte("secret"), key)
	if err != nil {
		t.Fatalf("SealV0: %v", err)
	}

	_, err = OpenV0(blob, wrongKey)
	if err != ErrDecryptionFailed {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestV0InvalidKeySize(t *testing.T) {
	_, err := SealV0([]byte("data"), []byte("short"))
	if err != ErrInvalidKeySize {
		t.Fatalf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestV0EmptyValue(t *testing.T) {
	key := randomKey(t)

	blob, err := SealV0([]byte{}, key)
	if err != nil {
		t.Fatalf("SealV0 empty: %v", err)
	}

	plaintext, err := OpenV0(blob, key)
	if err != nil {
		t.Fatalf("OpenV0 empty: %v", err)
	}
	if len(plaintext) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(plaintext))
	}
}

func TestV0OpenViaGenericOpen(t *testing.T) {
	key := randomKey(t)
	value := []byte("dispatched via Open()")

	blob, err := SealV0(value, key)
	if err != nil {
		t.Fatalf("SealV0: %v", err)
	}

	plaintext, meta, err := Open(blob, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if !bytes.Equal(plaintext, value) {
		t.Fatalf("got %q, want %q", plaintext, value)
	}
	if meta.FormatVersion != FormatV0 {
		t.Fatalf("format: got %d, want %d", meta.FormatVersion, FormatV0)
	}
}

func TestV1OpenViaGenericOpen(t *testing.T) {
	key := randomKey(t)
	value := []byte("dispatched via Open() v1")

	blob, err := Seal(value, [][]byte{key}, time.Now(), 1)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	plaintext, meta, err := Open(blob, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if !bytes.Equal(plaintext, value) {
		t.Fatalf("got %q, want %q", plaintext, value)
	}
	if meta.FormatVersion != FormatV1 {
		t.Fatalf("format: got %d, want %d", meta.FormatVersion, FormatV1)
	}
}

func TestV0AddKeySlotRejected(t *testing.T) {
	key := randomKey(t)
	newKey := randomKey(t)

	blob, err := SealV0([]byte("data"), key)
	if err != nil {
		t.Fatalf("SealV0: %v", err)
	}

	_, err = AddKeySlot(blob, key, newKey)
	if err != ErrV0NoKeySlots {
		t.Fatalf("expected ErrV0NoKeySlots, got %v", err)
	}
}

func TestV0RemoveKeySlotRejected(t *testing.T) {
	key := randomKey(t)

	blob, err := SealV0([]byte("data"), key)
	if err != nil {
		t.Fatalf("SealV0: %v", err)
	}

	_, err = RemoveKeySlot(blob, key, key)
	if err != ErrV0NoKeySlots {
		t.Fatalf("expected ErrV0NoKeySlots, got %v", err)
	}
}

func TestV0Metadata(t *testing.T) {
	key := randomKey(t)

	blob, err := SealV0([]byte("data"), key)
	if err != nil {
		t.Fatalf("SealV0: %v", err)
	}

	meta, err := Metadata(blob)
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if meta.FormatVersion != FormatV0 {
		t.Fatalf("format: got %d, want %d", meta.FormatVersion, FormatV0)
	}
}

func TestDetectFormat(t *testing.T) {
	key := randomKey(t)

	v0, _ := SealV0([]byte("v0"), key)
	v1, _ := Seal([]byte("v1"), [][]byte{key}, time.Now(), 1)

	f0, err := DetectFormat(v0)
	if err != nil || f0 != FormatV0 {
		t.Fatalf("v0: got %d, err %v", f0, err)
	}

	f1, err := DetectFormat(v1)
	if err != nil || f1 != FormatV1 {
		t.Fatalf("v1: got %d, err %v", f1, err)
	}

	_, err = DetectFormat([]byte{})
	if err != ErrInvalidEnvelope {
		t.Fatalf("empty: expected ErrInvalidEnvelope, got %v", err)
	}
}
