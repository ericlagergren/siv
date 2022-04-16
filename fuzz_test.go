package siv

import (
	"bytes"
	"os"
	"testing"
	"time"

	rand "github.com/ericlagergren/saferand"
	tink "github.com/google/tink/go/aead/subtle"
)

// TestTink tests against Google Tink.
func TestTink(t *testing.T) {
	runTests(t, func(t *testing.T) {
		t.Run("128", func(t *testing.T) {
			testTink(t, 16)
		})
		t.Run("256", func(t *testing.T) {
			testTink(t, 32)
		})
	})
}

func testTink(t *testing.T, keySize int) {
	d := 2 * time.Second
	if testing.Short() {
		d = 10 * time.Millisecond
	}
	if s := os.Getenv("SIV_FUZZ_TIMEOUT"); s != "" {
		var err error
		d, err = time.ParseDuration(s)
		if err != nil {
			t.Fatal(err)
		}
	}
	tm := time.NewTimer(d)
	t.Cleanup(func() {
		tm.Stop()
	})

	key := make([]byte, keySize)
	plaintext := make([]byte, 1*1024*1024) // 1 MB
	aad := make([]byte, 1*1024)            // 1 KiB
	for i := 0; ; i++ {
		select {
		case <-tm.C:
			t.Logf("iters: %d", i)
			return
		default:
		}

		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		n := rand.Intn(len(plaintext))
		if _, err := rand.Read(plaintext[:n]); err != nil {
			t.Fatal(err)
		}
		plaintext := plaintext[:n]

		n = rand.Intn(len(aad))
		if _, err := rand.Read(aad[:n]); err != nil {
			t.Fatal(err)
		}
		aad := aad[:n]

		refAead, err := tink.NewAESGCMSIV(key)
		if err != nil {
			t.Fatal(err)
		}
		nonceAndCt, err := refAead.Encrypt(plaintext, aad)
		if err != nil {
			t.Fatal(err)
		}
		nonce := nonceAndCt[:NonceSize]
		wantCt := nonceAndCt[NonceSize:]

		gotAead, err := NewGCM(key)
		if err != nil {
			t.Fatal(err)
		}

		gotCt := gotAead.Seal(nil, nonce, plaintext, aad)
		if !bytes.Equal(wantCt, gotCt) {
			wantTag := wantCt[len(wantCt)-TagSize:]
			gotTag := gotCt[len(gotCt)-TagSize:]
			if !bytes.Equal(wantTag, gotTag) {
				t.Fatalf("expected tag %x, got %x", wantTag, gotTag)
			}
			wantCt = wantCt[:len(wantCt)-TagSize]
			gotCt = gotCt[:len(gotCt)-TagSize]
			for i, c := range gotCt {
				if c != wantCt[i] {
					t.Fatalf("bad value at index %d (block %d of %d): %#x",
						i, i/blockSize, len(wantCt)/blockSize, c)
				}
			}
			t.Fatalf("expected %#x, got %#x", wantCt, gotCt)
		}

		wantPt, err := refAead.Decrypt(nonceAndCt, aad)
		if err != nil {
			t.Fatal(err)
		}
		gotPt, err := gotAead.Open(nil, nonce, wantCt, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(wantPt, gotPt) {
			t.Fatalf("expected %#x, got %#x", wantPt, gotPt)
		}
	}
}
