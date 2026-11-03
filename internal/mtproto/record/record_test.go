package tls

import (
	"bytes"
	"testing"
)

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) { return w.Buffer.Write(p[:min(3, len(p))]) }
func TestRecordHandlesShortWritesAndRejectsOversize(t *testing.T) {
	w := &shortWriter{}
	payload := []byte("hello-record")
	if err := WriteRecord(w, payload); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if _, _, err := ReadRecord(bytes.NewReader(w.Bytes()), &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("record mismatch: %v", err)
	}
	if _, _, err := ReadRecord(bytes.NewReader([]byte{23, 3, 3, 255, 255}), &got); err == nil {
		t.Fatal("oversize record accepted")
	}
}
