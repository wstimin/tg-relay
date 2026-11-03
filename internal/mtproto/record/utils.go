// Adapted from 9seconds/mtg (MIT). See THIRD_PARTY_NOTICES.md.
package tls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func ReadRecord(r io.Reader, w io.Writer) (byte, int64, error) {
	buf := [SizeHeader]byte{}

	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, 0, err
	}

	pVer := buf[SizeRecordType:]
	pLen := pVer[SizeVersion:]

	if !bytes.Equal(TLSVersion[:], pVer[:SizeVersion]) {
		return 0, 0, fmt.Errorf("incorrect tls version %v", pVer)
	}

	length := int64(binary.BigEndian.Uint16(pLen[:SizeSize]))
	if length > MaxRecordSize {
		return 0, 0, fmt.Errorf("record too large")
	}
	_, err := io.CopyN(w, r, length)

	return buf[0], length, err
}

func WriteRecord(w io.Writer, payload []byte) error {
	buf := [MaxRecordSize]byte{}
	copy(buf[SizeHeader:], payload)

	return WriteRecordInPlace(w, buf[:], len(payload))
}

func WriteRecordInPlace(w io.Writer, buf []byte, payloadLen int) error {
	if payloadLen > MaxRecordPayloadSize {
		return fmt.Errorf("payload %d exceeds max %d", payloadLen, MaxRecordPayloadSize)
	}

	buf[0] = TypeApplicationData
	copy(buf[SizeRecordType:SizeRecordType+SizeVersion], TLSVersion[:])
	binary.BigEndian.PutUint16(
		buf[SizeRecordType+SizeVersion:SizeRecordType+SizeVersion+SizeSize],
		uint16(payloadLen),
	)

	packet := buf[:SizeHeader+payloadLen]
	for len(packet) > 0 {
		n, err := w.Write(packet)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		packet = packet[n:]
	}
	return nil
}
