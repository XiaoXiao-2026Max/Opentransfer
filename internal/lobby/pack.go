package lobby

import (
	"encoding/binary"
	"errors"
)

type writer struct{ buf []byte }

func newWriter(protoID uint16) *writer {
	w := &writer{buf: make([]byte, 0, 64)}
	w.U16(protoID)
	return w
}

func (w *writer) U8(v byte) { w.buf = append(w.buf, v) }
func (w *writer) Bool(v bool) {
	if v {
		w.buf = append(w.buf, 1)
	} else {
		w.buf = append(w.buf, 0)
	}
}
func (w *writer) U16(v uint16) { w.buf = binary.BigEndian.AppendUint16(w.buf, v) }
func (w *writer) U32(v uint32) { w.buf = binary.BigEndian.AppendUint32(w.buf, v) }
func (w *writer) U64(v uint64) { w.buf = binary.BigEndian.AppendUint64(w.buf, v) }
func (w *writer) Raw(b []byte) { w.buf = append(w.buf, b...) }

func (w *writer) Str(s string) {
	b := []byte(s)
	if len(b) > 0xFFFF {
		b = b[:0xFFFF]
	}
	w.U16(uint16(len(b)))
	w.Raw(b)
}

func (w *writer) Bytes(b []byte) {
	if len(b) > 0xFFFF {
		b = b[:0xFFFF]
	}
	w.U16(uint16(len(b)))
	w.Raw(b)
}

func (w *writer) Done() []byte { return w.buf }

type reader struct {
	buf []byte
	off int
}

var errTruncated = errors.New("lobby: 数据包被截断")

func newReader(b []byte) *reader { return &reader{buf: b} }

func (r *reader) Remaining() int { return len(r.buf) - r.off }

func (r *reader) U8() (byte, error) {
	if r.Remaining() < 1 {
		return 0, errTruncated
	}
	v := r.buf[r.off]
	r.off++
	return v, nil
}

func (r *reader) U16() (uint16, error) {
	if r.Remaining() < 2 {
		return 0, errTruncated
	}
	v := binary.BigEndian.Uint16(r.buf[r.off:])
	r.off += 2
	return v, nil
}

func (r *reader) U32() (uint32, error) {
	if r.Remaining() < 4 {
		return 0, errTruncated
	}
	v := binary.BigEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v, nil
}

func (r *reader) U64() (uint64, error) {
	if r.Remaining() < 8 {
		return 0, errTruncated
	}
	v := binary.BigEndian.Uint64(r.buf[r.off:])
	r.off += 8
	return v, nil
}

func (r *reader) Str() (string, error) {
	n, err := r.U16()
	if err != nil {
		return "", err
	}
	if r.Remaining() < int(n) {
		return "", errTruncated
	}
	s := string(r.buf[r.off : r.off+int(n)])
	r.off += int(n)
	return s, nil
}
