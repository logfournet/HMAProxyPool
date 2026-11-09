package main

import (
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
)

// countingBind wraps a conn.Bind and counts raw UDP packets in each direction.
// rx_raw > 0 with rx_bytes == 0 means packets arrive but do not decrypt.
type countingBind struct {
	conn.Bind
	tx atomic.Int64
	rx atomic.Int64
}

func (b *countingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	n := len(bufs)
	err := b.Bind.Send(bufs, ep)
	if err == nil {
		b.tx.Add(int64(n))
	}
	return err
}

func (b *countingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, actual, err
	}
	out := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		f := fn
		out[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := f(packets, sizes, eps)
			if n > 0 {
				b.rx.Add(int64(n))
			}
			return n, err
		}
	}
	return out, actual, nil
}

func (b *countingBind) RawTX() int64 { return b.tx.Load() }
func (b *countingBind) RawRX() int64 { return b.rx.Load() }