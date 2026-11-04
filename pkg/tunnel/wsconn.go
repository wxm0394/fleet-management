package tunnel

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSConn 将 gorilla/websocket.Conn 包装为标准 net.Conn，供 yamux 多路复用使用
type WSConn struct {
	*websocket.Conn
	reader io.Reader
	writeM sync.Mutex
}

func NewWSConn(ws *websocket.Conn) net.Conn {
	return &WSConn{Conn: ws}
}

func (c *WSConn) Read(b []byte) (int, error) {
	for {
		if c.reader == nil {
			_, r, err := c.Conn.NextReader()
			if err != nil {
				return 0, err
			}
			c.reader = r
		}
		n, err := c.reader.Read(b)
		if err == io.EOF {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *WSConn) Write(b []byte) (int, error) {
	c.writeM.Lock()
	defer c.writeM.Unlock()
	err := c.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *WSConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}
