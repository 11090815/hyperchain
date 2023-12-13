package util_test

import (
	"testing"
	"time"

	"github.com/11090815/hyperchain/common/util"
	"github.com/stretchr/testify/require"
)

func TestConcatenateBytes(t *testing.T) {
	data := [][]byte{
		[]byte("y78asyuiy7823r"),
		[]byte("t127usbduiy387r"),
		[]byte("ask就会反对和户外iu和uish变速俄方哈布斯堡"),
		[]byte("剧i前往桃园翔安隧道和iush8别撒uidf和我额有入水淀粉就开始uosyuab飞机老师的8给"),
	}

	res1 := util.ConcatenateBytes(data...)
	res2 := util.ConcatenateBytes2(data...)
	require.Equal(t, res1, res2)

	start1 := time.Now()
	for i := 0; i < 10000; i++ {
		util.ConcatenateBytes2(data...)
	}
	end1 := time.Now()
	t.Log(end1.Sub(start1).Seconds())

	start2 := time.Now()
	for i := 0; i < 10000; i++ {
		util.ConcatenateBytes(data...)
	}
	end2 := time.Now()
	t.Log(end2.Sub(start2).Seconds())
}
