package enc

import "fmt"

type Color uint8

const ColorNone Color = 0 // 无特殊颜色

const (
	ColorBlack   Color = iota + 30 // 黑色 30
	ColorRed                       // 红色 31
	ColorGreen                     // 绿色 32
	ColorYellow                    // 黄色 33
	ColorBlue                      // 蓝色 34
	ColorMagenta                   // 品红 35
	ColorCyan                      // 青色 36
	ColorWhite                     // 白色
)

func (c Color) Normal() string {
	return fmt.Sprintf("\x1b[%dm", c)
}

func (c Color) Bold() string {
	if c == ColorNone {
		return c.Normal()
	}
	return fmt.Sprintf("\x1b[%d;1m", c)
}

func ResetColor() string {
	return ColorNone.Normal()
}
