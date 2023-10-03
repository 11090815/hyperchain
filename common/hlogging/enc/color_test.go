package enc_test

import (
	"fmt"
	"testing"

	"github.com/11090815/hyperchain/common/hlogging/enc"
)

func TestNormalColor(t *testing.T) {
	fmt.Println(enc.ColorBlue.Normal(), "蓝色的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorCyan.Normal(), "青色的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorRed.Normal(), "红色的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorYellow.Normal(), "黄色的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorBlack.Normal(), "黑色的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorMagenta.Normal(), "品红色的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorWhite.Normal(), "白色的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorGreen.Normal(), "绿色的字体", enc.ResetColor(), "无特殊颜色的字体")
}

func TestBoldColor(t *testing.T) {
	fmt.Println(enc.ColorBlue.Bold(), "蓝色加粗的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorCyan.Bold(), "青色加粗的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorRed.Bold(), "红色加粗的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorYellow.Bold(), "黄色加粗的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorBlack.Bold(), "黑色加粗的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorMagenta.Bold(), "品红色加粗的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorWhite.Bold(), "白色加粗的字体", enc.ResetColor(), "无特殊颜色的字体")
	fmt.Println(enc.ColorGreen.Bold(), "绿色加粗的字体", enc.ResetColor(), "无特殊颜色的字体")
}
