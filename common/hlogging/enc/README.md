# 正则表达式

## 1. 捕获与非捕获

在一些正则表达式里能见到 `?:` 符号，这个符号表示的含义就是**非捕获**匹配，什么是**捕获**匹配和什么是**非捕获匹配**，可通过以下例子进行说明：

我们先给出一个捕获匹配表达式：`Windows(XP|7|10)`，这个表达式可匹配字符串 `"Windows98 WindowsXP Windows7 Windows11"` 中的 `"WindowsXP"` 和 `Windows7`，同时，他也会将 `XP` 和 `7` 也单独匹配出来。非捕获匹配表达式的写法为 `Windows(?:XP|7|10)`，这个表达式仅能匹配字符串 `"Windows98 WindowsXP Windows7 Windows11"` 中的 `"WindowsXP"` 和 `Windows7`，`XP` 和 `7` 不会再单独匹配出来。

利用 `Go` 语言实现了一个例子，如下：

```go
func TestRegexp(t *testing.T) {
	str := "Windows98 WindowsXP Windows7 Windows11"

	capture := regexp.MustCompile("Windows(XP|7|10)")
	captureRes := capture.FindAllStringSubmatchIndex(str, -1)
	require.Equal(t, 2, len(captureRes))
	require.Equal(t, 4, len(captureRes[0]))
	require.Equal(t, "WindowsXP", str[captureRes[0][0]:captureRes[0][1]])
	require.Equal(t, "XP", str[captureRes[0][2]:captureRes[0][3]])
	require.Equal(t, 4, len(captureRes[1]))
	require.Equal(t, "Windows7", str[captureRes[1][0]:captureRes[1][1]])
	require.Equal(t, "7", str[captureRes[1][2]:captureRes[1][3]])

	nonCapture := regexp.MustCompile("Windows(?:XP|7|10)")
	nonCaptureRes := nonCapture.FindAllStringSubmatchIndex(str, -1)
	require.Equal(t, 2, len(nonCaptureRes))
	require.Equal(t, 2, len(nonCaptureRes[0]))
	require.Equal(t, "WindowsXP", str[nonCaptureRes[0][0]:nonCaptureRes[0][1]])
	require.Equal(t, 2, len(nonCaptureRes[1]))
	require.Equal(t, "Windows7", str[nonCaptureRes[1][0]:nonCaptureRes[1][1]])
}
```

上面代码的执行过程是可以通过验证的。`captureRes` 的结果是 `[[10 19 17 19] [20 28 27 28]]`，`nonCaptureRes` 的结果是 `[[10 19] [20 28]]`。可以看到，非捕获匹配得到的结果是比较精简的。在一些场合下，非捕获匹配可以提高正则匹配的效率，因为可能我们只想匹配到 `WindowsXP`，而不想匹配到 `XP`。


## 2. 中括号的妙用

中括号 `[]` 用于匹配单个字符是否属于中括号中所列出的字符。与中括号搭配使用的两个特殊字符有连接符 `-` 和取反符 `^`。

- 连接符
	1. `[0-9]` 表示 `0` 到 `9` 之间的数字，包括 `0` 和 `9`
	2. `[0-9a-z]` 表示 `0` 到 `9` 之间的数字 和 `a` 到 `z` 之间的所有字母
	3. `[!-\]` 表示 `ASCII` 码中 `!` 到 `\` 之间的所有字符

- 取反符
	1. `[^a]` 表示不匹配字母 `a`
	2. `[^abc]` 还是表示不匹配字母 `abc`
	3. `[^b-d^1-3^5]` 表示不匹配 `b c d 1 2 3 5` 这几个字符

**除了 `^` `-` `\` 这三个特殊字符在中括号中不会被当成普通字符，其他所有特殊字符在中括号里都会被当成普通字符看待，例如 `.` 只会被当成一个点看待，不会当成通配符。**