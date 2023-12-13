package util


func ConcatenateBytes(data ...[]byte) []byte {
	finalLength := 0
	for _, slice := range data {
		finalLength += len(slice)
	}
	result := make([]byte, finalLength)
	last := 0
	for _, slice := range data {
		for i := range slice {
			result[i+last] = slice[i]
		}
		last += len(slice)
	}
	return result
}

// ConcatenateBytes2
//
// Deprecated: inefficient
func ConcatenateBytes2(data ...[]byte) []byte {
	result := make([]byte, 0)
	for _, slice := range data {
		result = append(result, slice...)
	}
	return result
}
