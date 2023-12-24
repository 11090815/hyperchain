package util

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestPerm(t *testing.T) {
	var r = rand.New(rand.NewSource(time.Now().Unix()))

	perm := r.Perm(10)

	fmt.Println(perm)
}
