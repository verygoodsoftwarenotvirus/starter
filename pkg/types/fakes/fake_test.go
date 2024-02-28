package fakes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_buildFakeNumber(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		assert.NotZero(t, buildFakeNumber())
	})
}
