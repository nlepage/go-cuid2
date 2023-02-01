package cuid2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateId(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	id, err := CreateId()
	require.NoError(err)

	assert.Len(id, DefaultLength)

	t.Logf("generated id %s", id)
}
