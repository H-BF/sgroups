package main

import (
	"fmt"
	nft "github.com/google/nftables"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSetElems2Nets(t *testing.T) {
	cases := []struct {
		setElems []nft.SetElement
		err      bool
		expected []string
	}{
		{
			setElems: []nft.SetElement{
				{Key: []byte{10, 10, 2, 0}, IntervalEnd: true},
				{Key: []byte{10, 10, 1, 0}, IntervalEnd: false},
				{Key: []byte{0, 0, 0, 0}, IntervalEnd: true},
			},
			err:      false,
			expected: []string{"10.10.1.0/24"},
		},
		{
			setElems: []nft.SetElement{
				{Key: []byte{192, 168, 65, 255}, IntervalEnd: true},
				{Key: []byte{192, 168, 65, 254}, IntervalEnd: false},
				{Key: []byte{0, 0, 0, 0}, IntervalEnd: true},
			},
			err:      false,
			expected: []string{"192.168.65.254"},
		},

		{
			setElems: []nft.SetElement{
				{Key: []byte{253, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, IntervalEnd: true},
				{Key: []byte{253, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, IntervalEnd: false},
				{Key: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, IntervalEnd: true},
			},
			err:      false,
			expected: []string{"fdc0::/13"},
		},
	}

	for i, c := range cases {
		nets, err := setElems2Nets(c.setElems)
		if err != nil && !c.err {
			t.Fatalf("TestSetElems2Nets[case %d] not expected err: %v", i, err)
		}
		if c.err && err == nil {
			t.Fatalf("Tododo")
		}
		require.ElementsMatch(t, nets, c.expected)
	}
}

func TestFindCommonLongestMask(t *testing.T) {
	cases := []struct {
		a        []byte
		b        []byte
		err      bool
		expected int
	}{
		{
			a:        []byte{192, 0, 20, 0},
			b:        []byte{192, 0, 21, 0},
			err:      false,
			expected: 24,
		},
		{
			a:        []byte{192, 32, 0, 0},
			b:        []byte{192, 64, 0, 0},
			err:      false,
			expected: 11,
		},
		{
			a:        []byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			b:        []byte{32, 1, 13, 185, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			err:      false,
			expected: 32,
		},
		{
			a:        []byte{253, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			b:        []byte{253, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			err:      false,
			expected: 13,
		},
	}
	for _, c := range cases {
		mask, err := findCommonLongestMask(c.a, c.b)
		if !c.err {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
		fmt.Println("************")
		require.Equal(t, c.expected, mask)
	}
}
