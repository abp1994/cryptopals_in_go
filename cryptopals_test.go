package main

import (
	"os"
	"testing"

	"github.com/abp1994/cryptopals_in_go/pkg/utils"
)

var iceIceBabyLyrics []byte

func init() {
	var err error
	iceIceBabyLyrics, err = os.ReadFile("res/ice_ice_baby_lyrics.txt")
	if err != nil {
		panic(err)
	}
}

func TestChallenge1(t *testing.T) {
	t.Log("Convert hex to base64")

	got := c1()

	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestChallenge2(t *testing.T) {
	t.Log("Fixed XOR")

	got := c2()

	want := "746865206b696420646f6e277420706c6179"

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestChallenge3(t *testing.T) {
	t.Log("Single-byte XOR cipher")

	got := c3()

	want := "Cooking MC's like a pound of bacon"

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestChallenge4(t *testing.T) {
	t.Log("Detect single-character XOR")

	got := c4()

	want := "Now that the party is jumping\n"

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestChallenge5(t *testing.T) {
	t.Log("Implement repeating-key XOR")

	got := c5()

	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestChallenge6(t *testing.T) {
	t.Log("Break repeating-key XOR")

	text1 := []byte("this is a test")
	text2 := []byte("wokka wokka!!!")

	distance, err := utils.FindHammingDistance(text1, text2)
	if err != nil {
		t.Fatal(err)
	}

	if distance != 37 {
		t.Errorf("Hamming distance: got %d, want 37", distance)
	}

	got := c6()

	if got != string(iceIceBabyLyrics) {
		t.Errorf("recovered plaintext does not match expected plaintext")
	}
}

func TestChallenge7(t *testing.T) {
	t.Log("AES in ECB mode")

	got := c7()

	expected := append([]byte{}, iceIceBabyLyrics...)
	expected = append(expected, 0x04, 0x04, 0x04, 0x04)

	if got != string(expected) {
		t.Errorf("decrypted plaintext does not match expected plaintext")
	}
}
