package keras_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/defilantech/socair/internal/keras"
	"github.com/defilantech/socair/internal/keras/kerastest"
)

// FuzzRead feeds arbitrary bytes to the Keras reader, as an HDF5 file or a
// .keras archive, and every config it decodes to Analyze. They read
// untrusted artifacts, so neither may panic, and a read must be
// deterministic and keep its text within its caps.
func FuzzRead(f *testing.F) {
	config := kerastest.Functional3(kerastest.Dense3("dense"), kerastest.Lambda3("lam", kerastest.Bytecode),
		kerastest.Layer3("subprocess", "run", "x"))
	f.Add(kerastest.Archive(config, kerastest.Keras3Weights().Bytes(), kerastest.Member{Name: "assets/v.txt", Data: []byte("a")}))
	f.Add(kerastest.FullModel(kerastest.Functional2(kerastest.Lambda2("lam", kerastest.Bytecode))).Bytes())
	f.Add(kerastest.WeightsOnly().Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		a, errA := keras.ReadFrom(bytes.NewReader(data), int64(len(data)))
		b, errB := keras.ReadFrom(bytes.NewReader(data), int64(len(data)))
		if (errA == nil) != (errB == nil) {
			t.Fatal("read is not deterministic")
		}
		if errA != nil {
			return
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatal("two reads of the same bytes differ")
		}
		var total int64
		for _, v := range a.Text {
			total += int64(len(v))
		}
		if total != a.TextBytes {
			t.Fatalf("text holds %d bytes, TextBytes says %d", total, a.TextBytes)
		}
		for _, c := range a.Configs {
			if c.Err == "" {
				_ = keras.Analyze(c.Value, c.Source)
			}
		}
	})
}
