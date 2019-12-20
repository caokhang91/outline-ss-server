package shadowsocks

import (
	"crypto/md5"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"testing"
)

func MakeVecs(n int) [][32]byte {
	vecs := make([][32]byte, n)
	for i := 0; i < n; i++ {
		rand.Read(vecs[i][:])
	}
	return vecs
}

func TestByteHash(t *testing.T) {
	hasher := MakeByteHasher()
	vecs := MakeVecs(2)
	if hasher.Hash(vecs[0]) == hasher.Hash(vecs[1]) {
		t.Error("Hash collision.  This is extremely improbable.")
	}
}

func BenchmarkByteHash(b *testing.B) {
	vecs := MakeVecs(b.N)
	hasher := MakeByteHasher()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Hash(vecs[i])
	}
}

// To serve as a reference point for BenchmarkByteHash
func BenchmarkMD5(b *testing.B) {
	vecs := MakeVecs(b.N)
	hasher := md5.New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Sum(vecs[i][:])
	}
}

func TestSet64(t *testing.T) {
	s, err := NewSet64(slice64(make([]uint64, 32)))
	if err != nil {
		t.Fatal(err)
	}
	val := rand.Uint64()

	if s.Count() != 0 {
		t.Error("Empty set should be empty")
	}

	if s.Capacity() != 32 {
		t.Errorf("Capacity is 32, not %d", s.Capacity())
	}

	contains, err := s.Contains(val)
	if err != nil {
		t.Error(err)
	}
	if contains {
		t.Error("Empty set can't contain any value")
	}

	added, err := s.Add(val)
	if err != nil {
		t.Error(err)
	}
	if !added {
		t.Error("Add to an empty set can't fail")
	}

	contains, err = s.Contains(val)
	if err != nil {
		t.Error(err)
	}
	if !contains {
		t.Error("Value was just added")
	}

	if s.Count() != 1 {
		t.Errorf("Added 1 value, not %d", s.Count())
	}
}

func TestSet64_Zero(t *testing.T) {
	s, err := NewSet64(slice64(make([]uint64, 32)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Contains(0)
	if err == nil {
		t.Error("0 is not permissible to check")
	}

	_, err = s.Add(0)
	if err == nil {
		t.Error("0 is not permissible to add")
	}
}

func TestSet64_Full(t *testing.T) {
	s, err := NewSet64(slice64(make([]uint64, 32)))
	if err != nil {
		t.Fatal(err)
	}
	var vals [32]uint64
	for i := range vals {
		vals[i] = rand.Uint64()
		added, err := s.Add(vals[i])
		if err != nil {
			t.Error(err)
		}
		if !added {
			t.Errorf("Failed to add value %d, %d", i, vals[i])
		}
	}

	for i, v := range vals {
		contains, err := s.Contains(v)
		if err != nil {
			t.Error(err)
		}
		if !contains {
			t.Errorf("Failed to find value %d, %d", i, v)
		}
	}

	extra := rand.Uint64()
	_, err = s.Add(extra)
	if err == nil {
		t.Error("Set is full, so Add should have failed")
	}
	contains, err := s.Contains(extra)
	if err != nil {
		t.Error(err)
	}
	if contains {
		t.Error("We never added this value")
	}
}

func TestSet64_CollideLow(t *testing.T) {
	s, err := NewSet64(slice64(make([]uint64, 32)))
	if err != nil {
		t.Error(err)
	}
	var i uint64
	for i = 1; i <= 32; i++ {
		contains, err := s.Contains(i)
		if err != nil {
			t.Error(err)
		}
		if contains {
			t.Errorf("We haven't added %d yet", i)
		}
		added, err := s.Add(i)
		if err != nil {
			t.Error(err)
		}
		if !added {
			t.Errorf("Add(%d) failed", i)
		}
		contains, err = s.Contains(i)
		if err != nil {
			t.Error(err)
		}
		if !contains {
			t.Errorf("Missing value %d", i)
		}
	}
}

func TestSet64_CollideHigh(t *testing.T) {
	s, err := NewSet64(slice64(make([]uint64, 32)))
	if err != nil {
		t.Error(err)
	}
	var i uint64
	for i = 0; i < 32; i++ {
		v := math.MaxUint64 - i
		contains, err := s.Contains(v)
		if err != nil {
			t.Error(err)
		}
		if contains {
			t.Errorf("We haven't added %d yet", v)
		}
		added, err := s.Add(v)
		if err != nil {
			t.Error(err)
		}
		if !added {
			t.Errorf("Add(%d) failed", v)
		}
		contains, err = s.Contains(v)
		if err != nil {
			t.Error(err)
		}
		if !contains {
			t.Errorf("Missing value %v", v)
		}
	}
}

func BenchmarkSet64_Contains_95(b *testing.B) {
	s, err := NewSet64(slice64(make([]uint64, 1e6)))
	if err != nil {
		b.Error(err)
	}
	// Construct a set that is 95% full
	var N int = 0.95e6
	src := make([]uint64, N)
	for i := range src {
		src[i] = rand.Uint64()
	}
	for _, v := range src {
		s.Add(v)
	}
	// The set contains `k` values.

	b.ResetTimer()
	// Check every value in the set until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		s.Contains(src[j])
		j++
		if j == len(src) {
			j = 0
		}
	}
}

type empty struct{}

// Baseline for BenchmarkSet64_Contains_95
func BenchmarkMap_Contains(b *testing.B) {
	m := map[uint64]empty{}
	src := make([]uint64, 1e6)
	for i := range src {
		src[i] = rand.Uint64()
		m[src[i]] = empty{}
	}

	b.ResetTimer()
	// Check every value in the set until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		if _, ok := m[src[j]]; ok {
			j++
			if j == len(src) {
				j = 0
			}
		}
	}
}

func BenchmarkSet64_NotContains_95(b *testing.B) {
	s, _ := NewSet64(slice64(make([]uint64, 1e6)))
	// Construct a set that is 95% full
	var N int = 0.95e6
	for i := 0; i < N; i++ {
		s.Add(rand.Uint64())
	}

	// Create an array with new random values.
	src := make([]uint64, 1e6)
	for i := range src {
		src[i] = rand.Uint64()
	}

	b.ResetTimer()
	// Check `src` repeatedly until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		s.Contains(src[j])
		j++
		if j == len(src) {
			j = 0
		}
	}
}

// Baseline for BenchmarkSet64_NotContains_95
func BenchmarkMap_NotContains(b *testing.B) {
	m := map[uint64]empty{}
	for i := 0; i < 1e6; i++ {
		m[rand.Uint64()] = empty{}
	}

	// Create an array with new random values.
	src := make([]uint64, 1e6)
	for i := range src {
		src[i] = rand.Uint64()
	}

	b.ResetTimer()
	// Check `src` repeatedly until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		if _, ok := m[src[j]]; !ok {
			j++
			if j == len(src) {
				j = 0
			}
		}
	}
}

// Add values to the set until it reaches 95% full
func BenchmarkSet64_Add_95(b *testing.B) {
	s, _ := NewSet64(slice64(make([]uint64, 1e6)))
	var N int = 0.95e6

	// Create an array with new random values.
	src := make([]uint64, N)
	for i := range src {
		src[i] = rand.Uint64()
	}

	b.ResetTimer()
	// Check `src` repeatedly until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		added, _ := s.Add(src[j])
		if added {
			j++
			if j == len(src) {
				b.StopTimer()
				j = 0
				s.Clear()
				b.StartTimer()
			}
		}
	}
}

// Baseline for BenchmarkSet64_Add_95
func BenchmarkMap_Add(b *testing.B) {
	// Create an array with new random values.
	src := make([]uint64, 1e6)
	for i := range src {
		src[i] = rand.Uint64()
	}

	m := map[uint64]empty{}

	b.ResetTimer()
	// Check `src` repeatedly until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		if _, ok := m[src[j]]; !ok {
			m[src[j]] = empty{}
			j++
			if j == len(src) {
				b.StopTimer()
				j = 0
				m = map[uint64]empty{}
				b.StartTimer()
			}
		}
	}
}

func TestIVCache_Active(t *testing.T) {
	vecs := MakeVecs(2)
	cache := NewIVCache(5)
	added, err := cache.Add(vecs[0])
	if err != nil {
		t.Error(err)
	}
	if !added {
		t.Error("First addition to a clean cache should succeed")
	}
	added, err = cache.Add(vecs[0])
	if err != nil {
		t.Error(err)
	}
	if added {
		t.Error("Duplicate add should fail")
	}
	added, err = cache.Add(vecs[1])
	if err != nil {
		t.Error(err)
	}
	if !added {
		t.Error("Addition of a new vector should succeed")
	}
	added, err = cache.Add(vecs[1])
	if err != nil {
		t.Error(err)
	}
	if added {
		t.Error("Second duplicate add should fail")
	}
}

func TestIVCache_Archive(t *testing.T) {
	n := 256
	vecs0 := MakeVecs(n)
	vecs1 := MakeVecs(n)
	vecs2 := MakeVecs(n)
	// IVCache is guaranteed to remember at least `n` vectors, but always fewer than `3*n`
	cache := NewIVCache(n)
	// Add enough vectors to overflow the archive, so the first vectors are forgotten.
	for i, vecs := range [][][32]byte{vecs0, vecs1, vecs2} {
		for j, v := range vecs {
			if j == 255 {
				j++
				j--
			}
			added, err := cache.Add(v)
			if err != nil {
				t.Error(err)
			}
			if !added {
				t.Errorf("Round %d item %d: Addition of a new vector should succeed", i, j)
			}
		}

		// Check that this batch is all remembered.
		for j, v := range vecs {
			added, err := cache.Add(v)
			if err != nil {
				t.Error(err)
			}
			if added {
				t.Errorf("Round %d item %d: Duplicate add should fail", i, j)
			}
		}
	}

	added, err := cache.Add(vecs0[0])
	if err != nil {
		t.Error(err)
	}
	if !added {
		t.Error("Expected the first vector to be forgotten")
	}
}

func BenchmarkIVCache_Fit(b *testing.B) {
	vecs := MakeVecs(1e6)
	// All vectors will fit in the active set.
	cache := NewIVCache(len(vecs) * 2)
	b.ResetTimer()
	j := 0
	for i := 0; i < b.N; i++ {
		added, _ := cache.Add(vecs[j])
		if !added {
			b.Error("Collision!")
		}
		j++
		if j == len(vecs) {
			b.StopTimer()
			j = 0
			cache = NewIVCache(len(vecs))
			b.StartTimer()
		}
	}
}

func BenchmarkIVCache_Overflow(b *testing.B) {
	vecs := MakeVecs(1e6)
	// Every addition will archive the active set.
	cache := NewIVCache(1)
	b.ResetTimer()
	j := 0
	for i := 0; i < b.N; i++ {
		added, _ := cache.Add(vecs[j])
		if !added {
			b.Error("Collision!")
		}
		j++
		if j == len(vecs) {
			j = 0
		}
	}
}

func BenchmarkIVCache_Parallel(b *testing.B) {
	vecs := MakeVecs(b.N)
	c := make(chan [32]byte, b.N)
	for _, v := range vecs {
		c <- v
	}
	close(c)
	// Exercise both expansion and archiving.
	cache := NewIVCache(256)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			added, _ := cache.Add(<-c)
			if !added {
				b.Error("Collision!")
			}
		}
	})
}

func BenchmarkIVCache_File(b *testing.B) {
	vecs := MakeVecs(10e6) // Use 80 MB of RAM
	makeCache := func() (string, IVCache) {
		dir, err := ioutil.TempDir("", "outline_replay_benchmark")
		if err != nil {
			b.Fatal(err)
		}
		files := make([]File, 3)
		for i := range files {
			var err error
			// All vectors will fit in the active set.
			files[i], err = MakeFile(dir, 100e6)
			if err != nil {
				b.Fatal(err)
			}
		}
		cache, err := NewIVFileCache(files, MakeByteHasher())
		if err != nil {
			b.Fatal(err)
		}
		return dir, cache
	}
	dir, cache := makeCache()
	b.ResetTimer()
	j := 0
	for i := 0; i < b.N; i++ {
		added, _ := cache.Add(vecs[j])
		if !added {
			b.Error("Collision!")
		}
		j++
		if j == len(vecs) {
			b.StopTimer()
			j = 0
			os.RemoveAll(dir)
			dir, cache = makeCache()
			b.StartTimer()
		}
	}
	os.RemoveAll(dir)
}
