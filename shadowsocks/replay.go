package shadowsocks

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sync"
)

// Fix the length of all inputs at 32 bytes
const length = 32

// Hasher represents a salted 64-bit hash of a fixed-length array.
type Hasher interface {
	Hash([length]byte) uint64
}

// A Hasher that implements a classic Tabulation Hash:
// https://en.wikipedia.org/wiki/Tabulation_hashing
type byteHasher [length][256]uint64

// MakeByteHasher returns a Hasher that implements a tabulation hash.
func MakeByteHasher() Hasher {
	var h byteHasher
	for i := 0; i < length; i++ {
		for j := 0; j < 256; j++ {
			var num [8]byte
			if _, err := rand.Read(num[:]); err != nil {
				panic("Failed to acquire entropy")
			}
			h[i][j] = binary.BigEndian.Uint64(num[:])
		}
	}
	return &h
}

func (h *byteHasher) Hash(vec [length]byte) uint64 {
	var hash uint64
	for i := 0; i < length; i++ {
		hash ^= h[i][vec[i]]
	}
	return hash
}

// TODO: Add a method to save byteHasher to a file and recover it.

// File represents the minimal random-access file required by Set64.
type File interface {
	io.ReaderAt
	io.WriterAt
}

// Index64 is an abstraction encompassing []uint64 and File.
type Index64 interface {
	Get(index int64) (val uint64, err error)
	Set(index int64, val uint64) error
}

// Implementation of the Index64 interface wrapping []uint64
type slice64 []uint64

func (s slice64) check(index int64) error {
	if index >= int64(len(s)) {
		return io.EOF
	} else if index < 0 {
		return errors.New("negative index")
	}
	return nil
}

func (s slice64) Get(index int64) (val uint64, err error) {
	err = s.check(index)
	if err == nil {
		val = s[index]
	}
	return
}

func (s slice64) Set(index int64, val uint64) (err error) {
	err = s.check(index)
	if err == nil {
		s[index] = val
	}
	return
}

// Implementation of the Index64 interface wrapping File.
// TODO: Unit tests for file64.
type file64 struct {
	Index64
	f File
}

func (f file64) Get(index int64) (uint64, error) {
	var buf [8]byte
	n, err := f.f.ReadAt(buf[:], index*8)
	if n < 8 {
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("Short read: %d < 8", n)
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

func (f file64) Set(index int64, v uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	n, err := f.f.WriteAt(buf[:], index*8)
	if n < 8 {
		if err != nil {
			return err
		}
		return fmt.Errorf("Short write: %d < 8", n)
	}
	return nil
}

// Set64 is an add-only set of uint64s, implemented as a linear-probing
// ordered prefix table.  For good performance, values should be uniformly
// distributed.  Zero is not an allowed value.
type Set64 struct {
	length int64
	vals   Index64
	count  int64 // Number of nonzero values.
	wrap   int64 // vals[wrap:] + vals[:wrap] is in ascending order, ignoring zeros.
}

// NewSet64 returns a Set64 backed by `file`, whose length must be a power of 2 and
// at least 8.  If `file` already contains a Set64, the returned Set64 will maintain
// that state.
func NewSet64(file Index64) (*Set64, error) {
	// Figure out the length, count, and wrap from the contents of file.
	var maxVal uint64 = 0
	var maxIndex int64 = -1
	var minVal uint64 = 0
	var minIndex int64 = -1
	var count int64 = 0
	var i int64 = 0
	for {
		val, err := file.Get(i)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if val != 0 {
			count++
			if val > maxVal {
				maxVal = val
				maxIndex = i
			}
			if val < minVal {
				minVal = val
				minIndex = i
			}
		}
		i++
	}
	var wrap int64 = 0
	if minIndex > maxIndex {
		wrap = maxIndex + 1
	}
	return &Set64{
		length: i,
		vals:   file,
		count:  count,
		wrap:   wrap,
	}, nil
}

func split(x uint64) (lower uint64, upper uint64) {
	return
}

// Returns a * b / 2^64, without requiring 128-bit arithmetic.
// TODO: unit tests
func topmul(a int64, b uint64) int64 {
	a0, a1 := uint64(uint32(a)), a>>32
	b0, b1 := uint64(uint32(b)), b>>32
	a0b0 := a0 * b0
	a0b1 := a0 * b1
	a1b0 := a1 * int64(b0)
	a1b1 := a1 * int64(b1)

	carry := (a0b0>>32 + uint64(uint32(a0b1)) + uint64(uint32(a1b0))) >> 32
	return a1b1 + int64(a0b1>>32) + a1b0>>32 + int64(carry)
}

func (s *Set64) start(val uint64) int64 {
	i := topmul(s.length, val)
	if i < s.wrap {
		return s.wrap
	}
	return i
}

// Contains returns true if `val` is in the set.
func (s *Set64) Contains(val uint64) (bool, error) {
	if val == 0 {
		return false, errors.New("0 is not an allowed value")
	}
	i := s.start(val)
	for {
		v, err := s.vals.Get(i)
		if err != nil {
			if errors.Is(err, io.EOF) {
				i = 0
			} else {
				return false, err
			}
		} else {
			if v == 0 || v > val {
				return false, nil
			} else if v == val {
				return true, nil
			}
			i++
		}
		if i == s.wrap {
			return false, nil
		}
	}
}

// Add accepts a value, and returns true if the value was added.
// The set must not be full when Add is called.
func (s *Set64) Add(val uint64) (bool, error) {
	if val == 0 {
		return false, errors.New("0 is not an allowed value")
	}
	if s.count == s.length {
		return false, errors.New("Set is full")
	}
	i := s.start(val)
	for {
		v, err := s.vals.Get(i)
		if err != nil {
			if errors.Is(err, io.EOF) {
				i = 0
			} else {
				return false, err
			}
		} else {
			if v == 0 {
				if err := s.vals.Set(i, val); err != nil {
					return false, err
				}
				s.count++
				return true, nil // val was added to the set.
			} else if v == val {
				return false, nil // val was already in the set.
			} else if v > val {
				// Swap values to maintain ordering and continue.
				if err := s.vals.Set(i, val); err != nil {
					return false, err
				}
				val = v
			}
			i++
		}
		if i == s.wrap {
			// We have reached the wrap point, so val is the largest value in vals,
			// and s.vals[i] is the smallest value (or 0).
			v, err := s.vals.Get(i)
			if err != nil {
				return false, err
			}
			if err := s.vals.Set(i, val); err != nil {
				return false, err
			}
			val = v
			s.wrap++
			if val == 0 {
				s.count++
				return true, nil
			}
			i++
		}
	}
}

// Full returns true if the set has reached or exceeded the specified occupancy fraction.
func (s *Set64) Count() int64 {
	return s.count
}

func (s *Set64) Capacity() int64 {
	return s.length
}

// Clear resets the set to its initial, empty state.
func (s *Set64) Clear() error {
	var i int64
	for i = 0; i < s.length; i++ {
		if err := s.vals.Set(i, 0); err != nil {
			return err
		}
	}
	s.count = 0
	s.wrap = 0
	return nil
}

// IVCache is a thread-safe cache for initialization vectors.
type IVCache interface {
	// Add an IV to the cache.  Returns false if the IV is already present.
	// An error is only returned in exceptional circumstances.
	Add(iv [length]byte) (bool, error)
}

// An implementation of IVCache using Set64, with a false-positive
// probability of N/2^64, where N is the number of cache entries.
type set64Cache struct {
	IVCache
	locks  []sync.RWMutex // locks[i] controls all access to sets[i].
	sets   []*Set64       // The first entry is the active set, and the last entry is the spare.
	hasher Hasher
}

// The maximum occupancy to allow in the active set.
// Higher values have better memory efficiency, but additions take
// time O(1/(1 - occupancy)).
const maxOccupancy = 0.95

type memfile []byte

func (m memfile) ReadAt(p []byte, off int64) (int, error) {
	i := int(off)
	if i >= len(m) {
		return 0, io.EOF
	}
	n := copy(p, m[i:])
	if n < len(p) {
		return n, errors.New("Read too close to end")
	}
	return n, nil
}

func (m memfile) WriteAt(p []byte, off int64) (int, error) {
	i := int(off)
	if i >= len(m) {
		return 0, io.EOF
	}
	n := copy(m[i:], p)
	if n < len(p) {
		return n, errors.New("Write too close to end")
	}
	return n, nil
}

func (m memfile) Seek(offset int64, whence int) (int64, error) {
	if offset != 0 || whence != io.SeekEnd {
		return 0, errors.New("Unsupported use of seek")
	}
	return int64(len(m)), nil
}

// NewIVCache returns a memory-backed IVCache, initialized with a random salt.
// The cache promises to remember at least the last `n` IVs.
func NewIVCache(n int) IVCache {
	n = int(float64(n)/maxOccupancy) + 1
	s1, err := NewSet64(slice64(make([]uint64, n)))
	if err != nil {
		panic(err)
	}
	s2, err := NewSet64(slice64(make([]uint64, n)))
	if err != nil {
		panic(err)
	}
	s3, err := NewSet64(slice64(make([]uint64, n)))
	if err != nil {
		panic(err)
	}
	return &set64Cache{
		locks:  make([]sync.RWMutex, 3),
		sets:   []*Set64{s1, s2, s3},
		hasher: MakeByteHasher(),
	}
}

// MakeFile returns a file in `dir` with a length of `size` bytes.
func MakeFile(dir string, size int64) (*os.File, error) {
	f, err := ioutil.TempFile(dir, "outline_replay_cache")
	if err != nil {
		return nil, err
	}
	if err = f.Truncate(size); err != nil {
		return nil, err
	}
	return f, nil
}

// NewIVFileCache returns an IVCache backed by the provided `files`
// (of which there must be at least 3), using `hasher` for hashing.
// When reconstituting an IVCache from disk, the files must be provided in the
// same order, and `hasher` must be the same hash function.
func NewIVFileCache(files []File, hasher Hasher) (IVCache, error) {
	sets := make([]*Set64, len(files))
	for i, f := range files {
		var err error
		sets[i], err = NewSet64(file64{f: f})
		if err != nil {
			return nil, err
		}
	}
	// Make sure that the spare set is clear, in case we are recovering from
	// an unclean shutdown.
	spare := sets[len(sets)-1]
	if spare.Count() != 0 {
		spare.Clear()
	}
	return &set64Cache{
		locks:  make([]sync.RWMutex, len(sets)),
		sets:   sets,
		hasher: hasher,
	}, nil
}

func (c *set64Cache) Add(iv [length]byte) (bool, error) {
	if c == nil {
		// Cache is disabled, so every IV is new.
		return true, nil
	}

	N := len(c.sets)
	if N < 3 {
		return false, errors.New("Need at least one active, archive, and spare set")
	} else if len(c.locks) != N {
		return false, errors.New("Wrong number of locks")
	}
	found := make([]bool, N)
	errs := make([]error, N)

	hash := c.hasher.Hash(iv)
	// Start a scan of each archive set (c.sets[1:N-1]).
	// If any scan finds `hash`, it will set `found` to true.
	// If any scan encounters an error, it will set `err` to non-nil.
	// When all scans are finished, `wg` will complete.
	var wg sync.WaitGroup
	for i := 1; i < N-1; i++ {
		wg.Add(1)
		go func(i int) {
			c.locks[i].RLock()
			found[i], errs[i] = c.sets[i].Contains(hash)
			c.locks[i].RUnlock()
			wg.Done()
		}(i)
	}
	// Try to add this hash to the active set (c.sets[0]).
	c.locks[0].Lock()
	added, addErr := c.sets[0].Add(hash)
	// Wait for all the archive checks to finish.
	wg.Wait()
	if added && float64(c.sets[0].Count()) >= maxOccupancy*float64(c.sets[0].Capacity()) {
		// This addition caused the active set to cross the max occupancy threshold, so
		// it's time to archive it.
		// Acquire all the remaining writer locks, in order.
		for i := 1; i < N; i++ {
			c.locks[i].Lock()
		}
		// Cyclic permutation of c.sets, archiving the active set and
		// making the spare set the new active set.
		spare := c.sets[N-1]
		copy(c.sets[1:], c.sets[0:N-1])
		c.sets[0] = spare
		// Unlock all archive sets, but not the new spare
		for i := 1; i < N-1; i++ {
			c.locks[i].Unlock()
		}
		// Clear the new spare set.  This is an O(n) operation, so we do it asynchronously.
		// Clearing a set is faster than populating it, so this operation should complete
		// before the new active set can fill up and trigger the next rotation.
		go func() {
			c.sets[N-1].Clear()
			c.locks[N-1].Unlock()
		}()
	}
	c.locks[0].Unlock()

	for _, e := range errs {
		if e != nil {
			return false, e
		}
	}
	for _, f := range found {
		if f {
			return false, nil
		}
	}
	return added, addErr
}
