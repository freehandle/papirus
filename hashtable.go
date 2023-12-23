package papirus

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"time"
)

var cloneInterval time.Duration

func init() {
	var err error
	cloneInterval, err = time.ParseDuration("10ms")
	if err != nil {
		panic(err)
	}
}

const (
	size       = int(sha256.Size)
	size64     = int64(size)
	nBuckets   = int64(2048) // TODO: ajusta depois
	loadFactor = int64(2)    // number of overflow buckets that will trigger duplication
)

type Item struct {
	Bucket *Bucket
	Item   int64
}

type OperationResult struct {
	Added   *Item
	Deleted *Item
	Result  QueryResult
}

type QueryResult struct {
	Ok   bool
	Data []byte
}

type Query[T Hasher] struct {
	Hash     T
	Param    []byte
	Response chan QueryResult
}

type Hasher interface {
	ToInt64() int64
	Equals([]byte) bool
}

type QueryOperation[T Hasher] func(found bool, hash T, b *Bucket, item int64, data []byte) OperationResult

type HashStore[T Hasher] struct {
	name             string
	store            *BucketStore
	bitsForBucket    int
	mask             int64
	bitsCount        []int // number of items in the bucket
	freeOverflows    []int64
	isReady          bool
	operation        QueryOperation[T]
	query            chan Query[T]
	doubleJob        chan int64
	cloneJob         chan int64
	Stop             chan chan bool
	clone            chan chan bool
	cloned           chan bool
	isDoubling       bool
	bitsTransferered int64
	newHashStore     *HashStore[T]
}

func NewHashStore[T Hasher](name string, buckets *BucketStore, bitsForBucket int, operation QueryOperation[T]) *HashStore[T] {
	if bitsForBucket < 6 {
		panic("bitsForBucket too small")
	}
	return &HashStore[T]{
		name:             name,
		store:            buckets,
		bitsForBucket:    bitsForBucket,
		mask:             int64(1<<bitsForBucket - 1),
		bitsCount:        make([]int, 1<<bitsForBucket),
		freeOverflows:    make([]int64, 0),
		isReady:          true,
		operation:        operation,
		query:            make(chan Query[T]),
		doubleJob:        make(chan int64),
		Stop:             make(chan chan bool),
		cloneJob:         make(chan int64),
		clone:            make(chan chan bool),
		cloned:           make(chan bool),
		isDoubling:       false,
		bitsTransferered: 0,
		newHashStore:     nil,
	}
}

func (hs *HashStore[T]) Query(q Query[T]) (bool, []byte) {
	hs.query <- q
	resp := <-q.Response
	return resp.Ok, resp.Data
}

func (hs *HashStore[T]) Start() {
	go func() {
		for {
			select {
			case q := <-hs.query:
				resp := hs.findAndOperate(q)
				q.Response <- resp
			case bucket := <-hs.doubleJob:
				hs.continueDuplication(bucket)
			case hs.cloned = <-hs.clone:
				hs.StartCloning()
			case <-hs.cloneJob:
				hs.continueCloning()
			case ok := <-hs.Stop:
				// wait until cloning and doubling is complete
				if hs.store.isCloning || hs.isDoubling {
					ok <- false
				}
				close(hs.query)
				close(hs.doubleJob)
				close(hs.cloneJob)
				close(hs.Stop)
				ok <- true
				return
			}
		}
	}()
}

func (ws *HashStore[T]) findAndOperate(q Query[T]) QueryResult {
	hashMask := q.Hash.ToInt64() & ws.mask
	wallet := ws
	if ws.isDoubling && hashMask <= ws.bitsTransferered {
		hashMask = q.Hash.ToInt64() & ws.newHashStore.mask
		wallet = ws.newHashStore
	}
	bucket := wallet.store.ReadBucket(hashMask)
	countAccounts, totalAccounts := 0, wallet.bitsCount[hashMask]
	for {
		for item := int64(0); item < ws.store.itemsPerBucket; item++ {
			countAccounts += 1
			if countAccounts > int(totalAccounts) {
				resp := ws.operation(false, q.Hash, bucket, item, q.Param)
				wallet.ProcessMutation(hashMask, resp.Added, resp.Deleted, countAccounts) // ws -> wallet
				return resp.Result
			}
			data := bucket.ReadItem(item)
			if q.Hash.Equals(data) {
				resp := ws.operation(true, q.Hash, bucket, item, q.Param)
				wallet.ProcessMutation(hashMask, resp.Added, resp.Deleted, countAccounts) // ws -> walltet
				return resp.Result
			}
		}
		bucket = bucket.NextBucket()
		if bucket == nil {
			panic(fmt.Sprintf("could not get here: %v %v", countAccounts, totalAccounts))
		}
	}
}

func (ws *HashStore[T]) ProcessMutation(hashMask int64, added *Item, deleted *Item, count int) {
	if added != nil {
		ws.bitsCount[hashMask] += 1
		if added.Item == ws.store.itemsPerBucket-1 {
			if len(ws.freeOverflows) > 0 {
				added.Bucket.WriteOverflow(ws.freeOverflows[0])
				ws.freeOverflows = ws.freeOverflows[1:]
			} else {
				added.Bucket.AppendOverflow()
			}
		}
		if (ws.store.bucketCount > 2*int64(1<<ws.bitsForBucket)) && !ws.store.isCloning && !ws.isDoubling {
			ws.startDuplication()
		}
	}
	if deleted != nil {
		lastItem := ws.bitsCount[hashMask] - 1
		ws.bitsCount[hashMask] -= 1
		if count == lastItem {
			deleted.Bucket.WriteItem(deleted.Item, make([]byte, ws.store.itemBytes))
			return
		}
		var previousBucket *Bucket
		lastBucket := deleted.Bucket
		for {
			if nextBucket := lastBucket.NextBucket(); nextBucket != nil {
				previousBucket = lastBucket
				lastBucket = nextBucket
			} else {
				item := lastItem % int(ws.store.itemsPerBucket)
				lastBucket.WriteItem(int64(item), make([]byte, ws.store.itemBytes))
				if item == 0 && previousBucket != nil {
					ws.freeOverflows = append(ws.freeOverflows, lastBucket.n)
					previousBucket.WriteOverflow(0)
				}
				break
			}
		}
	}
}

func (w *HashStore[T]) transferBuckets(starting, N int64) {
	// mask to test the newer bit
	highBit := uint64(1 << w.bitsForBucket)
	for bucket := starting; bucket < starting+N; bucket++ {
		// read items for the bucket
		itemsCount := int64(w.bitsCount[bucket])
		items := w.store.ReadBucket(bucket).ReadBulk(itemsCount)
		// divide items by lBit (newer bit = 0) and hBit (newer bit = 1)
		lBitBucket := make([]byte, 0, len(items)/2)
		hBitBucket := make([]byte, 0, len(items)/2)
		for _, item := range items {
			hashBit := (uint64(item[0]) + (uint64(item[1]) << 8) + (uint64(item[2]) << 16) +
				(uint64(item[3]) << 24))
			hashBit = hashBit & highBit
			if hashBit > 0 {
				hBitBucket = append(hBitBucket, item...)
			} else {
				lBitBucket = append(lBitBucket, item...)
			}
		}
		// put lBit and hBit items in new wallter
		w.newHashStore.bitsCount[bucket] = len(lBitBucket) / int(w.store.itemBytes)
		w.newHashStore.store.ReadBucket(bucket).WriteBulk(lBitBucket)
		w.newHashStore.bitsCount[bucket+int64(highBit)] = len(hBitBucket) / int(w.store.itemBytes)
		w.newHashStore.store.ReadBucket(bucket + int64(highBit)).WriteBulk(hBitBucket)
	}
	w.bitsTransferered = starting + N - 1
}

func (w *HashStore[T]) continueDuplication(bucket int64) {
	//for bucket := int64(0); bucket < 1<<w.bitsForBucket; bucket += NBuckets {
	if bucket+nBuckets > 1<<w.bitsForBucket {
		w.transferBuckets(bucket, 1<<w.bitsForBucket-bucket)
	} else {
		w.transferBuckets(bucket, nBuckets)
	}
	if bucket+nBuckets < 1<<w.bitsForBucket {
		go func() {
			sleep, _ := time.ParseDuration("10ms")
			time.Sleep(sleep)
			w.doubleJob <- bucket + nBuckets
		}()
	} else {
		// task completed merge stores
		w.store.bytes.Merge(w.newHashStore.store.bytes)
		w.bitsForBucket = w.newHashStore.bitsForBucket
		w.mask = w.newHashStore.mask
		w.bitsCount = w.newHashStore.bitsCount
		w.freeOverflows = w.newHashStore.freeOverflows
		w.store.bucketCount = w.newHashStore.store.bucketCount
		w.isDoubling = false
		w.bitsTransferered = 0
		w.newHashStore = nil
		w.isReady = true
	}
}

func (w *HashStore[T]) startDuplication() {
	w.isDoubling = true
	newStoreBitsForBucket := int64(w.bitsForBucket + 1)
	newStoreInitialBuckets := int64(1 << newStoreBitsForBucket)
	newStoreSize := newStoreInitialBuckets*w.store.bucketBytes + w.store.headerBytes
	newByteStore := w.store.bytes.New(newStoreSize)
	header := w.store.bytes.ReadAt(0, w.store.headerBytes)
	newByteStore.WriteAt(0, header)
	newBucketStore := NewBucketStore(w.store.itemBytes, w.store.itemsPerBucket, newByteStore)
	w.newHashStore = NewHashStore(w.name, newBucketStore, int(newStoreBitsForBucket), w.operation)
	w.newHashStore.isReady = false
	w.bitsTransferered = 0
	w.continueDuplication(0)
}

// Put the hashstore into cloning mode and start the clonning job.
func (hs *HashStore[T]) StartCloning() {
	hs.store.isCloning = true
	timeStamp := time.Now().Format("2006_01_02_15_04_05")
	hs.store.journal = NewJournalStore(fmt.Sprintf("%v_journal_%v.dat", hs.name, timeStamp))
	hs.store.cloning = NewJournalStore(fmt.Sprintf("%v_clone_%v.dat", hs.name, timeStamp))
}

func (hs *HashStore[T]) continueCloning() {
	bucketsToClone := maxCloningBlockSize / hs.store.bucketBytes
	if hs.store.bucketsCloned+bucketsToClone > hs.store.bucketToClone {
		bucketsToClone = hs.store.bucketToClone - hs.store.bucketsCloned
	}
	bytesCount := hs.store.bucketBytes * bucketsToClone
	offset := hs.store.headerBytes + hs.store.bucketsCloned*hs.store.bucketBytes
	data := hs.store.bytes.ReadAt(offset, bytesCount)
	hs.store.bucketsCloned += bucketsToClone
	go func() {
		hs.store.cloning.Append(data)
		time.Sleep(cloneInterval)
		if hs.store.bucketsCloned < hs.store.bucketToClone {
			hs.cloneJob <- hs.store.bucketsCloned
		} else {
			hs.store.journal.Close()
			hs.store.cloning.Close()
			hs.store.isCloning = false
			hs.store.journal = nil
			hs.store.cloning = nil
			hs.cloned <- true
		}
	}()
}

func PutUint64(v uint64, data *[]byte) {
	b := make([]byte, 8)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
	*data = append(*data, b...)
}

func ParseUint64(data []byte, position int) (uint64, int) {
	if position+7 >= len(data) {
		return 0, position + 8
	}
	value := uint64(data[position+0]) |
		uint64(data[position+1])<<8 |
		uint64(data[position+2])<<16 |
		uint64(data[position+3])<<24 |
		uint64(data[position+4])<<32 |
		uint64(data[position+5])<<40 |
		uint64(data[position+6])<<48 |
		uint64(data[position+7])<<56
	return value, position + 8
}

func (hs *HashStore[T]) Bytes() []byte {
	size := hs.store.bytes.Size()
	clone := NewMemoryStore(size)
	Clone(hs.store.bytes, clone)

	data := []byte{byte(hs.bitsForBucket)}
	PutUint64(uint64(hs.store.itemBytes), &data)
	PutUint64(uint64(hs.store.itemsPerBucket), &data)
	PutUint64(uint64(len(hs.bitsCount)), &data)
	for _, count := range hs.bitsCount {
		PutUint64(uint64(count), &data)
	}
	PutUint64(uint64(len(hs.freeOverflows)), &data)
	for _, overflow := range hs.freeOverflows {
		PutUint64(uint64(overflow), &data)
	}
	data = append(data, clone.data...)
	return data
}

func NewHashStoreFromClonedBytes[T Hasher](name string, byteStore ByteStore, operation QueryOperation[T], data []byte) *HashStore[T] {
	if len(data) < 1 {
		return nil
	}
	bitsForBucket := data[0]
	hs := &HashStore[T]{
		name:             name,
		bitsForBucket:    int(bitsForBucket),
		mask:             int64(1<<bitsForBucket - 1),
		isReady:          true,
		operation:        operation,
		query:            make(chan Query[T]),
		doubleJob:        make(chan int64),
		Stop:             make(chan chan bool),
		cloneJob:         make(chan int64),
		clone:            make(chan chan bool),
		cloned:           make(chan bool),
		isDoubling:       false,
		bitsTransferered: 0,
		newHashStore:     nil,
	}
	var itemBytes, itemsPerBucket, bitsCount uint64
	position := 1
	itemBytes, position = ParseUint64(data, position)
	itemsPerBucket, position = ParseUint64(data, position)
	bitsCount, position = ParseUint64(data, position)
	hs.bitsCount = make([]int, int(bitsCount))
	var count uint64
	for i := 0; i < int(bitsCount); i++ {
		count, position = ParseUint64(data, position)
		hs.bitsCount[i] = int(count)
	}
	var freeOverflows uint64
	freeOverflows, position = ParseUint64(data, position)
	hs.freeOverflows = make([]int64, int(freeOverflows))
	var overflow uint64
	for i := 0; i < int(freeOverflows); i++ {
		overflow, position = ParseUint64(data, position)
		hs.freeOverflows[i] = int64(overflow)
	}
	if len(data) > position {
		byteStore.Append(data[position:])
	}
	hs.store = NewBucketStore(int64(itemBytes), int64(itemsPerBucket), byteStore)
	return hs
}

func (hs *HashStore[T]) Clone() *HashStore[T] {
	size := hs.store.bytes.Size()
	cloneName := fmt.Sprintf("%v_clone_%v", hs.name, time.Now())
	//clone := NewFileStore(fmt.Sprintf("%v.dat", cloneName), size)
	clone := NewMemoryStore(size)
	Clone(hs.store.bytes, clone)
	bs := NewBucketStore(hs.store.itemBytes, hs.store.itemsPerBucket, clone)
	nhs := NewHashStore[T](cloneName, bs, hs.bitsForBucket, hs.operation)
	nhs.bitsCount = make([]int, len(hs.bitsCount))
	copy(nhs.bitsCount, hs.bitsCount)
	nhs.freeOverflows = make([]int64, len(hs.freeOverflows))
	copy(nhs.freeOverflows, hs.freeOverflows)
	return nhs
}

func (hs *HashStore[T]) CloneAsync() chan *HashStore[T] {
	output := make(chan *HashStore[T])
	done := make(chan bool)
	hs.clone <- done
	go func() {
		ok := <-done
		if !ok {
			output <- nil
			return
		}
		clone := hs.store.cloning.AsByteStore()
		journal := hs.store.journal.AsByteStore()
		buckets := RecreateBucket(clone, journal)
		output <- NewHashStore[T](fmt.Sprintf("%v_clone", hs.name), buckets, hs.bitsForBucket, hs.operation)
	}()
	return output
}

// Structure to implement sorting of hashes.
type itemsArray [][]byte

func (ia itemsArray) Len() int {
	return len(ia)
}

func (ia itemsArray) Less(i, j int) bool {
	for n := 0; n < size; n++ {
		if ia[i][n] < ia[j][n] {
			return true
		}
		if ia[i][n] > ia[j][n] {
			return false
		}
	}
	return false
}

func (ia itemsArray) Swap(i, j int) {
	ia[i], ia[j] = ia[j], ia[i]
}

// Hash calculates a checksum for the state of the system. It groups hashes into
// 256 * 256 * 16 items, ordered by hash, and calculates checksum of each on of
// / these groups. The final hash is the hash of all hashes.
func (hs *HashStore[T]) Hash(HashFunction func([]byte) T) T {
	hasharray := make([]byte, 0)
	hashBlock := 256 * 256 * 16 * hs.store.itemBytes
	bucketCollection := make([]byte, 0, hashBlock)
	for n := int64(0); n < 1<<hs.bitsForBucket; n++ {
		buckets := itemsArray(hs.store.ReadBucket(n).ReadBulk(int64(hs.bitsCount[n])))
		sort.Sort(buckets)
		for _, b := range buckets {
			bucketCollection = append(bucketCollection, b...)
			if len(bucketCollection) >= int(hashBlock) {
				hash := sha256.Sum256(bucketCollection)
				hasharray = append(hasharray, hash[:]...)
				bucketCollection = make([]byte, 0, hashBlock)
			}
		}
	}
	if len(bucketCollection) > 0 {
		hash := sha256.Sum256(bucketCollection)
		hasharray = append(hasharray, hash[:]...)
	}
	return HashFunction(hasharray)
}
