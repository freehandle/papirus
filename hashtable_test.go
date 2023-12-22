package papirus

import (
	"encoding/binary"
	"testing"

	"github.com/freehandle/breeze/crypto"
)

func creditOrDebit(found bool, hash crypto.Hash, b *Bucket, item int64, param []byte) OperationResult {
	sign := int64(1)
	if param[0] == 1 {
		sign = -1 * sign
	}
	value := sign * int64(binary.LittleEndian.Uint64(param[1:]))
	if found {
		acc := b.ReadItem(item)
		balance := int64(binary.LittleEndian.Uint64(acc[crypto.Size:]))
		if value == 0 {
			return OperationResult{
				Result: QueryResult{Ok: true, Data: acc},
			}
		}
		newbalance := balance + value
		if newbalance > 0 {
			// update balance
			acc := make([]byte, crypto.Size+8)
			binary.LittleEndian.PutUint64(acc[crypto.Size:], uint64(newbalance))
			copy(acc[0:crypto.Size], hash[:])
			b.WriteItem(item, acc)
			return OperationResult{
				Result: QueryResult{Ok: true, Data: acc},
			}
		} else if newbalance == 0 {
			// account is market to be deleted
			return OperationResult{
				Deleted: &Item{Bucket: b, Item: item},
				Result:  QueryResult{Ok: true, Data: acc},
			}
		} else {
			return OperationResult{
				Result: QueryResult{Ok: false},
			}
		}
	} else {
		if value > 0 {
			acc := make([]byte, crypto.Size+8)
			binary.LittleEndian.PutUint64(acc[crypto.Size:], uint64(value))
			copy(acc[0:crypto.Size], hash[:])
			b.WriteItem(item, acc)
			return OperationResult{
				Added:  &Item{Bucket: b, Item: item},
				Result: QueryResult{Ok: true, Data: acc},
			}
		} else {
			return OperationResult{
				Result: QueryResult{
					Ok: false,
				},
			}
		}
	}
}

// Wallet is a hash store that stores the balance of an account. It is used to
// store the balance of the wallet and the deposits.
type Wallet struct {
	HS *HashStore[crypto.Hash]
}

// CreditHash credits the account with the given hash with the given value.
func (w *Wallet) CreditHash(hash crypto.Hash, value uint64) bool {
	response := make(chan QueryResult)
	param := make([]byte, 9)
	binary.LittleEndian.PutUint64(param[1:], value)
	ok, _ := w.HS.Query(Query[crypto.Hash]{Hash: hash, Param: param, Response: response})
	return ok
}

// Credit credits the account with the given token with the given value.
func (w *Wallet) Credit(token crypto.Token, value uint64) bool {
	hash := crypto.HashToken(token)
	return w.CreditHash(hash, value)
}

// BalanceHash returns the balance of the account with the given hash.
func (w *Wallet) BalanceHash(hash crypto.Hash) (bool, uint64) {
	response := make(chan QueryResult)
	param := make([]byte, 9)
	ok, data := w.HS.Query(Query[crypto.Hash]{Hash: hash, Param: param, Response: response})
	if ok {
		return true, binary.LittleEndian.Uint64(data[32:])
	}
	return false, 0
}

// Balance returns the balance of the account with the given token.
func (w *Wallet) Balance(token crypto.Token) (bool, uint64) {
	hash := crypto.HashToken(token)
	return w.BalanceHash(hash)
}

// DebitHash debits the account with the given hash with the given value.
func (w *Wallet) DebitHash(hash crypto.Hash, value uint64) bool {
	response := make(chan QueryResult)
	param := make([]byte, 9)
	param[0] = 1
	binary.LittleEndian.PutUint64(param[1:], value)
	ok, _ := w.HS.Query(Query[crypto.Hash]{Hash: hash, Param: param, Response: response})
	return ok
}

// Debit debits the account with the given token with the given value.
func (w *Wallet) Debit(token crypto.Token, value uint64) bool {
	hash := crypto.HashToken(token)
	return w.DebitHash(hash, value)
}

// Close graciously closes the wallet.
func (w *Wallet) Close() bool {
	ok := make(chan bool)
	w.HS.Stop <- ok
	return <-ok
}

func NewMemoryWalletStore(name string, bitsForBucket int64) *Wallet {
	nbytes := 56 + int64(1<<bitsForBucket)*(40*6+8)
	bytestore := NewMemoryStore(nbytes)
	Bucketstore := NewBucketStore(40, 6, bytestore)
	w := &Wallet{
		HS: NewHashStore(name, Bucketstore, int(bitsForBucket), creditOrDebit),
	}
	w.HS.Start()
	return w
}
func NewMemoryWalletStoreFromBytes(name string, data []byte) *Wallet {
	bytestore := NewMemoryStore(0)
	return newWalltetStoreFromBytes(name, bytestore, data)
}

func newWalltetStoreFromBytes(name string, store ByteStore, data []byte) *Wallet {
	hs := NewHashStoreFromClonedBytes(name, store, creditOrDebit, data)
	w := &Wallet{
		HS: hs,
	}
	w.HS.Start()
	return w
}

func (w *Wallet) Bytes() []byte {
	return w.HS.Bytes()
}

func TestClone(t *testing.T) {
	wallet := NewMemoryWalletStore("wallet", 8)
	for n := 0; n < 10000; n++ {
		token, _ := crypto.RandomAsymetricKey()
		wallet.Credit(token, 1000)
	}

	newWallet := wallet.HS.Clone()
	hash := wallet.HS.Hash(crypto.Hasher)
	newHash := newWallet.Hash(crypto.Hasher)
	if hash != newHash {
		t.Error("hashes do not match")
	}
}

func TestBuildFromBytes(t *testing.T) {
	wallet := NewMemoryWalletStore("wallet", 8)
	for n := 0; n < 10000; n++ {
		token, _ := crypto.RandomAsymetricKey()
		wallet.Credit(token, 1000)
	}
	bytes := wallet.Bytes()
	newWallet := NewMemoryWalletStoreFromBytes("wallet", bytes)
	hash := wallet.HS.Hash(crypto.Hasher)
	newHash := newWallet.HS.Hash(crypto.Hasher)
	if hash != newHash {
		t.Error("hashes do not match")
	}
}
