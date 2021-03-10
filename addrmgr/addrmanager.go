// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	crand "crypto/rand" // for seeding
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
)

// peersFilename is the default filename to store serialized peers.
const peersFilename = "peers.json"

// AddrManager provides a concurrency safe address manager for caching potential
// peers on the Decred network.
type AddrManager struct {
	// mtx is used to ensure safe concurrent access to fields on an instance
	// of the address manager.
	mtx sync.Mutex

	// peersFile is the path of file that the address manager's serialized state
	// is saved to and loaded from.
	peersFile string

	// lookupFunc is a function provided to the address manager that is used to
	// perform DNS lookups for a given hostname.
	// The provided function MUST be safe for concurrent access.
	lookupFunc func(string) ([]net.IP, error)

	// rand is the address manager's internal PRNG.  It is used to both randomly
	// retrieve addresses from the address manager's internal new and tried
	// buckets in addition to deciding whether a not-known address is accepted
	// to the address manager.
	rand *rand.Rand

	// key is a random seed used to map addresses to a new and tried buckets.
	key [32]byte

	// addrIndex maintains an index of all addresses known to the address
	// manager, including both new and tried addresses. The key is a
	// unique string representation of the underlying network address.
	addrIndex map[string]*KnownAddress

	// addrNew stores addresses considered newly added to the address manager
	// and have not been tried.  It also serves as storage for addresses that
	// were considered tried but were randomly evicted due to the address
	// manager exceeding tried address capacity.
	addrNew [newBucketCount]map[string]*KnownAddress

	// addrTried is a collection of tried buckets that store tried addresses.
	// Tried address are address that have been tested
	addrTried [triedBucketCount][]*KnownAddress

	// addrChanged signals whether the address manager needs to have its state
	// serialized and saved to the file system.
	addrChanged bool

	// started signals whether the address manager has been started.  It's value
	// is 1 or more if started.
	started int32

	// shutdown signals whether a shutdown of the address manager has been
	// initiated.  It's value is 1 or more if a shutdown is done or in progress.
	shutdown int32

	// The following fields are used for lifecycle management of the
	// address manager.
	wg   sync.WaitGroup
	quit chan struct{}

	// nTried represents the total number of tried addresses across all tried
	// buckets.
	nTried int

	// nNew represents the total number of new addresses across all new buckets.
	nNew int

	// lamtx is used to protect access to the local address map.
	lamtx sync.Mutex

	// localAddresses stores all known local addresses, keyed by the respective
	// network address' unique string representation.
	localAddresses map[string]*localAddress

	// getTriedBucket returns an index in the tried bucket for the network
	// address.
	getTriedBucket func(netAddr *wire.NetAddress) int

	// getNewBucket returns an index in the addrNew bucket for the network
	// address.
	getNewBucket func(netAddr, srcAddr *wire.NetAddress) int

	// triedBucketSize is the maximum number of addresses in each tried bucket.
	triedBucketSize int
}

// serializedKnownAddress is used to represent the serializable state of a
// KnownAddress instance. It excludes convenience fields such as ref count and
// tried since those values can be derived from the address manager's state.
type serializedKnownAddress struct {
	Addr        string
	Src         string
	Attempts    int
	TimeStamp   int64
	LastAttempt int64
	LastSuccess int64
}

// serializedAddrManager is used to represent the serializable state of a
// AddrManager instance.
type serializedAddrManager struct {
	Version      int
	Key          [32]byte
	Addresses    []*serializedKnownAddress
	NewBuckets   [newBucketCount][]string // string is NetAddressKey
	TriedBuckets [triedBucketCount][]string
}

type localAddress struct {
	na    *wire.NetAddress
	score AddressPriority
}

// LocalAddr represents network address information for a local address.
type LocalAddr struct {
	Address string
	Port    uint16
	Score   int32
}

// AddressPriority type is used to describe the hierarchy of local address
// discovery methods.
type AddressPriority int

const (
	// InterfacePrio signifies the address is on a local interface
	InterfacePrio AddressPriority = iota

	// BoundPrio signifies the address has been explicitly bounded to.
	BoundPrio

	// UpnpPrio signifies the address was obtained from UPnP.
	UpnpPrio

	// HTTPPrio signifies the address was obtained from an external HTTP service.
	HTTPPrio

	// ManualPrio signifies the address was provided by --externalip.
	ManualPrio
)

const (
	// needAddressThreshold is the number of addresses under which the
	// address manager will claim to need more addresses.
	needAddressThreshold = 1000

	// dumpAddressInterval is the interval used to dump the address
	// cache to disk for future use.
	dumpAddressInterval = time.Minute * 10

	// defaultTriedBucketSize is the default value for the maximum number of
	// addresses in each tried address bucket.
	defaultTriedBucketSize = 256

	// triedBucketCount is the number of buckets we split tried
	// addresses over.
	triedBucketCount = 64

	// newBucketSize is the maximum number of addresses in each new address
	// bucket.
	newBucketSize = 64

	// newBucketCount is the number of buckets that we spread new addresses
	// over.
	newBucketCount = 1024

	// triedBucketsPerGroup is the number of tried buckets over which an
	// address group will be spread.
	triedBucketsPerGroup = 8

	// newBucketsPerGroup is the number of new buckets over which an
	// source address group will be spread.
	newBucketsPerGroup = 64

	// newBucketsPerAddress is the number of buckets a frequently seen new
	// address may end up in.
	newBucketsPerAddress = 8

	// numMissingDays is the number of days before which we assume an
	// address has vanished if we have not seen it announced in that long.
	numMissingDays = 30

	// numRetries is the number of tried without a single success before
	// we assume an address is bad.
	numRetries = 3

	// maxFailures is the maximum number of failures we will accept without
	// a success before considering an address bad.
	maxFailures = 5

	// minBadDays is the number of days since the last success before we
	// will consider evicting an address.
	minBadDays = 7

	// getAddrMax is the most addresses that we will send in response
	// to a getAddr message. Effectively, this defines the most addresses
	// returned from a call to AddressCache().
	getAddrMax = 2500

	// getAddrPercent is the percentage of total addresses known that we
	// will share with a call to AddressCache.
	getAddrPercent = 23

	// serialisationVersion is the current version of the on-disk format.
	serialisationVersion = 1
)

// updateAddress is a helper function to either update an address already known
// to the address manager, or to add the address if not already known.
func (a *AddrManager) updateAddress(netAddr, srcAddr *wire.NetAddress) {
	// Filter out non-routable addresses. Note that non-routable
	// also includes invalid and local addresses.
	if !IsRoutable(netAddr) {
		return
	}

	addr := NetAddressKey(netAddr)
	ka := a.find(netAddr)
	if ka != nil {
		// TODO(oga) only update addresses periodically.
		// Update the last seen time and services.
		// note that to prevent causing excess garbage on getaddr
		// messages the netaddresses in addrmanager are *immutable*,
		// if we need to change them then we replace the pointer with a
		// new copy so that we don't have to copy every na for getaddr.
		if netAddr.Timestamp.After(ka.na.Timestamp) ||
			(ka.na.Services&netAddr.Services) !=
				netAddr.Services {

			naCopy := *ka.na
			naCopy.Timestamp = netAddr.Timestamp
			naCopy.AddService(netAddr.Services)
			ka.mtx.Lock()
			ka.na = &naCopy
			ka.mtx.Unlock()
		}

		// If already in tried, we have nothing to do here.
		if ka.tried {
			return
		}

		// Already at our max?
		if ka.refs == newBucketsPerAddress {
			return
		}

		// The more entries we have, the less likely we are to add more.
		// likelihood is 2N.
		factor := int32(2 * ka.refs)
		if a.rand.Int31n(factor) != 0 {
			return
		}
	} else {
		// Make a copy of the net address to avoid races since it is
		// updated elsewhere in the addrmanager code and would otherwise
		// change the actual netaddress on the peer.
		netAddrCopy := *netAddr
		ka = &KnownAddress{na: &netAddrCopy, srcAddr: srcAddr}
		a.addrIndex[addr] = ka
		a.nNew++
		a.addrChanged = true
	}

	bucket := a.getNewBucket(netAddr, srcAddr)

	// If the address already exists in the new bucket, do not replace it.
	if _, ok := a.addrNew[bucket][addr]; ok {
		return
	}

	// Enforce max addresses.
	if len(a.addrNew[bucket]) > newBucketSize {
		log.Tracef("new bucket is full, expiring old")
		a.expireNew(bucket)
	}

	// Add to new bucket.
	ka.refs++
	a.addrNew[bucket][addr] = ka
	a.addrChanged = true

	log.Tracef("Added new address %s for a total of %d addresses", addr,
		a.nTried+a.nNew)
}

// expireNew makes space in the new buckets by expiring the really bad entries.
// If no bad entries are available we look at a few and remove the oldest.
func (a *AddrManager) expireNew(bucket int) {
	// First see if there are any entries that are so bad we can just throw
	// them away. otherwise we throw away the oldest entry in the cache.
	// Bitcoind here chooses four random and just throws the oldest of
	// those away, but we keep track of oldest in the initial traversal and
	// use that information instead.
	var oldest *KnownAddress
	for k, v := range a.addrNew[bucket] {
		if v.isBad() {
			log.Tracef("expiring bad address %v", k)
			delete(a.addrNew[bucket], k)
			a.addrChanged = true
			v.refs--
			if v.refs == 0 {
				a.nNew--
				delete(a.addrIndex, k)
			}
			continue
		}
		if oldest == nil {
			oldest = v
		} else if !v.na.Timestamp.After(oldest.na.Timestamp) {
			oldest = v
		}
	}

	if oldest != nil {
		key := NetAddressKey(oldest.na)
		log.Tracef("expiring oldest address %v", key)

		delete(a.addrNew[bucket], key)
		a.addrChanged = true
		oldest.refs--
		if oldest.refs == 0 {
			a.nNew--
			delete(a.addrIndex, key)
		}
	}
}

// getOldestAddressIndex returns the index of the oldest address in the tried
// bucket.  It is used when there is a need to evict an element from a tried
// bucket to make room for a newly tried address.
func (a *AddrManager) getOldestAddressIndex(bucket int) int {
	var oldest *KnownAddress
	var idx int

	for i, ka := range a.addrTried[bucket] {
		if i == 0 || oldest.na.Timestamp.After(ka.na.Timestamp) {
			oldest = ka
			idx = i
		}
	}
	return idx
}

// getNewBucket returns a psuedorandom new bucket index for the provided
// IPs using key as a seed.
// This is used to as a mitigation against eclipse attacks described in
// "Eclipse Attacks on Bitcoin’s Peer-to-Peer Network" by Heilman et al.
func getNewBucket(key [32]byte, netAddr, srcAddr *wire.NetAddress) int {
	data1 := []byte{}
	data1 = append(data1, key[:]...)
	data1 = append(data1, []byte(GroupKey(netAddr))...)
	data1 = append(data1, []byte(GroupKey(srcAddr))...)
	hash1 := chainhash.HashB(data1)
	hash64 := binary.LittleEndian.Uint64(hash1)
	hash64 %= newBucketsPerGroup
	var hashbuf [8]byte
	binary.LittleEndian.PutUint64(hashbuf[:], hash64)
	data2 := []byte{}
	data2 = append(data2, key[:]...)
	data2 = append(data2, GroupKey(srcAddr)...)
	data2 = append(data2, hashbuf[:]...)

	hash2 := chainhash.HashB(data2)
	return int(binary.LittleEndian.Uint64(hash2) % newBucketCount)
}

// getTriedBucket returns a psuedorandom tried bucket index for the provided
// network address using key as a seed.
func getTriedBucket(key [32]byte, netAddr *wire.NetAddress) int {
	data1 := []byte{}
	data1 = append(data1, key[:]...)
	data1 = append(data1, []byte(NetAddressKey(netAddr))...)
	hash1 := chainhash.HashB(data1)
	hash64 := binary.LittleEndian.Uint64(hash1)
	hash64 %= triedBucketsPerGroup
	var hashbuf [8]byte
	binary.LittleEndian.PutUint64(hashbuf[:], hash64)
	data2 := []byte{}
	data2 = append(data2, key[:]...)
	data2 = append(data2, GroupKey(netAddr)...)
	data2 = append(data2, hashbuf[:]...)

	hash2 := chainhash.HashB(data2)
	return int(binary.LittleEndian.Uint64(hash2) % triedBucketCount)
}

// addressHandler is the main handler for the address manager.  It must be run
// as a goroutine.
func (a *AddrManager) addressHandler() {
	dumpAddressTicker := time.NewTicker(dumpAddressInterval)
	defer dumpAddressTicker.Stop()
out:
	for {
		select {
		case <-dumpAddressTicker.C:
			a.savePeers()

		case <-a.quit:
			break out
		}
	}
	a.savePeers()
	a.wg.Done()
	log.Trace("Address handler done")
}

// savePeers saves all the known addresses to a file so they can be read back
// in at next run.
func (a *AddrManager) savePeers() {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if !a.addrChanged {
		// Nothing changed since last savePeers call.
		return
	}

	// First we make a serialisable data structure so we can encode it to JSON.
	sam := new(serializedAddrManager)
	sam.Version = serialisationVersion
	copy(sam.Key[:], a.key[:])

	sam.Addresses = make([]*serializedKnownAddress, len(a.addrIndex))
	i := 0
	for k, v := range a.addrIndex {
		ska := new(serializedKnownAddress)
		ska.Addr = k
		ska.TimeStamp = v.na.Timestamp.Unix()
		ska.Src = NetAddressKey(v.srcAddr)
		ska.Attempts = v.attempts
		ska.LastAttempt = v.lastattempt.Unix()
		ska.LastSuccess = v.lastsuccess.Unix()
		// Tried and refs are implicit in the rest of the structure
		// and will be worked out from context on unserialisation.
		sam.Addresses[i] = ska
		i++
	}
	for i := range a.addrNew {
		sam.NewBuckets[i] = make([]string, len(a.addrNew[i]))
		j := 0
		for k := range a.addrNew[i] {
			sam.NewBuckets[i][j] = k
			j++
		}
	}
	for i := range a.addrTried {
		sam.TriedBuckets[i] = make([]string, len(a.addrTried[i]))
		j := 0
		for _, ka := range a.addrTried[i] {
			sam.TriedBuckets[i][j] = NetAddressKey(ka.na)
			j++
		}
	}

	// Write temporary peers file and then move it into place.
	tmpfile := a.peersFile + ".new"
	w, err := os.Create(tmpfile)
	if err != nil {
		log.Errorf("Error opening file %s: %v", tmpfile, err)
		return
	}
	enc := json.NewEncoder(w)
	if err := enc.Encode(&sam); err != nil {
		log.Errorf("Failed to encode file %s: %v", tmpfile, err)
		return
	}
	if err := w.Close(); err != nil {
		log.Errorf("Error closing file %s: %v", tmpfile, err)
		return
	}
	if err := os.Rename(tmpfile, a.peersFile); err != nil {
		log.Errorf("Error writing file %s: %v", a.peersFile, err)
		return
	}
	a.addrChanged = false
}

// loadPeers loads the known address from the saved file.  If empty, missing, or
// malformed file, just don't load anything and start fresh.
func (a *AddrManager) loadPeers() {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	err := a.deserializePeers(a.peersFile)
	if err != nil {
		log.Errorf("Failed to parse file %s: %v", a.peersFile, err)
		// if it is invalid we nuke the old one unconditionally.
		err = os.Remove(a.peersFile)
		if err != nil {
			log.Warnf("Failed to remove corrupt peers file %s: %v",
				a.peersFile, err)
		}
		a.reset()
		return
	}
	log.Infof("Loaded %d addresses from file '%s'", a.numAddresses(), a.peersFile)
}

func (a *AddrManager) deserializePeers(filePath string) error {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return nil
	}
	r, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("%s error opening file: %v", filePath, err)
	}
	defer r.Close()

	var sam serializedAddrManager
	dec := json.NewDecoder(r)
	err = dec.Decode(&sam)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", filePath, err)
	}

	if sam.Version != serialisationVersion {
		return fmt.Errorf("unknown version %v in serialized "+
			"addrmanager", sam.Version)
	}
	copy(a.key[:], sam.Key[:])

	for _, v := range sam.Addresses {
		ka := new(KnownAddress)
		ka.na, err = a.DeserializeNetAddress(v.Addr)
		if err != nil {
			return fmt.Errorf("failed to deserialize netaddress "+
				"%s: %v", v.Addr, err)
		}
		ka.srcAddr, err = a.DeserializeNetAddress(v.Src)
		if err != nil {
			return fmt.Errorf("failed to deserialize netaddress "+
				"%s: %v", v.Src, err)
		}
		ka.attempts = v.Attempts
		ka.lastattempt = time.Unix(v.LastAttempt, 0)
		ka.lastsuccess = time.Unix(v.LastSuccess, 0)
		a.addrIndex[NetAddressKey(ka.na)] = ka
	}

	for i := range sam.NewBuckets {
		for _, val := range sam.NewBuckets[i] {
			ka, ok := a.addrIndex[val]
			if !ok {
				return fmt.Errorf("new buckets contains %s but "+
					"none in address list", val)
			}

			if ka.refs == 0 {
				a.nNew++
			}
			ka.refs++
			a.addrNew[i][val] = ka
		}
	}
	for i := range sam.TriedBuckets {
		for _, val := range sam.TriedBuckets[i] {
			ka, ok := a.addrIndex[val]
			if !ok {
				return fmt.Errorf("tried buckets contains %s but "+
					"none in address list", val)
			}

			ka.tried = true
			a.nTried++
			a.addrTried[i] = append(a.addrTried[i], ka)
		}
	}

	// Sanity checking.
	for k, v := range a.addrIndex {
		if v.refs == 0 && !v.tried {
			return fmt.Errorf("address %s after serialisation "+
				"with no references", k)
		}

		if v.refs > 0 && v.tried {
			return fmt.Errorf("address %s after serialisation "+
				"which is both new and tried", k)
		}
	}

	return nil
}

// DeserializeNetAddress converts a given address string to a *wire.NetAddress
func (a *AddrManager) DeserializeNetAddress(addr string) (*wire.NetAddress, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	return a.HostToNetAddress(host, uint16(port), wire.SFNodeNetwork)
}

// Start begins the core address handler which manages a pool of known
// addresses, timeouts, and interval based writes.  If the address manager is
// starting or has already been started, invoking this method has no
// effect.
//
// This function is safe for concurrent access.
func (a *AddrManager) Start() {
	// Return early if the address manager has already been started.
	if atomic.AddInt32(&a.started, 1) != 1 {
		return
	}

	log.Trace("Starting address manager")

	// Load peers we already know about from file.
	a.loadPeers()

	// Start the address ticker to save addresses periodically.
	a.wg.Add(1)
	go a.addressHandler()
}

// Stop gracefully shuts down the address manager by stopping the main handler.
func (a *AddrManager) Stop() error {
	// Return early if the address manager has already been stopped.
	if atomic.AddInt32(&a.shutdown, 1) != 1 {
		log.Warnf("Address manager is already in the process of shutting down")
		return nil
	}

	log.Infof("Address manager shutting down")
	close(a.quit)
	a.wg.Wait()
	return nil
}

// AddAddresses adds new addresses to the address manager.  It enforces a max
// number of addresses and silently ignores duplicate addresses.
//
// This function is safe for concurrent access.
func (a *AddrManager) AddAddresses(addrs []*wire.NetAddress, srcAddr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	for _, na := range addrs {
		a.updateAddress(na, srcAddr)
	}
}

// AddAddress adds a new address to the address manager.  It enforces a max
// number of addresses and silently ignores duplicate addresses.
//
// This function is safe for concurrent access.
func (a *AddrManager) AddAddress(addr, srcAddr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	a.updateAddress(addr, srcAddr)
}

// numAddresses returns the number of addresses known to the address manager.
//
// This function MUST be called with the address manager lock held (for reads).
func (a *AddrManager) numAddresses() int {
	return a.nTried + a.nNew
}

// NeedMoreAddresses returns whether or not the address manager needs more
// addresses.
//
// This function is safe for concurrent access.
func (a *AddrManager) NeedMoreAddresses() bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return a.numAddresses() < needAddressThreshold
}

// AddressCache returns a randomized subset of all addresses known to the
// address manager.
//
// This function is safe for concurrent access.
func (a *AddrManager) AddressCache() []*wire.NetAddress {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	// Determine length of all addresses in index.
	addrLen := len(a.addrIndex)
	if addrLen == 0 {
		return nil
	}

	allAddr := make([]*wire.NetAddress, 0, addrLen)
	// Iteration order is undefined here, but we randomize it anyway.
	for _, v := range a.addrIndex {
		// Skip low quality addresses.
		if v.isBad() {
			continue
		}
		// Skip addresses that never succeeded.
		if v.lastsuccess.IsZero() {
			continue
		}
		allAddr = append(allAddr, v.na)
	}

	// Adjust length, we only deal with high quality addresses now.
	addrLen = len(allAddr)

	numAddresses := addrLen * getAddrPercent / 100
	if numAddresses > getAddrMax {
		numAddresses = getAddrMax
	}

	// Fisher-Yates shuffle the array. We only need to do the first
	// numAddresses since we are throwing away the rest.
	for i := 0; i < numAddresses; i++ {
		// Pick a number between current index and the end.
		j := a.rand.Intn(addrLen-i) + i
		allAddr[i], allAddr[j] = allAddr[j], allAddr[i]
	}

	// Slice off the limit we are willing to share.
	return allAddr[0:numAddresses]
}

// reset resets the address manager by reinitialising the random source
// and allocating fresh empty bucket storage.
func (a *AddrManager) reset() {
	a.addrIndex = make(map[string]*KnownAddress)

	// fill key with bytes from a good random source.
	io.ReadFull(crand.Reader, a.key[:])
	for i := range a.addrNew {
		a.addrNew[i] = make(map[string]*KnownAddress)
	}
	for i := range a.addrTried {
		a.addrTried[i] = nil
	}
	a.addrChanged = true
	a.getNewBucket = func(netAddr, srcAddr *wire.NetAddress) int {
		return getNewBucket(a.key, netAddr, srcAddr)
	}
	a.getTriedBucket = func(netAddr *wire.NetAddress) int {
		return getTriedBucket(a.key, netAddr)
	}
}

// HostToNetAddress parses and returns an address manager network address given
// a hostname in a supported format (IPv4, IPv6, TORv2).  If the hostname
// cannot be immediately converted from a known address format, it will be
// resolved using the lookup function provided to the address manager. If it
// cannot be resolved, an error is returned.
//
// This function is safe for concurrent access.
func (a *AddrManager) HostToNetAddress(host string, port uint16, services wire.ServiceFlag) (*wire.NetAddress, error) {
	// Tor address is 16 char base32 + ".onion"
	var ip net.IP
	if len(host) == 22 && host[16:] == ".onion" {
		// go base32 encoding uses capitals (as does the rfc
		// but Tor and bitcoind tend to user lowercase, so we switch
		// case here.
		data, err := base32.StdEncoding.DecodeString(
			strings.ToUpper(host[:16]))
		if err != nil {
			return nil, err
		}
		prefix := []byte{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43}
		ip = net.IP(append(prefix, data...))
	} else if ip = net.ParseIP(host); ip == nil {
		ips, err := a.lookupFunc(host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses found for %s", host)
		}
		ip = ips[0]
	}

	return wire.NewNetAddressIPPort(ip, port, services), nil
}

// ipString returns a string for the ip from the provided NetAddress. If the
// ip is in the range used for TORv2 addresses then it will be transformed into
// the respective .onion address.
func ipString(na *wire.NetAddress) string {
	if isOnionCatTor(na) {
		// We know now that na.IP is long enough.
		base32 := base32.StdEncoding.EncodeToString(na.IP[6:])
		return strings.ToLower(base32) + ".onion"
	}

	return na.IP.String()
}

// NetAddressKey returns a string key in the form of ip:port for IPv4 addresses
// or [ip]:port for IPv6 addresses.
func NetAddressKey(na *wire.NetAddress) string {
	port := strconv.FormatUint(uint64(na.Port), 10)

	return net.JoinHostPort(ipString(na), port)
}

// GetAddress returns a single address that should be routable.  It picks a
// random one from the possible addresses with preference given to ones that
// have not been used recently and should not pick 'close' addresses
// consecutively.
//
// This function is safe for concurrent access.
func (a *AddrManager) GetAddress() *KnownAddress {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if a.numAddresses() == 0 {
		return nil
	}

	// Use a 50% chance for choosing between tried and new table entries.
	large := 1 << 30
	factor := 1.0
	if a.nTried > 0 && (a.nNew == 0 || a.rand.Intn(2) == 0) {
		// Tried entry.
		for {
			// Pick a random bucket.
			bucket := a.rand.Intn(len(a.addrTried))
			if len(a.addrTried[bucket]) == 0 {
				continue
			}

			// Then, a random entry in the list.
			randEntry := a.rand.Intn(len(a.addrTried[bucket]))
			ka := a.addrTried[bucket][randEntry]

			randval := a.rand.Intn(large)
			if float64(randval) < (factor * ka.chance() * float64(large)) {
				log.Tracef("Selected %v from tried bucket",
					NetAddressKey(ka.na))
				return ka
			}
			factor *= 1.2
		}
	} else {
		// New node.
		for {
			// Pick a random bucket.
			bucket := a.rand.Intn(len(a.addrNew))
			if len(a.addrNew[bucket]) == 0 {
				continue
			}

			// Then, a random entry in it.
			var ka *KnownAddress
			nth := a.rand.Intn(len(a.addrNew[bucket]))
			for _, value := range a.addrNew[bucket] {
				if nth == 0 {
					ka = value
				}
				nth--
			}
			randval := a.rand.Intn(large)
			if float64(randval) < (factor * ka.chance() * float64(large)) {
				log.Tracef("Selected %v from new bucket",
					NetAddressKey(ka.na))
				return ka
			}
			factor *= 1.2
		}
	}
}

func (a *AddrManager) find(addr *wire.NetAddress) *KnownAddress {
	return a.addrIndex[NetAddressKey(addr)]
}

// Attempt increases the given address' attempt counter and updates
// the last attempt time, if it is known to the address manager. If the address
// is not known to the address manager an error is returned.
//
// This function is safe for concurrent access.
func (a *AddrManager) Attempt(addr *wire.NetAddress) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	// find address.
	// Surely address will be in tried by now?
	ka := a.find(addr)
	if ka == nil {
		str := fmt.Sprintf("address %s not found", ipString(addr))
		return makeError(ErrAddressNotFound, str)
	}

	// set last tried time to now
	ka.mtx.Lock()
	ka.attempts++
	ka.lastattempt = time.Now()
	ka.mtx.Unlock()
	return nil
}

// Connected Marks the given address as currently connected and working at the
// current time.  If the address is not known to the address manager an error
// is returned.
//
// This function is safe for concurrent access.
func (a *AddrManager) Connected(addr *wire.NetAddress) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	ka := a.find(addr)
	if ka == nil {
		str := fmt.Sprintf("address %s not found", ipString(addr))
		return makeError(ErrAddressNotFound, str)
	}

	// Update the time as long as it has been 20 minutes since last we did
	// so.
	now := time.Now()
	if now.After(ka.na.Timestamp.Add(time.Minute * 20)) {
		// ka.na is immutable, so replace it.
		ka.mtx.Lock()
		naCopy := *ka.na
		naCopy.Timestamp = time.Now()
		ka.na = &naCopy
		ka.mtx.Unlock()
	}
	return nil
}

// Good marks the given address as good.  This should be called after a
// successful outbound connection to and version exchange with a peer.  If the
// address is not known to the address manager an error is returned.
//
// This function is safe for concurrent access.
func (a *AddrManager) Good(addr *wire.NetAddress) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	ka := a.find(addr)
	if ka == nil {
		str := fmt.Sprintf("address %s not found", ipString(addr))
		return makeError(ErrAddressNotFound, str)
	}

	// ka.Timestamp is not updated here to avoid leaking information
	// about currently connected peers.
	now := time.Now()
	ka.lastsuccess = now
	ka.lastattempt = now
	ka.attempts = 0

	// If the address is already tried then return since it's already good.
	// Otherwise, move it to a tried bucket. If the target tried bucket is full,
	// then room will be made by evicting the oldest address in that bucket and
	// moving it to a new bucket. If the psuedorandomly selected new bucket is
	// full, then swap the addresses' positions between tried and new.
	if ka.tried {
		return nil
	}

	// remove from all new buckets.
	// record one of the buckets in question and call it the `first'
	addrKey := NetAddressKey(addr)
	addrNewAvailableIndex := -1
	for i := range a.addrNew {
		// we check for existence so we can record the first one
		if _, ok := a.addrNew[i][addrKey]; ok {
			delete(a.addrNew[i], addrKey)
			a.addrChanged = true
			ka.refs--
			if addrNewAvailableIndex == -1 {
				addrNewAvailableIndex = i
			}
		}
	}
	a.nNew--

	if addrNewAvailableIndex == -1 {
		str := fmt.Sprintf("%s is not marked as a new address", ipString(addr))
		return makeError(ErrAddressNotFound, str)
	}

	bucket := a.getTriedBucket(ka.na)

	// If this tried bucket has enough capacity for another address,
	// add the address to the bucket and flag it as tried.
	if len(a.addrTried[bucket]) < a.triedBucketSize {
		ka.tried = true
		a.addrTried[bucket] = append(a.addrTried[bucket], ka)
		a.addrChanged = true
		a.nTried++
		return nil
	}

	// Since the tried bucket is at capacity, evict the oldest address
	// in the tried bucket and move it to a new bucket.
	oldestTriedIndex := a.getOldestAddressIndex(bucket)
	rmka := a.addrTried[bucket][oldestTriedIndex]

	// First bucket it would have been put in.
	newBucket := a.getNewBucket(rmka.na, rmka.srcAddr)

	// If there is no room in the psuedorandomly selected new bucket,
	// then reuse the new bucket that the newly tried address was removed from.
	if len(a.addrNew[newBucket]) >= newBucketSize {
		newBucket = addrNewAvailableIndex
	}

	// Replace oldest tried address in bucket with ka.
	ka.tried = true
	a.addrTried[bucket][oldestTriedIndex] = ka

	rmka.tried = false
	rmka.refs++

	// The total number of tried addresses a.nTried is not modified here since
	// the number of tried addresses stays the same.  However, since the total
	// number of new addresses a.nNew was decremented above, increment it now
	// since an address is being evicted from a tried bucket to a new bucket.
	a.nNew++

	rmkey := NetAddressKey(rmka.na)
	log.Tracef("Replacing %s with %s in tried", rmkey, addrKey)

	// We made sure there is space here just above.
	a.addrNew[newBucket][rmkey] = rmka
	return nil
}

// SetServices sets the services for the given address to the provided value.
// If the address is not known to the address manager an error is returned.
func (a *AddrManager) SetServices(addr *wire.NetAddress, services wire.ServiceFlag) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	ka := a.find(addr)
	if ka == nil {
		str := fmt.Sprintf("address %s not found", ipString(addr))
		return makeError(ErrAddressNotFound, str)
	}

	// Update the services if needed.
	if ka.na.Services != services {
		// ka.na is immutable, so replace it.
		ka.mtx.Lock()
		naCopy := *ka.na
		naCopy.Services = services
		ka.na = &naCopy
		ka.mtx.Unlock()
	}
	return nil
}

// AddLocalAddress adds na to the list of known local addresses to advertise
// with the given priority.
//
// This function is safe for concurrent access.
func (a *AddrManager) AddLocalAddress(na *wire.NetAddress, priority AddressPriority) error {
	if !IsRoutable(na) {
		return fmt.Errorf("address %s is not routable", ipString(na))
	}

	a.lamtx.Lock()
	defer a.lamtx.Unlock()

	key := NetAddressKey(na)
	la, ok := a.localAddresses[key]
	if !ok || la.score < priority {
		if ok {
			la.score = priority + 1
		} else {
			a.localAddresses[key] = &localAddress{
				na:    na,
				score: priority,
			}
		}
	}
	return nil
}

// HasLocalAddress asserts if the manager has the provided local address.
//
// This function is safe for concurrent access.
func (a *AddrManager) HasLocalAddress(na *wire.NetAddress) bool {
	key := NetAddressKey(na)
	a.lamtx.Lock()
	_, ok := a.localAddresses[key]
	a.lamtx.Unlock()
	return ok
}

// LocalAddresses returns a summary of local addresses information for
// the getnetworkinfo rpc.
//
// This function is safe for concurrent access.
func (a *AddrManager) LocalAddresses() []LocalAddr {
	a.lamtx.Lock()
	defer a.lamtx.Unlock()

	addrs := make([]LocalAddr, 0, len(a.localAddresses))
	for _, addr := range a.localAddresses {
		la := LocalAddr{
			Address: addr.na.IP.String(),
			Port:    addr.na.Port,
		}

		addrs = append(addrs, la)
	}

	return addrs
}

const (
	// Unreachable represents a publicly unreachable connection state
	// between two addresses.
	Unreachable = 0

	// Default represents the default connection state between
	// two addresses.
	Default = iota

	// Teredo represents a connection state between two RFC4380 addresses.
	Teredo

	// Ipv6Weak represents a weak IPV6 connection state between two
	// addresses.
	Ipv6Weak

	// Ipv4 represents an IPV4 connection state between two addresses.
	Ipv4

	// Ipv6Strong represents a connection state between two IPV6 addresses.
	Ipv6Strong

	// Private represents a connection state connect between two Tor addresses.
	Private
)

// getReachabilityFrom returns the relative reachability of the provided local
// address to the provided remote address.
//
// This function is safe for concurrent access.
func getReachabilityFrom(localAddr, remoteAddr *wire.NetAddress) int {
	if !IsRoutable(remoteAddr) {
		return Unreachable
	}

	if isOnionCatTor(remoteAddr) {
		if isOnionCatTor(localAddr) {
			return Private
		}

		if IsRoutable(localAddr) && isIPv4(localAddr) {
			return Ipv4
		}

		return Default
	}

	if isRFC4380(remoteAddr) {
		if !IsRoutable(localAddr) {
			return Default
		}

		if isRFC4380(localAddr) {
			return Teredo
		}

		if isIPv4(localAddr) {
			return Ipv4
		}

		return Ipv6Weak
	}

	if isIPv4(remoteAddr) {
		if IsRoutable(localAddr) && isIPv4(localAddr) {
			return Ipv4
		}
		return Unreachable
	}

	/* ipv6 */
	var tunnelled bool
	// Is our v6 tunnelled?
	if isRFC3964(localAddr) || isRFC6052(localAddr) || isRFC6145(localAddr) {
		tunnelled = true
	}

	if !IsRoutable(localAddr) {
		return Default
	}

	if isRFC4380(localAddr) {
		return Teredo
	}

	if isIPv4(localAddr) {
		return Ipv4
	}

	if tunnelled {
		// only prioritise ipv6 if we aren't tunnelling it.
		return Ipv6Weak
	}

	return Ipv6Strong
}

// GetBestLocalAddress returns the most appropriate local address to use
// for the given remote address.
//
// This function is safe for concurrent access.
func (a *AddrManager) GetBestLocalAddress(remoteAddr *wire.NetAddress) *wire.NetAddress {
	a.lamtx.Lock()
	defer a.lamtx.Unlock()

	bestreach := 0
	var bestscore AddressPriority
	var bestAddress *wire.NetAddress
	for _, la := range a.localAddresses {
		reach := getReachabilityFrom(la.na, remoteAddr)
		if reach > bestreach ||
			(reach == bestreach && la.score > bestscore) {
			bestreach = reach
			bestscore = la.score
			bestAddress = la.na
		}
	}
	if bestAddress != nil {
		log.Debugf("Suggesting address %s:%d for %s:%d", bestAddress.IP,
			bestAddress.Port, remoteAddr.IP, remoteAddr.Port)
	} else {
		log.Debugf("No worthy address for %s:%d", remoteAddr.IP,
			remoteAddr.Port)

		// Send something unroutable if nothing suitable.
		var ip net.IP
		if !isIPv4(remoteAddr) && !isOnionCatTor(remoteAddr) {
			ip = net.IPv6zero
		} else {
			ip = net.IPv4zero
		}
		bestAddress = wire.NewNetAddressIPPort(ip, 0, wire.SFNodeNetwork)
	}

	return bestAddress
}

// ValidatePeerNa returns the validity and reachability of the
// provided local address based on its routablility and reachability
// from the peer that suggested it.
//
// This function is safe for concurrent access.
func (a *AddrManager) ValidatePeerNa(localAddr, remoteAddr *wire.NetAddress) (bool, int) {
	net := getNetwork(localAddr)
	reach := getReachabilityFrom(localAddr, remoteAddr)
	valid := (net == IPv4Address && reach == Ipv4) || (net == IPv6Address &&
		(reach == Ipv6Weak || reach == Ipv6Strong || reach == Teredo))
	return valid, reach
}

// New constructs a new address manager instance.
// Use Start to begin processing asynchronous address updates.
// The address manager uses lookupFunc for necessary DNS lookups.
func New(dataDir string, lookupFunc func(string) ([]net.IP, error)) *AddrManager {
	am := AddrManager{
		peersFile:       filepath.Join(dataDir, peersFilename),
		lookupFunc:      lookupFunc,
		rand:            rand.New(rand.NewSource(time.Now().UnixNano())),
		quit:            make(chan struct{}),
		localAddresses:  make(map[string]*localAddress),
		triedBucketSize: defaultTriedBucketSize,
	}
	am.reset()
	return &am
}
