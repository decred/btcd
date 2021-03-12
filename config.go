// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/connmgr/v3"
	"github.com/decred/dcrd/database/v2"
	_ "github.com/decred/dcrd/database/v2/ffldb"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/internal/mempool"
	"github.com/decred/dcrd/internal/version"
	"github.com/decred/dcrd/rpc/jsonrpc/types/v3"
	"github.com/decred/dcrd/sampleconfig"
	"github.com/decred/go-socks/socks"
	"github.com/decred/slog"
	flags "github.com/jessevdk/go-flags"
)

const (
	// Defaults for general application behavior options.
	defaultConfigFilename   = "dcrd.conf"
	defaultDataDirname      = "data"
	defaultLogDirname       = "logs"
	defaultLogFilename      = "dcrd.log"
	defaultDbType           = "ffldb"
	defaultLogLevel         = "info"
	defaultSigCacheMaxSize  = 100000
	defaultUtxoCacheMaxSize = 150
	minUtxoCacheMaxSize     = 25
	maxUtxoCacheMaxSize     = 32768 // 32 GiB

	// Defaults for RPC server options and policy.
	defaultTLSCurve             = "P-256"
	defaultMaxRPCClients        = 10
	defaultMaxRPCWebsockets     = 25
	defaultMaxRPCConcurrentReqs = 20

	// Defaults for P2P network options.
	defaultMaxSameIP       = 5
	defaultMaxPeers        = 125
	defaultDialTimeout     = time.Second * 30
	defaultPeerIdleTimeout = time.Second * 120

	// Defaults for banning options.
	defaultBanDuration  = time.Hour * 24
	defaultBanThreshold = 100

	// Defaults for relay and mempool policy options.
	defaultFreeTxRelayLimit      = 15.0
	defaultMaxOrphanTransactions = 100
	defaultAllowOldVotes         = false

	// Defaults for mining options and policy.
	defaultGenerate            = false
	defaultBlockMinSize        = 0
	defaultBlockMaxSize        = 375000
	blockMaxSizeMin            = 1000
	defaultNoMiningStateSync   = false
	defaultAllowUnsyncedMining = false

	// Defaults for indexing options.
	defaultTxIndex           = false
	defaultAddrIndex         = false
	defaultNoExistsAddrIndex = false

	// Authorization types.
	authTypeBasic      = "basic"
	authTypeClientCert = "clientcert"
)

var (
	// Constructed defaults for general application behavior options.
	defaultHomeDir    = dcrutil.AppDataDir("dcrd", false)
	defaultConfigFile = filepath.Join(defaultHomeDir, defaultConfigFilename)
	defaultDataDir    = filepath.Join(defaultHomeDir, defaultDataDirname)
	defaultLogDir     = filepath.Join(defaultHomeDir, defaultLogDirname)
	knownDbTypes      = database.SupportedDrivers()

	// Constructed defaults for RPC server options and policy.
	defaultRPCKeyFile   = filepath.Join(defaultHomeDir, "rpc.key")
	defaultRPCCertFile  = filepath.Join(defaultHomeDir, "rpc.cert")
	defaultRPCAuthType  = authTypeBasic
	defaultRPCClientCAs = filepath.Join(defaultHomeDir, "clients.pem")
)

// runServiceCommand is only set to a real function on Windows.  It is used
// to parse and execute service commands specified via the -s flag.
var runServiceCommand func(string) error

// minUint32 is a helper function to return the minimum of two uint32s.
// This avoids a math import and the need to cast to floats.
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// config defines the configuration options for dcrd.
//
// See loadConfig for details on the configuration load process.
type config struct {
	// General application behavior.
	ShowVersion      bool   `short:"V" long:"version" description:"Display version information and exit"`
	HomeDir          string `short:"A" long:"appdata" description:"Path to application home directory"`
	ConfigFile       string `short:"C" long:"configfile" description:"Path to configuration file"`
	DataDir          string `short:"b" long:"datadir" description:"Directory to store data"`
	LogDir           string `long:"logdir" description:"Directory to log output"`
	NoFileLogging    bool   `long:"nofilelogging" description:"Disable file logging"`
	DbType           string `long:"dbtype" description:"Database backend to use for the block chain"`
	Profile          string `long:"profile" description:"Enable HTTP profiling on given [addr:]port -- NOTE port must be between 1024 and 65536"`
	CPUProfile       string `long:"cpuprofile" description:"Write CPU profile to the specified file"`
	MemProfile       string `long:"memprofile" description:"Write mem profile to the specified file"`
	TestNet          bool   `long:"testnet" description:"Use the test network"`
	SimNet           bool   `long:"simnet" description:"Use the simulation test network"`
	RegNet           bool   `long:"regnet" description:"Use the regression test network"`
	DebugLevel       string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`
	SigCacheMaxSize  uint   `long:"sigcachemaxsize" description:"The maximum number of entries in the signature verification cache"`
	UtxoCacheMaxSize uint   `long:"utxocachemaxsize" description:"The maximum size in MiB of the utxo cache"`

	// RPC server options and policy.
	DisableRPC           bool     `long:"norpc" description:"Disable built-in RPC server -- NOTE: The RPC server is disabled by default if no rpcuser/rpcpass or rpclimituser/rpclimitpass is specified"`
	RPCListeners         []string `long:"rpclisten" description:"Add an interface/port to listen for RPC connections (default port: 9109, testnet: 19109)"`
	RPCUser              string   `short:"u" long:"rpcuser" description:"Username for RPC connections"`
	RPCPass              string   `short:"P" long:"rpcpass" default-mask:"-" description:"Password for RPC connections"`
	RPCAuthType          string   `long:"authtype" description:"Method for RPC client authentication (basic or clientcert)"`
	RPCClientCAs         string   `long:"clientcafile" description:"File containing Certificate Authorities to verify TLS client certificates; requires authtype=clientcert"`
	RPCLimitUser         string   `long:"rpclimituser" description:"Username for limited RPC connections"`
	RPCLimitPass         string   `long:"rpclimitpass" default-mask:"-" description:"Password for limited RPC connections"`
	RPCCert              string   `long:"rpccert" description:"File containing the certificate file"`
	RPCKey               string   `long:"rpckey" description:"File containing the certificate key"`
	TLSCurve             string   `long:"tlscurve" description:"Curve to use when generating TLS keypairs"`
	AltDNSNames          []string `long:"altdnsnames" description:"Specify additional DNS names to use when generating the RPC server certificate" env:"DCRD_ALT_DNSNAMES" env-delim:","`
	DisableTLS           bool     `long:"notls" description:"Disable TLS for the RPC server -- NOTE: This is only allowed if the RPC server is bound to localhost"`
	RPCMaxClients        int      `long:"rpcmaxclients" description:"Max number of RPC clients for standard connections"`
	RPCMaxWebsockets     int      `long:"rpcmaxwebsockets" description:"Max number of RPC websocket connections"`
	RPCMaxConcurrentReqs int      `long:"rpcmaxconcurrentreqs" description:"Max number of concurrent RPC requests that may be processed concurrently"`

	// P2P proxy and Tor settings.
	Proxy          string `long:"proxy" description:"Connect via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	ProxyUser      string `long:"proxyuser" description:"Username for proxy server"`
	ProxyPass      string `long:"proxypass" default-mask:"-" description:"Password for proxy server"`
	OnionProxy     string `long:"onion" description:"Connect to tor hidden services via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	OnionProxyUser string `long:"onionuser" description:"Username for onion proxy server"`
	OnionProxyPass string `long:"onionpass" default-mask:"-" description:"Password for onion proxy server"`
	NoOnion        bool   `long:"noonion" description:"Disable connecting to tor hidden services"`
	TorIsolation   bool   `long:"torisolation" description:"Enable Tor stream isolation by randomizing user credentials for each connection"`

	// P2P network options.
	AddPeers        []string      `short:"a" long:"addpeer" description:"Add a peer to connect with at startup"`
	ConnectPeers    []string      `long:"connect" description:"Connect only to the specified peers at startup"`
	DisableListen   bool          `long:"nolisten" description:"Disable listening for incoming connections -- NOTE: Listening is automatically disabled if the --connect or --proxy options are used without also specifying listen interfaces via --listen"`
	Listeners       []string      `long:"listen" description:"Add an interface/port to listen for connections (default all interfaces port: 9108, testnet: 19108)"`
	MaxSameIP       int           `long:"maxsameip" description:"Max number of connections with the same IP -- 0 to disable"`
	MaxPeers        int           `long:"maxpeers" description:"Max number of inbound and outbound peers"`
	DialTimeout     time.Duration `long:"dialtimeout" description:"How long to wait for TCP connection completion.  Valid time units are {s, m, h}.  Minimum 1 second"`
	PeerIdleTimeout time.Duration `long:"peeridletimeout" description:"The duration of inactivity before a peer is timed out. Valid time units are {s,m,h}. Minimum 15 seconds"`

	// P2P network discovery options.
	DisableSeeders bool     `long:"noseeders" description:"Disable seeding for peer discovery"`
	DisableDNSSeed bool     `long:"nodnsseed" description:"DEPRECATED: use --noseeders"`
	ExternalIPs    []string `long:"externalip" description:"Add an ip to the list of local addresses we claim to listen on to peers"`
	NoDiscoverIP   bool     `long:"nodiscoverip" description:"Disable automatic network address discovery of local external IPs"`
	Upnp           bool     `long:"upnp" description:"Use UPnP to map our listening port outside of NAT"`

	// Banning options.
	DisableBanning bool          `long:"nobanning" description:"Disable banning of misbehaving peers"`
	BanDuration    time.Duration `long:"banduration" description:"How long to ban misbehaving peers.  Valid time units are {s, m, h}.  Minimum 1 second"`
	BanThreshold   uint32        `long:"banthreshold" description:"Maximum allowed ban score before disconnecting and banning misbehaving peers"`
	Whitelists     []string      `long:"whitelist" description:"Add an IP network or IP that will not be banned. (eg. 192.168.1.0/24 or ::1)"`

	// Chain related options.
	DisableCheckpoints bool   `long:"nocheckpoints" description:"Disable built-in checkpoints.  Don't do this unless you know what you're doing"`
	DumpBlockchain     string `long:"dumpblockchain" description:"Write blockchain as a flat file of blocks for use with addblock, to the specified filename"`

	// Relay and mempool policy.
	MinRelayTxFee    float64 `long:"minrelaytxfee" description:"The minimum transaction fee in DCR/kB to be considered a non-zero fee"`
	FreeTxRelayLimit float64 `long:"limitfreerelay" description:"Limit relay of transactions with no transaction fee to the given amount in thousands of bytes per minute"`
	NoRelayPriority  bool    `long:"norelaypriority" description:"Do not require free or low-fee transactions to have high priority for relaying"`
	MaxOrphanTxs     int     `long:"maxorphantx" description:"Max number of orphan transactions to keep in memory"`
	BlocksOnly       bool    `long:"blocksonly" description:"Do not accept transactions from remote peers"`
	AcceptNonStd     bool    `long:"acceptnonstd" description:"Accept and relay non-standard transactions to the network regardless of the default settings for the active network"`
	RejectNonStd     bool    `long:"rejectnonstd" description:"Reject non-standard transactions regardless of the default settings for the active network"`
	AllowOldVotes    bool    `long:"allowoldvotes" description:"Enable the addition of very old votes to the mempool"`

	// Mining options and policy.
	Generate            bool     `long:"generate" description:"Generate (mine) coins using the CPU"`
	MiningAddrs         []string `long:"miningaddr" description:"Add the specified payment address to the list of addresses to use for generated blocks -- At least one address is required if the generate option is set"`
	BlockMinSize        uint32   `long:"blockminsize" description:"Minimum block size in bytes to be used when creating a block"`
	BlockMaxSize        uint32   `long:"blockmaxsize" description:"Maximum block size in bytes to be used when creating a block"`
	BlockPrioritySize   uint32   `long:"blockprioritysize" description:"Size in bytes for high-priority/low-fee transactions when creating a block"`
	MiningTimeOffset    int      `long:"miningtimeoffset" description:"Offset the mining timestamp of a block by this many seconds (positive values are in the past)"`
	NonAggressive       bool     `long:"nonaggressive" description:"Disable mining off of the parent block of the blockchain if there aren't enough voters"`
	NoMiningStateSync   bool     `long:"nominingstatesync" description:"Disable synchronizing the mining state with other nodes"`
	AllowUnsyncedMining bool     `long:"allowunsyncedmining" description:"Allow block templates to be generated even when the chain is not considered synced on networks other than the main network.  This is automatically enabled when the simnet option is set.  Don't do this unless you know what you're doing"`

	// Indexing options.
	TxIndex             bool `long:"txindex" description:"Maintain a full hash-based transaction index which makes all transactions available via the getrawtransaction RPC"`
	DropTxIndex         bool `long:"droptxindex" description:"Deletes the hash-based transaction index from the database on start up and then exits"`
	AddrIndex           bool `long:"addrindex" description:"Maintain a full address-based transaction index which makes the searchrawtransactions RPC available"`
	DropAddrIndex       bool `long:"dropaddrindex" description:"Deletes the address-based transaction index from the database on start up and then exits"`
	NoExistsAddrIndex   bool `long:"noexistsaddrindex" description:"Disable the exists address index, which tracks whether or not an address has even been used"`
	DropExistsAddrIndex bool `long:"dropexistsaddrindex" description:"Deletes the exists address index from the database on start up and then exits"`

	// IPC options.
	PipeRx         uint `long:"piperx" description:"File descriptor of read end pipe to enable parent -> child process communication"`
	PipeTx         uint `long:"pipetx" description:"File descriptor of write end pipe to enable parent <- child process communication"`
	LifetimeEvents bool `long:"lifetimeevents" description:"Send lifetime notifications over the TX pipe"`

	// Cooked options ready for use.
	onionlookup   func(string) ([]net.IP, error)
	lookup        func(string) ([]net.IP, error)
	oniondial     func(context.Context, string, string) (net.Conn, error)
	dial          func(context.Context, string, string) (net.Conn, error)
	miningAddrs   []dcrutil.Address
	minRelayTxFee dcrutil.Amount
	whitelists    []*net.IPNet
	ipv4NetInfo   types.NetworksResult
	ipv6NetInfo   types.NetworksResult
	onionNetInfo  types.NetworksResult
	params        *params
}

// serviceOptions defines the configuration options for the daemon as a service on
// Windows.
type serviceOptions struct {
	ServiceCommand string `short:"s" long:"service" description:"Service command {install, remove, start, stop}"`
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Nothing to do when no path is given.
	if path == "" {
		return path
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows cmd.exe-style
	// %VARIABLE%, but the variables can still be expanded via POSIX-style
	// $VARIABLE.
	path = os.ExpandEnv(path)

	if !strings.HasPrefix(path, "~") {
		return filepath.Clean(path)
	}

	// Expand initial ~ to the current user's home directory, or ~otheruser
	// to otheruser's home directory.  On Windows, both forward and backward
	// slashes can be used.
	path = path[1:]

	var pathSeparators string
	if runtime.GOOS == "windows" {
		pathSeparators = string(os.PathSeparator) + "/"
	} else {
		pathSeparators = string(os.PathSeparator)
	}

	userName := ""
	if i := strings.IndexAny(path, pathSeparators); i != -1 {
		userName = path[:i]
		path = path[i:]
	}

	homeDir := ""
	var u *user.User
	var err error
	if userName == "" {
		u, err = user.Current()
	} else {
		u, err = user.Lookup(userName)
	}
	if err == nil {
		homeDir = u.HomeDir
	}
	// Fallback to CWD if user lookup fails or user has no home directory.
	if homeDir == "" {
		homeDir = "."
	}

	return filepath.Join(homeDir, path)
}

// validLogLevel returns whether or not logLevel is a valid debug log level.
func validLogLevel(logLevel string) bool {
	_, ok := slog.LevelFromString(logLevel)
	return ok
}

// supportedSubsystems returns a sorted slice of the supported subsystems for
// logging purposes.
func supportedSubsystems() []string {
	// Convert the subsystemLoggers map keys to a slice.
	subsystems := make([]string, 0, len(subsystemLoggers))
	for subsysID := range subsystemLoggers {
		subsystems = append(subsystems, subsysID)
	}

	// Sort the subsystems for stable display.
	sort.Strings(subsystems)
	return subsystems
}

// parseAndSetDebugLevels attempts to parse the specified debug level and set
// the levels accordingly.  An appropriate error is returned if anything is
// invalid.
func parseAndSetDebugLevels(debugLevel string) error {
	// When the specified string doesn't have any delimiters, treat it as
	// the log level for all subsystems.
	if !strings.Contains(debugLevel, ",") && !strings.Contains(debugLevel, "=") {
		// Validate debug log level.
		if !validLogLevel(debugLevel) {
			str := "the specified debug level [%v] is invalid"
			return fmt.Errorf(str, debugLevel)
		}

		// Change the logging level for all subsystems.
		setLogLevels(debugLevel)

		return nil
	}

	// Split the specified string into subsystem/level pairs while detecting
	// issues and update the log levels accordingly.
	for _, logLevelPair := range strings.Split(debugLevel, ",") {
		if !strings.Contains(logLevelPair, "=") {
			str := "the specified debug level contains an invalid " +
				"subsystem/level pair [%v]"
			return fmt.Errorf(str, logLevelPair)
		}

		// Extract the specified subsystem and log level.
		fields := strings.Split(logLevelPair, "=")
		subsysID, logLevel := fields[0], fields[1]

		// Validate subsystem.
		if _, exists := subsystemLoggers[subsysID]; !exists {
			str := "the specified subsystem [%v] is invalid -- " +
				"supported subsystems %v"
			return fmt.Errorf(str, subsysID, supportedSubsystems())
		}

		// Validate log level.
		if !validLogLevel(logLevel) {
			str := "the specified debug level [%v] is invalid"
			return fmt.Errorf(str, logLevel)
		}

		setLogLevel(subsysID, logLevel)
	}

	return nil
}

// validDbType returns whether or not dbType is a supported database type.
func validDbType(dbType string) bool {
	for _, knownType := range knownDbTypes {
		if dbType == knownType {
			return true
		}
	}

	return false
}

// removeDuplicateAddresses returns a new slice with all duplicate entries in
// addrs removed.
func removeDuplicateAddresses(addrs []string) []string {
	result := make([]string, 0, len(addrs))
	seen := map[string]struct{}{}
	for _, val := range addrs {
		if _, ok := seen[val]; !ok {
			result = append(result, val)
			seen[val] = struct{}{}
		}
	}
	return result
}

// normalizeAddress returns addr with the passed default port appended if
// there is not already a port specified.
func normalizeAddress(addr, defaultPort string) string {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.JoinHostPort(addr, defaultPort)
	}
	return addr
}

// normalizeAddresses returns a new slice with all the passed peer addresses
// normalized with the given default port, and all duplicates removed.
func normalizeAddresses(addrs []string, defaultPort string) []string {
	for i, addr := range addrs {
		addrs[i] = normalizeAddress(addr, defaultPort)
	}

	return removeDuplicateAddresses(addrs)
}

// fileExists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// newConfigParser returns a new command line flags parser.
func newConfigParser(cfg *config, so *serviceOptions, options flags.Options) *flags.Parser {
	parser := flags.NewParser(cfg, options)
	if runtime.GOOS == "windows" {
		parser.AddGroup("Service Options", "Service Options", so)
	}
	return parser
}

// createDefaultConfig copies the file sample-dcrd.conf to the given destination path,
// and populates it with some randomly generated RPC username and password.
func createDefaultConfigFile(destPath string) error {
	// Create the destination directory if it does not exist.
	err := os.MkdirAll(filepath.Dir(destPath), 0700)
	if err != nil {
		return err
	}

	// Generate a random user and password for the RPC server credentials.
	randomBytes := make([]byte, 20)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return err
	}
	generatedRPCUser := base64.StdEncoding.EncodeToString(randomBytes)
	rpcUserLine := fmt.Sprintf("rpcuser=%v", generatedRPCUser)

	_, err = rand.Read(randomBytes)
	if err != nil {
		return err
	}
	generatedRPCPass := base64.StdEncoding.EncodeToString(randomBytes)
	rpcPassLine := fmt.Sprintf("rpcpass=%v", generatedRPCPass)

	// Replace the rpcuser and rpcpass lines in the sample configuration
	// file contents with their generated values.
	rpcUserRE := regexp.MustCompile(`(?m)^;\s*rpcuser=[^\s]*$`)
	rpcPassRE := regexp.MustCompile(`(?m)^;\s*rpcpass=[^\s]*$`)
	s := rpcUserRE.ReplaceAllString(sampleconfig.FileContents(), rpcUserLine)
	s = rpcPassRE.ReplaceAllString(s, rpcPassLine)

	// Create config file at the provided path.
	dest, err := os.OpenFile(destPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC,
		0600)
	if err != nil {
		return err
	}
	defer dest.Close()

	_, err = dest.WriteString(s)
	return err
}

// generateNetworkInfo is a convenience function that creates a slice from the
// available networks.
func (cfg *config) generateNetworkInfo() []types.NetworksResult {
	return []types.NetworksResult{cfg.ipv4NetInfo, cfg.ipv6NetInfo,
		cfg.onionNetInfo}
}

// parseNetworkInterfaces updates all network interface states based on the
// provided configuration.
func parseNetworkInterfaces(cfg *config) error {
	var v4Addrs, v6Addrs uint32
	listeners, err := parseListeners(cfg.Listeners)
	if err != nil {
		return err
	}

	for _, addr := range listeners {
		if addr.Network() == "tcp4" {
			v4Addrs++
			continue
		}

		if addr.Network() == "tcp6" {
			v6Addrs++
		}
	}

	// Set IPV4 interface state.
	if v4Addrs > 0 {
		ipv4 := &cfg.ipv4NetInfo
		ipv4.Reachable = !cfg.DisableListen
		ipv4.Limited = v6Addrs == 0
		ipv4.Proxy = cfg.Proxy
	}

	// Set IPV6 interface state.
	if v6Addrs > 0 {
		ipv6 := &cfg.ipv6NetInfo
		ipv6.Reachable = !cfg.DisableListen
		ipv6.Limited = v4Addrs == 0
		ipv6.Proxy = cfg.Proxy
	}

	// Set Onion interface state.
	if v6Addrs > 0 && (cfg.Proxy != "" || cfg.OnionProxy != "") {
		onion := &cfg.onionNetInfo
		onion.Reachable = !cfg.DisableListen && !cfg.NoOnion
		onion.Limited = v4Addrs == 0
		onion.Proxy = cfg.Proxy
		if cfg.OnionProxy != "" {
			onion.Proxy = cfg.OnionProxy
		}
		onion.ProxyRandomizeCredentials = cfg.TorIsolation
	}

	return nil
}

// errSuppressUsage signifies that an error that happened during the initial
// configuration phase should suppress the usage output since it was not caused
// by the user.
type errSuppressUsage string

// Error implements the error interface.
func (e errSuppressUsage) Error() string {
	return string(e)
}

// loadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
// 	1) Start with a default config with sane settings
// 	2) Pre-parse the command line to check for an alternative config file
// 	3) Load configuration file overwriting defaults with any specified options
// 	4) Parse CLI options and overwrite/add any specified options
//
// The above results in dcrd functioning properly without any config settings
// while still allowing the user to override settings with config files and
// command line options.  Command line options always take precedence.
func loadConfig(appName string) (*config, []string, error) {
	// Default config.
	cfg := config{
		// General application behavior.
		HomeDir:          defaultHomeDir,
		ConfigFile:       defaultConfigFile,
		DataDir:          defaultDataDir,
		LogDir:           defaultLogDir,
		DbType:           defaultDbType,
		DebugLevel:       defaultLogLevel,
		SigCacheMaxSize:  defaultSigCacheMaxSize,
		UtxoCacheMaxSize: defaultUtxoCacheMaxSize,

		// RPC server options and policy.
		RPCCert:              defaultRPCCertFile,
		RPCKey:               defaultRPCKeyFile,
		RPCAuthType:          defaultRPCAuthType,
		RPCClientCAs:         defaultRPCClientCAs,
		TLSCurve:             defaultTLSCurve,
		RPCMaxClients:        defaultMaxRPCClients,
		RPCMaxWebsockets:     defaultMaxRPCWebsockets,
		RPCMaxConcurrentReqs: defaultMaxRPCConcurrentReqs,

		// P2P network options.
		MaxSameIP:       defaultMaxSameIP,
		MaxPeers:        defaultMaxPeers,
		DialTimeout:     defaultDialTimeout,
		PeerIdleTimeout: defaultPeerIdleTimeout,

		// Banning options.
		BanDuration:  defaultBanDuration,
		BanThreshold: defaultBanThreshold,

		// Relay and mempool policy.
		MinRelayTxFee:    mempool.DefaultMinRelayTxFee.ToCoin(),
		FreeTxRelayLimit: defaultFreeTxRelayLimit,
		MaxOrphanTxs:     defaultMaxOrphanTransactions,
		AllowOldVotes:    defaultAllowOldVotes,

		// Mining options and policy.
		Generate:            defaultGenerate,
		BlockMinSize:        defaultBlockMinSize,
		BlockMaxSize:        defaultBlockMaxSize,
		BlockPrioritySize:   mempool.DefaultBlockPrioritySize,
		NoMiningStateSync:   defaultNoMiningStateSync,
		AllowUnsyncedMining: defaultAllowUnsyncedMining,

		// Indexing options.
		TxIndex:           defaultTxIndex,
		AddrIndex:         defaultAddrIndex,
		NoExistsAddrIndex: defaultNoExistsAddrIndex,

		// Cooked options ready for use.
		ipv4NetInfo:  types.NetworksResult{Name: "IPV4"},
		ipv6NetInfo:  types.NetworksResult{Name: "IPV6"},
		onionNetInfo: types.NetworksResult{Name: "Onion"},
		params:       &mainNetParams,
	}

	// Service options which are only added on Windows.
	serviceOpts := serviceOptions{}

	// Pre-parse the command line options to see if an alternative config
	// file or the version flag was specified.  Any errors aside from the
	// help message error can be ignored here since they will be caught by
	// the final parse below.
	preCfg := cfg
	preParser := newConfigParser(&preCfg, &serviceOpts, flags.HelpFlag)
	_, err := preParser.Parse()
	if err != nil {
		var e *flags.Error
		if errors.As(err, &e) {
			if e.Type != flags.ErrHelp {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Fprintln(os.Stdout, err)
			os.Exit(0)
		}
	}

	// Show the version and exit if the version flag was specified.
	if preCfg.ShowVersion {
		fmt.Printf("%s version %s (Go version %s %s/%s)\n", appName,
			version.String(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Perform service command and exit if specified.  Invalid service
	// commands show an appropriate error.  Only runs on Windows since
	// the runServiceCommand function will be nil when not on Windows.
	if serviceOpts.ServiceCommand != "" && runServiceCommand != nil {
		err := runServiceCommand(serviceOpts.ServiceCommand)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(0)
	}

	// Update the home directory for dcrd if specified. Since the home
	// directory is updated, other variables need to be updated to
	// reflect the new changes.
	if preCfg.HomeDir != "" {
		cfg.HomeDir, _ = filepath.Abs(preCfg.HomeDir)

		if preCfg.ConfigFile == defaultConfigFile {
			defaultConfigFile = filepath.Join(cfg.HomeDir,
				defaultConfigFilename)
			preCfg.ConfigFile = defaultConfigFile
			cfg.ConfigFile = defaultConfigFile
		} else {
			cfg.ConfigFile = preCfg.ConfigFile
		}
		if preCfg.DataDir == defaultDataDir {
			cfg.DataDir = filepath.Join(cfg.HomeDir, defaultDataDirname)
		} else {
			cfg.DataDir = preCfg.DataDir
		}
		if preCfg.RPCKey == defaultRPCKeyFile {
			cfg.RPCKey = filepath.Join(cfg.HomeDir, "rpc.key")
		} else {
			cfg.RPCKey = preCfg.RPCKey
		}
		if preCfg.RPCCert == defaultRPCCertFile {
			cfg.RPCCert = filepath.Join(cfg.HomeDir, "rpc.cert")
		} else {
			cfg.RPCCert = preCfg.RPCCert
		}
		if preCfg.RPCClientCAs == defaultRPCClientCAs {
			cfg.RPCClientCAs = filepath.Join(cfg.HomeDir, "clients.pem")
		} else {
			cfg.RPCClientCAs = preCfg.RPCClientCAs
		}
		if preCfg.LogDir == defaultLogDir {
			cfg.LogDir = filepath.Join(cfg.HomeDir, defaultLogDirname)
		} else {
			cfg.LogDir = preCfg.LogDir
		}
	}

	// Create a default config file when one does not exist and the user did
	// not specify an override.
	if !(preCfg.SimNet || preCfg.RegNet) && preCfg.ConfigFile ==
		defaultConfigFile && !fileExists(preCfg.ConfigFile) {

		err := createDefaultConfigFile(preCfg.ConfigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating a default "+
				"config file: %v\n", err)
		}
	}

	// Load additional config from file.
	var configFileError error
	parser := newConfigParser(&cfg, &serviceOpts, flags.Default)
	if !(cfg.SimNet || cfg.RegNet) || preCfg.ConfigFile != defaultConfigFile {
		err := flags.NewIniParser(parser).ParseFile(preCfg.ConfigFile)
		if err != nil {
			var e *os.PathError
			if !errors.As(err, &e) {
				err = fmt.Errorf("Error parsing config file: %w", err)
				return nil, nil, err
			}
			configFileError = err
		}
	}

	// Don't add peers from the config file when in regression test mode.
	if preCfg.RegNet && len(cfg.AddPeers) > 0 {
		cfg.AddPeers = nil
	}

	// Parse command line options again to ensure they take precedence.
	remainingArgs, err := parser.Parse()
	if err != nil {
		return nil, nil, err
	}

	// Create the home directory if it doesn't already exist.
	funcName := "loadConfig"
	err = os.MkdirAll(cfg.HomeDir, 0700)
	if err != nil {
		// Show a nicer error message if it's because a symlink is
		// linked to a directory that does not exist (probably because
		// it's not mounted).
		var e *os.PathError
		if errors.As(err, &e) && os.IsExist(err) {
			if link, lerr := os.Readlink(e.Path); lerr == nil {
				str := "is symlink %s -> %s mounted?"
				err = fmt.Errorf(str, e.Path, link)
			}
		}

		str := "%s: failed to create home directory: %w"
		err := errSuppressUsage(fmt.Sprintf(str, funcName, err))
		return nil, nil, err
	}

	if cfg.DisableDNSSeed {
		cfg.DisableSeeders = true
		fmt.Fprintln(os.Stderr, "The --nodnsseed is deprecated: use --noseeders")
	}

	// Multiple networks can't be selected simultaneously.  Count number of
	// network flags passed and assign active network params.
	numNets := 0
	if cfg.TestNet {
		numNets++
		cfg.params = &testNet3Params
	}
	if cfg.SimNet {
		numNets++
		// Also disable dns seeding on the simulation test network.
		cfg.params = &simNetParams
		cfg.DisableSeeders = true
	}
	if cfg.RegNet {
		numNets++
		cfg.params = &regNetParams
	}
	if numNets > 1 {
		str := "%s: the testnet, regnet, and simnet params can't be " +
			"used together -- choose one of the three"
		err := fmt.Errorf(str, funcName)
		return nil, nil, err
	}

	// Set the default policy for relaying non-standard transactions
	// according to the default of the active network. The set
	// configuration value takes precedence over the default value for the
	// selected network.
	acceptNonStd := cfg.params.AcceptNonStdTxs
	switch {
	case cfg.AcceptNonStd && cfg.RejectNonStd:
		str := "%s: rejectnonstd and acceptnonstd cannot be used " +
			"together -- choose only one"
		err := fmt.Errorf(str, funcName)
		return nil, nil, err
	case cfg.RejectNonStd:
		acceptNonStd = false
	case cfg.AcceptNonStd:
		acceptNonStd = true
	}
	cfg.AcceptNonStd = acceptNonStd

	// Append the network type to the data directory so it is "namespaced"
	// per network.  In addition to the block database, there are other
	// pieces of data that are saved to disk such as address manager state.
	// All data is specific to a network, so namespacing the data directory
	// means each individual piece of serialized data does not have to
	// worry about changing names per network and such.
	//
	// Make list of old versions of testnet directories here since the
	// network specific DataDir will be used after this.
	cfg.DataDir = cleanAndExpandPath(cfg.DataDir)
	var oldTestNets []string
	oldTestNets = append(oldTestNets, filepath.Join(cfg.DataDir, "testnet"))
	oldTestNets = append(oldTestNets, filepath.Join(cfg.DataDir, "testnet2"))
	cfg.DataDir = filepath.Join(cfg.DataDir, cfg.params.Name)
	logRotator = nil
	if !cfg.NoFileLogging {
		// Append the network type to the log directory so it is "namespaced"
		// per network in the same fashion as the data directory.
		cfg.LogDir = cleanAndExpandPath(cfg.LogDir)
		cfg.LogDir = filepath.Join(cfg.LogDir, cfg.params.Name)

		// Initialize log rotation.  After log rotation has been initialized, the
		// logger variables may be used.
		initLogRotator(filepath.Join(cfg.LogDir, defaultLogFilename))
	}

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems", supportedSubsystems())
		os.Exit(0)
	}

	// Parse, validate, and set debug log level(s).
	if err := parseAndSetDebugLevels(cfg.DebugLevel); err != nil {
		err := fmt.Errorf("%s: %w", funcName, err)
		return nil, nil, err
	}

	// Validate database type.
	if !validDbType(cfg.DbType) {
		str := "%s: the specified database type [%v] is invalid -- " +
			"supported types %v"
		err := fmt.Errorf(str, funcName, cfg.DbType, knownDbTypes)
		return nil, nil, err
	}

	// Enforce the minimum and maximum utxo cache max size.
	if cfg.UtxoCacheMaxSize < minUtxoCacheMaxSize {
		cfg.UtxoCacheMaxSize = minUtxoCacheMaxSize
	} else if cfg.UtxoCacheMaxSize > maxUtxoCacheMaxSize {
		cfg.UtxoCacheMaxSize = maxUtxoCacheMaxSize
	}

	// Validate format of profile, can be an address:port, or just a port.
	if cfg.Profile != "" {
		// if profile is just a number, then add a default host of "127.0.0.1" such that Profile is a valid tcp address
		if _, err := strconv.Atoi(cfg.Profile); err == nil {
			cfg.Profile = net.JoinHostPort("127.0.0.1", cfg.Profile)
		}

		// check the Profile is a valid address
		_, portStr, err := net.SplitHostPort(cfg.Profile)
		if err != nil {
			str := "%s: profile: %w"
			err := fmt.Errorf(str, funcName, err)
			return nil, nil, err
		}

		// finally, check the port is in range
		if port, _ := strconv.Atoi(portStr); port < 1024 || port > 65535 {
			str := "%s: profile: address %s: port must be between 1024 and 65535"
			err := fmt.Errorf(str, funcName, cfg.Profile)
			return nil, nil, err
		}
	}

	// Don't allow ban durations that are too short.
	if cfg.BanDuration < time.Second {
		str := "%s: the banduration option may not be less than 1s -- parsed [%v]"
		err := fmt.Errorf(str, funcName, cfg.BanDuration)
		return nil, nil, err
	}

	// Don't allow dialtimeout durations that are too short.
	if cfg.DialTimeout < time.Second {
		str := "%s: the dialtimeout option may not be less than 1s -- parsed [%v]"
		err := fmt.Errorf(str, funcName, cfg.DialTimeout)
		return nil, nil, err
	}

	// Don't allow peeridletimeout durations that are too short.
	if cfg.PeerIdleTimeout < time.Second*15 {
		str := "%s: the peeridletimeout option may not be less " +
			"than 15s -- parsed [%v]"
		err := fmt.Errorf(str, funcName, cfg.PeerIdleTimeout)
		return nil, nil, err
	}

	// Validate any given whitelisted IP addresses and networks.
	if len(cfg.Whitelists) > 0 {
		var ip net.IP
		cfg.whitelists = make([]*net.IPNet, 0, len(cfg.Whitelists))

		for _, addr := range cfg.Whitelists {
			_, ipnet, err := net.ParseCIDR(addr)
			if err != nil {
				ip = net.ParseIP(addr)
				if ip == nil {
					str := "%s: the whitelist value of '%s' is invalid"
					err = fmt.Errorf(str, funcName, addr)
					return nil, nil, err
				}
				var bits int
				if ip.To4() == nil {
					// IPv6
					bits = 128
				} else {
					bits = 32
				}
				ipnet = &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(bits, bits),
				}
			}
			cfg.whitelists = append(cfg.whitelists, ipnet)
		}
	}

	// --addPeer and --connect do not mix.
	if len(cfg.AddPeers) > 0 && len(cfg.ConnectPeers) > 0 {
		str := "%s: the --addpeer and --connect options can not be " +
			"mixed"
		err := fmt.Errorf(str, funcName)
		return nil, nil, err
	}

	// --proxy or --connect without --listen disables listening.
	if (cfg.Proxy != "" || len(cfg.ConnectPeers) > 0) &&
		len(cfg.Listeners) == 0 {
		cfg.DisableListen = true
	}

	// Connect means no seeding.
	if len(cfg.ConnectPeers) > 0 {
		cfg.DisableSeeders = true
	}

	// Add the default listener if none were specified. The default
	// listener is all addresses on the listen port for the network
	// we are to connect to.
	if len(cfg.Listeners) == 0 {
		cfg.Listeners = []string{
			net.JoinHostPort("", cfg.params.DefaultPort),
		}
	}

	// Check to make sure limited and admin users don't have the same username
	if cfg.RPCUser == cfg.RPCLimitUser && cfg.RPCUser != "" {
		str := "%s: --rpcuser and --rpclimituser must not specify the " +
			"same username"
		err := fmt.Errorf(str, funcName)
		return nil, nil, err
	}

	// Check to make sure limited and admin users don't have the same password
	if cfg.RPCPass == cfg.RPCLimitPass && cfg.RPCPass != "" {
		str := "%s: --rpcpass and --rpclimitpass must not specify the " +
			"same password"
		err := fmt.Errorf(str, funcName)
		return nil, nil, err
	}

	// The RPC server is disabled if no username or password is provided
	// under basic user/pass authentication.
	if cfg.RPCAuthType == authTypeBasic &&
		(cfg.RPCUser == "" || cfg.RPCPass == "") &&
		(cfg.RPCLimitUser == "" || cfg.RPCLimitPass == "") {
		cfg.DisableRPC = true
	}

	// Check to make sure RPC usernames and passwords are not provided under
	// client cert authentiation.
	if cfg.RPCAuthType == authTypeClientCert {
		switch {
		case cfg.RPCUser != "", cfg.RPCPass != "",
			cfg.RPCLimitUser != "", cfg.RPCLimitPass != "":
			str := "%s: RPC usernames and passwords are not allowed " +
				"with --authtype=clientcert"
			err := fmt.Errorf(str, funcName)
			return nil, nil, err
		}
	}

	// Default RPC to listen on localhost only.
	if !cfg.DisableRPC && len(cfg.RPCListeners) == 0 {
		addrs, err := net.LookupHost("localhost")
		if err != nil {
			return nil, nil, err
		}
		cfg.RPCListeners = make([]string, 0, len(addrs))
		for _, addr := range addrs {
			addr = net.JoinHostPort(addr, cfg.params.rpcPort)
			cfg.RPCListeners = append(cfg.RPCListeners, addr)
		}
	}

	if cfg.RPCMaxConcurrentReqs < 0 {
		str := "%s: the rpcmaxwebsocketconcurrentrequests option may " +
			"not be less than 0 -- parsed [%d]"
		err := fmt.Errorf(str, funcName, cfg.RPCMaxConcurrentReqs)
		return nil, nil, err
	}

	// Validate the minrelaytxfee.
	cfg.minRelayTxFee, err = dcrutil.NewAmount(cfg.MinRelayTxFee)
	if err != nil {
		str := "%s: invalid minrelaytxfee: %w"
		err := fmt.Errorf(str, funcName, err)
		return nil, nil, err
	}

	// Ensure the specified max block size is not larger than the network will
	// allow.  1000 bytes is subtracted from the max to account for overhead.
	blockMaxSizeMax := uint32(cfg.params.MaximumBlockSizes[0]) - 1000
	if cfg.BlockMaxSize < blockMaxSizeMin || cfg.BlockMaxSize >
		blockMaxSizeMax {

		str := "%s: the blockmaxsize option must be in between %d " +
			"and %d -- parsed [%d]"
		err := fmt.Errorf(str, funcName, blockMaxSizeMin,
			blockMaxSizeMax, cfg.BlockMaxSize)
		return nil, nil, err
	}

	// Limit the max orphan count to a sane value.
	if cfg.MaxOrphanTxs < 0 {
		str := "%s: the maxorphantx option may not be less than 0 " +
			"-- parsed [%d]"
		err := fmt.Errorf(str, funcName, cfg.MaxOrphanTxs)
		return nil, nil, err
	}

	// Limit the block priority and minimum block sizes to max block size.
	cfg.BlockPrioritySize = minUint32(cfg.BlockPrioritySize, cfg.BlockMaxSize)
	cfg.BlockMinSize = minUint32(cfg.BlockMinSize, cfg.BlockMaxSize)

	// --txindex and --droptxindex do not mix.
	if cfg.TxIndex && cfg.DropTxIndex {
		err := fmt.Errorf("%s: the --txindex and --droptxindex "+
			"options may  not be activated at the same time",
			funcName)
		return nil, nil, err
	}

	// --addrindex and --dropaddrindex do not mix.
	if cfg.AddrIndex && cfg.DropAddrIndex {
		err := fmt.Errorf("%s: the --addrindex and --dropaddrindex "+
			"options may not be activated at the same time",
			funcName)
		return nil, nil, err
	}

	// --addrindex and --droptxindex do not mix.
	if cfg.AddrIndex && cfg.DropTxIndex {
		err := fmt.Errorf("%s: the --addrindex and --droptxindex "+
			"options may not be activated at the same time "+
			"because the address index relies on the transaction "+
			"index", funcName)
		return nil, nil, err
	}

	// !--noexistsaddrindex and --dropexistsaddrindex do not mix.
	if !cfg.NoExistsAddrIndex && cfg.DropExistsAddrIndex {
		err := fmt.Errorf("dropexistsaddrindex cannot be activated when " +
			"existsaddressindex is on (try setting --noexistsaddrindex)")
		return nil, nil, err
	}

	// Check mining addresses are valid and saved parsed versions.
	cfg.miningAddrs = make([]dcrutil.Address, 0, len(cfg.MiningAddrs))
	for _, strAddr := range cfg.MiningAddrs {
		addr, err := dcrutil.DecodeAddress(strAddr, cfg.params.Params)
		if err != nil {
			str := "%s: mining address '%s' failed to decode: %w"
			err := fmt.Errorf(str, funcName, strAddr, err)
			return nil, nil, err
		}
		cfg.miningAddrs = append(cfg.miningAddrs, addr)
	}

	// Ensure there is at least one mining address when the generate flag is
	// set.
	if cfg.Generate && len(cfg.miningAddrs) == 0 {
		str := "%s: the generate flag is set, but there are no mining " +
			"addresses specified "
		err := fmt.Errorf(str, funcName)
		return nil, nil, err
	}

	// Don't allow unsynchronized mining on mainnet.
	if cfg.AllowUnsyncedMining && cfg.params == &mainNetParams {
		str := "%s: allowunsyncedmining cannot be activated on mainnet"
		err := fmt.Errorf(str, funcName)
		return nil, nil, err
	}

	// Always allow unsynchronized mining on simnet and regnet.
	if cfg.SimNet || cfg.RegNet {
		cfg.AllowUnsyncedMining = true
	}

	// Add default port to all listener addresses if needed and remove
	// duplicate addresses.
	cfg.Listeners = normalizeAddresses(cfg.Listeners,
		cfg.params.DefaultPort)

	// Add default port to all rpc listener addresses if needed and remove
	// duplicate addresses.
	cfg.RPCListeners = normalizeAddresses(cfg.RPCListeners,
		cfg.params.rpcPort)

	// The authtype config must be one of "basic" or "clientcert".
	switch cfg.RPCAuthType {
	case authTypeBasic, authTypeClientCert:
	default:
		err := fmt.Errorf("%s: invalid authtype option %q",
			funcName, cfg.RPCAuthType)
		return nil, nil, err
	}

	// Only allow TLS to be disabled if the RPC is bound to localhost
	// addresses, and when client cert auth is not used.
	if !cfg.DisableRPC && cfg.DisableTLS {
		allowedTLSListeners := map[string]struct{}{
			"localhost": {},
			"127.0.0.1": {},
			"::1":       {},
		}
		for _, addr := range cfg.RPCListeners {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				str := "%s: RPC listen interface '%s' is " +
					"invalid: %w"
				err := fmt.Errorf(str, funcName, addr, err)
				return nil, nil, err
			}
			if _, ok := allowedTLSListeners[host]; !ok {
				str := "%s: the --notls option may not be used " +
					"when binding RPC to non localhost " +
					"addresses: %s"
				err := fmt.Errorf(str, funcName, addr)
				return nil, nil, err
			}
		}

		if cfg.RPCAuthType == authTypeClientCert {
			err := fmt.Errorf("%s: TLS may not be disabled with "+
				"authtype=clientcert", funcName)
			return nil, nil, err
		}
	}

	// Add default port to all added peer addresses if needed and remove
	// duplicate addresses.
	cfg.AddPeers = normalizeAddresses(cfg.AddPeers,
		cfg.params.DefaultPort)
	cfg.ConnectPeers = normalizeAddresses(cfg.ConnectPeers,
		cfg.params.DefaultPort)

	// Tor stream isolation requires either proxy or onion proxy to be set.
	if cfg.TorIsolation && cfg.Proxy == "" && cfg.OnionProxy == "" {
		str := "%s: Tor stream isolation requires either proxy or " +
			"onionproxy to be set"
		err := fmt.Errorf(str, funcName)
		return nil, nil, err
	}

	// Setup dial and DNS resolution (lookup) functions depending on the
	// specified options.  The default is to use the standard net.Dial
	// function as well as the system DNS resolver.  When a proxy is
	// specified, the dial function is set to the proxy specific dial
	// function and the lookup is set to use tor (unless --noonion is
	// specified in which case the system DNS resolver is used).
	var d net.Dialer
	cfg.dial = d.DialContext
	cfg.lookup = net.LookupIP
	if cfg.Proxy != "" {
		_, _, err := net.SplitHostPort(cfg.Proxy)
		if err != nil {
			str := "%s: proxy address '%s' is invalid: %w"
			err := fmt.Errorf(str, funcName, cfg.Proxy, err)
			return nil, nil, err
		}

		if cfg.TorIsolation &&
			(cfg.ProxyUser != "" || cfg.ProxyPass != "") {
			fmt.Fprintln(os.Stderr, "Tor isolation set -- "+
				"overriding specified proxy user credentials")
		}

		proxy := &socks.Proxy{
			Addr:         cfg.Proxy,
			Username:     cfg.ProxyUser,
			Password:     cfg.ProxyPass,
			TorIsolation: cfg.TorIsolation,
		}
		cfg.dial = proxy.DialContext
		if !cfg.NoOnion {
			cfg.lookup = func(host string) ([]net.IP, error) {
				return connmgr.TorLookupIP(context.Background(), host, cfg.Proxy)
			}
		}
	}

	// Setup onion address dial and DNS resolution (lookup) functions
	// depending on the specified options.  The default is to use the
	// same dial and lookup functions selected above.  However, when an
	// onion-specific proxy is specified, the onion address dial and
	// lookup functions are set to use the onion-specific proxy while
	// leaving the normal dial and lookup functions as selected above.
	// This allows .onion address traffic to be routed through a different
	// proxy than normal traffic.
	if cfg.OnionProxy != "" {
		_, _, err := net.SplitHostPort(cfg.OnionProxy)
		if err != nil {
			str := "%s: Onion proxy address '%s' is invalid: %w"
			err := fmt.Errorf(str, funcName, cfg.OnionProxy, err)
			return nil, nil, err
		}

		if cfg.TorIsolation &&
			(cfg.OnionProxyUser != "" || cfg.OnionProxyPass != "") {
			fmt.Fprintln(os.Stderr, "Tor isolation set -- "+
				"overriding specified onionproxy user "+
				"credentials ")
		}

		cfg.oniondial = func(ctx context.Context, a, b string) (net.Conn, error) {
			proxy := &socks.Proxy{
				Addr:         cfg.OnionProxy,
				Username:     cfg.OnionProxyUser,
				Password:     cfg.OnionProxyPass,
				TorIsolation: cfg.TorIsolation,
			}
			return proxy.DialContext(ctx, a, b)
		}
		cfg.onionlookup = func(host string) ([]net.IP, error) {
			return connmgr.TorLookupIP(context.Background(), host, cfg.OnionProxy)
		}
	} else {
		cfg.oniondial = cfg.dial
		cfg.onionlookup = cfg.lookup
	}

	// Specifying --noonion means the onion address dial and DNS resolution
	// (lookup) functions result in an error.
	if cfg.NoOnion {
		cfg.oniondial = func(ctx context.Context, a, b string) (net.Conn, error) {
			return nil, errors.New("tor has been disabled")
		}
		cfg.onionlookup = func(a string) ([]net.IP, error) {
			return nil, errors.New("tor has been disabled")
		}
	}

	// Warn if old testnet directory is present.
	for _, oldDir := range oldTestNets {
		if fileExists(oldDir) {
			dcrdLog.Warnf("Block chain data from previous testnet"+
				" found (%v) and can probably be removed.",
				oldDir)
		}
	}

	// Parse information regarding the state of the supported network
	// interfaces.
	if err := parseNetworkInterfaces(&cfg); err != nil {
		return nil, nil, err
	}

	// Prevent using an unsupported curve.
	if _, err := tlsCurve(cfg.TLSCurve); err != nil {
		return nil, nil, err
	}

	// Warn about missing config file only after all other configuration is
	// done.  This prevents the warning on help messages and invalid
	// options.  Note this should go directly before the return.
	if configFileError != nil {
		dcrdLog.Warnf("%v", configFileError)
	}

	return &cfg, remainingArgs, nil
}

// dcrdDial connects to the address on the named network using the appropriate
// dial function depending on the address and configuration options.  For
// example, .onion addresses will be dialed using the onion specific proxy if
// one was specified, but will otherwise use the normal dial function (which
// could itself use a proxy or not).
func dcrdDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if strings.Contains(addr, ".onion:") {
		return cfg.oniondial(ctx, network, addr)
	}
	return cfg.dial(ctx, network, addr)
}

// dcrdLookup invokes the correct DNS lookup function to use depending on the
// passed host and configuration options.  For example, .onion addresses will be
// resolved using the onion specific proxy if one was specified, but will
// otherwise treat the normal proxy as tor unless --noonion was specified in
// which case the lookup will fail.  Meanwhile, normal IP addresses will be
// resolved using tor if a proxy was specified unless --noonion was also
// specified in which case the normal system DNS resolver will be used.
func (cfg *config) dcrdLookup(host string) ([]net.IP, error) {
	if strings.HasSuffix(host, ".onion") {
		return cfg.onionlookup(host)
	}
	return cfg.lookup(host)
}

// tlsCurve returns the correct curve given a config option indicating the
// curve to use or an error if the curve does not exist.
func tlsCurve(curve string) (elliptic.Curve, error) {
	switch curve {
	case "P-521":
		return elliptic.P521(), nil
	case "P-256":
		return elliptic.P256(), nil
	default:
		return nil, fmt.Errorf("unsupported curve %s", curve)
	}
}
