// Copyright (c) 2014 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package dcrjson

// GetStakeDifficultyResult models the data returned from the
// getstakedifficulty command.
type GetStakeDifficultyResult struct {
	CurrentStakeDifficulty float64 `json:"current"`
	NextStakeDifficulty    float64 `json:"next"`
}

// StakeVersions models the data for GetStakeVersionsResult.
type StakeVersions struct {
	Hash          string   `json:"hash"`
	Height        int64    `json:"height"`
	BlockVersion  int32    `json:"blockversion"`
	StakeVersion  uint32   `json:"stakeversion"`
	VoterVersions []uint32 `json:"voterversions"`
}

// GetStakeVersionsResult models the data returned from the getstakeversions
// command.
type GetStakeVersionsResult struct {
	StakeVersions []StakeVersions `json:"stakeversions"`
}

type Choice struct {
	Id          string  `json:"id"`
	Description string  `json:"description"`
	Bits        uint16  `json:"bits"`
	IsIgnore    bool    `json:"isignore"`
	IsNo        bool    `json:"isno"`
	Count       uint32  `json:"count"`
	Percentage  float64 `json:"percentage"`
}

// Agenda
type Agenda struct {
	Id               string   `json:"id"`
	Description      string   `json:"description"`
	Mask             uint16   `json:"mask"`
	StartTime        uint64   `json:"starttime"`
	ExpireTime       uint64   `json:"expiretime"`
	TotalVotes       uint32   `json:"totalvotes"`
	Status           string   `json:"status"`
	QuorumPercentage float64  `json:"quorumpercentage"`
	Choices          []Choice `json:"choices"`
}

// GetVoteInfoResult models the data returned from the getvoteinfo command.
type GetVoteInfoResult struct {
	CurrentHeight int64    `json:"currentheight"`
	StartHeight   int64    `json:"startheight"`
	EndHeight     int64    `json:"endheight"`
	Hash          string   `json:"hash"`
	StakeVersion  uint32   `json:"stakeversion"`
	Quorum        uint32   `json:"quorum"`
	Agendas       []Agenda `json:"agendas"`
}

// EstimateStakeDiffResult models the data returned from the estimatestakediff
// command.
type EstimateStakeDiffResult struct {
	Min      float64  `json:"min"`
	Max      float64  `json:"max"`
	Expected float64  `json:"expected"`
	User     *float64 `json:"user,omitempty"`
}

// LiveTicketsResult models the data returned from the livetickets
// command.
type LiveTicketsResult struct {
	Tickets []string `json:"tickets"`
}

// MissedTicketsResult models the data returned from the missedtickets
// command.
type MissedTicketsResult struct {
	Tickets []string `json:"tickets"`
}

// Ticket is the structure representing a ticket.
type Ticket struct {
	Hash  string `json:"hash"`
	Owner string `json:"owner"`
}

// FeeInfoBlock is ticket fee information about a block.
type FeeInfoBlock struct {
	Height uint32  `json:"height"`
	Number uint32  `json:"number"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Mean   float64 `json:"mean"`
	Median float64 `json:"median"`
	StdDev float64 `json:"stddev"`
}

// FeeInfoMempool is ticket fee information about the mempool.
type FeeInfoMempool struct {
	Number uint32  `json:"number"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Mean   float64 `json:"mean"`
	Median float64 `json:"median"`
	StdDev float64 `json:"stddev"`
}

// FeeInfoRange is ticket fee information about a range.
type FeeInfoRange struct {
	Number uint32  `json:"number"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Mean   float64 `json:"mean"`
	Median float64 `json:"median"`
	StdDev float64 `json:"stddev"`
}

// FeeInfoWindow is ticket fee information about an adjustment window.
type FeeInfoWindow struct {
	StartHeight uint32  `json:"startheight"`
	EndHeight   uint32  `json:"endheight"`
	Number      uint32  `json:"number"`
	Min         float64 `json:"min"`
	Max         float64 `json:"max"`
	Mean        float64 `json:"mean"`
	Median      float64 `json:"median"`
	StdDev      float64 `json:"stddev"`
}

// TicketFeeInfoResult models the data returned from the ticketfeeinfo command.
// command.
type TicketFeeInfoResult struct {
	FeeInfoMempool FeeInfoMempool  `json:"feeinfomempool"`
	FeeInfoBlocks  []FeeInfoBlock  `json:"feeinfoblocks"`
	FeeInfoWindows []FeeInfoWindow `json:"feeinfowindows"`
}

// TicketsForAddressResult models the data returned from the ticketforaddress
// command.
type TicketsForAddressResult struct {
	Tickets []string `json:"tickets"`
}

// TxFeeInfoResult models the data returned from the ticketfeeinfo command.
// command.
type TxFeeInfoResult struct {
	FeeInfoMempool FeeInfoMempool `json:"feeinfomempool"`
	FeeInfoBlocks  []FeeInfoBlock `json:"feeinfoblocks"`
	FeeInfoRange   FeeInfoRange   `json:"feeinforange"`
}

// VersionResult models objects included in the version response.  In the actual
// result, these objects are keyed by the program or API name.
type VersionResult struct {
	VersionString string `json:"versionstring"`
	Major         uint32 `json:"major"`
	Minor         uint32 `json:"minor"`
	Patch         uint32 `json:"patch"`
	Prerelease    string `json:"prerelease"`
	BuildMetadata string `json:"buildmetadata"`
}
