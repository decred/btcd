// Copyright (c) 2015 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package dcrjson

import v3 "github.com/decred/dcrd/dcrjson/v3"

// GenerateHelp generates and returns help output for the provided method and
// result types given a map to provide the appropriate keys for the method
// synopsis, field descriptions, conditions, and result descriptions.  The
// method must be associated with a registered type.  All commands provided by
// this package are registered by default.
//
// The resultTypes must be pointer-to-types which represent the specific types
// of values the command returns.  For example, if the command only returns a
// boolean value, there should only be a single entry of (*bool)(nil).  Note
// that each type must be a single pointer to the type.  Therefore, it is
// recommended to simply pass a nil pointer cast to the appropriate type as
// previously shown.
//
// The provided descriptions map must contain all of the keys or an error will
// be returned which includes the missing key, or the final missing key when
// there is more than one key missing.  The generated help in the case of such
// an error will use the key in place of the description.
//
// The following outlines the required keys:
//   "<method>--synopsis"             Synopsis for the command
//   "<method>-<lowerfieldname>"      Description for each command argument
//   "<typename>-<lowerfieldname>"    Description for each object field
//   "<method>--condition<#>"         Description for each result condition
//   "<method>--result<#>"            Description for each primitive result num
//
// Notice that the "special" keys synopsis, condition<#>, and result<#> are
// preceded by a double dash to ensure they don't conflict with field names.
//
// The condition keys are only required when there is more than on result type,
// and the result key for a given result type is only required if it's not an
// object.
//
// For example, consider the 'help' command itself.  There are two possible
// returns depending on the provided parameters.  So, the help would be
// generated by calling the function as follows:
//   GenerateHelp("help", descs, (*string)(nil), (*string)(nil)).
//
// The following keys would then be required in the provided descriptions map:
//
//   "help--synopsis":   "Returns a list of all commands or help for ...."
//   "help-command":     "The command to retrieve help for",
//   "help--condition0": "no command provided"
//   "help--condition1": "command specified"
//   "help--result0":    "List of commands"
//   "help--result1":    "Help for specified command"
func GenerateHelp(method string, descs map[string]string, resultTypes ...interface{}) (string, error) {
	return v3.GenerateHelp(method, descs, resultTypes...)
}
