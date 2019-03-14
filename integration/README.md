integration
===========
[![Build Status](http://img.shields.io/travis/decred/dcrd.svg)](https://travis-ci.org/decred/dcrd)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)

Offers components to implement regression testing framework.

Subpackages:

 - [harness](https://github.com/decred/dcrd/tree/master/integration/harness)
 provides a unified platform for creating RPC-driven integration tests involving
 node and wallet executables.

 - [commandline](https://github.com/decred/dcrd/tree/master/integration/commandline)
 provides helpers to run external command-line tools.

 - [gobuilder](https://github.com/decred/dcrd/tree/master/integration/gobuilder)
 helps to build a target Go project upon request.

 - [simpleregtest](https://github.com/decred/dcrd/tree/master/integration/harness/simpleregtest)
 harbours a pre-configured test setup and unit tests to run RPC-driven node tests.

 ## License
 This code is licensed under the [copyfree](http://copyfree.org) ISC License.