![RMC](/images/RMC_Logo.svg)

# What is RMC?
RMC is a network of computers which use the [Ripple consensus algorithm](https://www.youtube.com/watch?v=pj1QVb1vlC0) to atomically settle and record
transactions on a secure distributed database, the RMC Consensus Ledger
(RCL). Because of its distributed nature, the RCL offers transaction immutability
without a central operator. The RCL contains a built-in currency exchange and its
path-finding algorithm finds competitive exchange rates across order books
and currency pairs.

### Key Features
- **Distributed**
  - Direct account-to-account settlement with no central operator
  - Decentralized global market for competitive FX
- **Secure**
  - Transactions are cryptographically signed using ECDSA
  - Multi-signing capabilities
- **Scalable**
  - Capacity to process the world’s cross-border payments volume
  - Easy access to liquidity through a competitive FX marketplace

### License
`rmcd` is open source and permissively licensed under the
ISC license. See the LICENSE file for more details.

#### Repository Contents

| Folder  | Contents |
|---------|----------|
| ./build | Intermediate and final build outputs.          |
| ./Builds| Platform or IDE-specific project files.        |
| ./conf  | Example configuration files.                   |
| ./doc   | Documentation.                                 |
| ./src   | Source code.                                   |

Some of the directories under `src` are external repositories inlined via
git-subtree. See the corresponding README for more details.

- - -

Copyright © 2017, Ripple Labs. All rights reserved.

Copyright © 2017, Russian Mining Company. All rights reserved.

Portions of this document, including but not limited to the Ripple logo,
images and image templates are the property of Ripple Labs and cannot be
copied or used without permission.
