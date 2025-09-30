# NOTES
Notes taken for research and development purposes.

## Component Connectivity
Using [iroh][] as the connectivity framework provides flexibility for any network topology among the component instances.
At its core it's a P2P framework that provides resilient connectivity between nodes. Its SDK has primitives for building application specific protocols. There's a [collection of existing protocols](https://www.iroh.computer/proto), highlighting the following three that are maintained by the core team:

* [iroh-blobs](https://www.iroh.computer/proto/iroh-blobs): Provides blob and blob sequence transfer support for iroh. It implements a simple request-response protocol based on BLAKE3 verified streaming.
* [iroh-gossip](https://www.iroh.computer/proto/iroh-gossip): Gossip protocol based on epidemic broadcast trees to disseminate messages among a swarm of peers interested in a topic.
* [iroh-docs](https://www.iroh.computer/proto/iroh-docs): Builds on the blobs and gossip protocol and features multi-dimensional key-value documents with an efficient synchronization protocol.

## Authentication && Authorization

### ed25519 keys
Iroh natively uses ed25519 keys to authenticate nodes. This allows reusing existing SSH keys where that's desired.

Reference code:
*  [iroh-node-util code showing SSH key handling](https://github.com/n0-computer/iroh-node-util/blob/3e9702ad215b9b986c6d45e4762a8fbe241163b0/src/fs.rs#L11)

## Authorization
Iroh-docs comes with [a builtin capability model](https://docs.rs/iroh-docs/latest/iroh_docs/sync/enum.Capability.html) with Write and Read operations per Namespace. In scoping the namespaces appropriately, this model is flexible enough for all our use-cases.

TODO: map out namespaces and scopes for each component

## Consistency Considerations
A system with asynchronous processing implicates consistency trade-offs. The aim with this section is to surface and document these alongside their influence on current architectural decisions.

### Audit trail
All admin operations, such as submitting an updated or initial configuration for a device, or changing the administrator constellation, are subject to be logged in a tamper-proof audit trail.

The audit trail requires to record all administrator operations in an append-only fashion across all coordinators. This forms an effective transaction boundary between the admin operation and the accompanying audit trail record.

### High-Availability Coordinator (later)
Avoiding a single-point-of-failure in the coordinator functionality of the fleet is desired in the future.

The design can be guided by the [PACELC](https://en.wikipedia.org/wiki/PACELC_design_principle) design principle, which clearly delineated trade-offs under normal and partitioned networking conditions. We can distinguish different requirements for different types of data in the system.

The following list discusses various approaches and their trade-offs:

* With the number of coordinators ≥ 3, it's feasible to use a distributed storage engine that relies on a consensus algorithm such as Raft to have immediate consistency. In this scenario there needs to be at least 2 coordinators online for write operations.
* Using an eventual consistency model would allow even offline-write operations, at the cost of having intermittently inconsistent state. It's to be evaluated whether such a model can be a fit for the architecture requirements.

## Persistence
Each fleet relies on persisted data for its operation which is at the Coordinator's responsibility.

* Agents
  * Id
  * Type
  * Status
  * History of facts
  * Artifact graph
  * Reference to current position in the artifact graph
  * Metadata
    * Name?
    * Owner?
* Enrolling Agents
    * Type
    * History of submitted facts
* Enrolled Agents
    * Type
    * History of submitted facts
* Credentials map
* Audit logs

### Artifacts
At first all artifacts are actually nix build outputs. It's worth considering that all artifacts could be content addressable and the fact that it's a nix build output could be irrelevant.

The artifact storage should allow to attach metadata to the artifact.

Question: is there any use-case that's not covered by a content-addressed store?

Could the content-addressed store be embedded in the coordinator process or should it run separately?


#### Nix Build Outputs

We certainly want to store Nix build outputs somewhere and need to make them retrievable by the Agent.
As it's a requirement that the Agent doesn't have to evaluate its configuration, it's feasible to drop `nix` as a runtime dependency on the Agent altogether.
This frees up the choice of protocols for transferring the artifacts, e.g. there's no need to stay within the limitations of the Nix Binary Cache protocol

#### Evaluation Snix' CAStore

* Currently Write/Insert Only, No GC
* Could CAStore be embedded in the rust application and use iroh for transport?
* What is the consensus mechanism among CAStore nodes, if any?

---

[iroh]: https://www.iroh.computer/
