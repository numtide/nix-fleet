# NOTES

These will be refactored later.

## Iroh

*  [iroh-node-util code showing SSH key hadnling](https://github.com/n0-computer/iroh-node-util/blob/3e9702ad215b9b986c6d45e4762a8fbe241163b0/src/fs.rs#L11)

## Persistence

There are multiple runtime data types that are subject to persistence for the desired livetime of the fleet:

### Fleet metadata
* Enrolling Agents
    * Type
    * History of submitted facts
* Enrolled Agents
    * Type
    * History of submitted facts
    * Artifact graph
    * Reference to known artifact graph node
* Coordinator instances
    * Question: are all coordinators equal or is there a leader? this probably depends on the type of distributed storage that's used
* Credentials map
* Audit logs


### Artifacts

At first all artifacts are actually nix build outputs. It's worth considering that all artifacts could be content addressable and the fact that it's a nix build output could be irrelevant.

Question: is there any use-case that's not covered by a content-addressed store?

Could the content-addressed store be embedded in the coordinator process or should it run seperately?

#### Nix Build Outputs

We certainly want to store Nix build outputs somewhere and need to make them retrievable by the Agent.
As it's a requirement that the Agent doesn't have to evaluate its configuration, it's feasible to drop `nix` as a runtime dependency on the Agent altogether.
This frees up the choice of protocols for transferring the artifacts, e.g. there's no need to stay within the limitations of the Nix Binary Cache protocol

#### Evaluation Snix' CAStore

* Currently Write/Insert Only, No GC
* Could CAStore be embedded in the rust application and use iroh for transport?
* What is the consensus mechanism among CAStore nodes, if any?
