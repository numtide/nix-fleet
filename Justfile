COORDINATOR_NODE_ID := "ba48d5a18a06a0348511b83ef8e8b900ea653c43086e55613344cdd8192f7f6c"
AGENT_NODE_ID := "976f02e6c46cd53189128d7b72ec1a2eeff05012130debefc7a5dab8d0744139"

coordinator-nodeid:
    echo {{COORDINATOR_NODE_ID}}

agent-nodeid:
    echo {{AGENT_NODE_ID}}

run-coordinator relay_mode="disabled" +args="":
    #!/usr/bin/env bash
    RUST_LOG=iroh=debug,flt=trace,flt_lib=trace \
        cargo run -- \
            --maybe-secret-key=./fixtures/coordinator.ed25519 \
            --relay-mode={{relay_mode}} \
        coordinator \
            {{args}}

run-agent relay_mode="disabled" node_id=COORDINATOR_NODE_ID +args="":
    #!/usr/bin/env bash
    RUST_LOG=flt=trace,flt_lib=trace \
        cargo run -- \
            --maybe-secret-key=./fixtures/agent.ed25519 \
            --relay-mode={{relay_mode}} \
        agent \
            --coordinator="{{ node_id }}" \
            {{args}}

run-admin relay_mode="disabled" node_id=COORDINATOR_NODE_ID +args="":    #!/usr/bin/env bash
    RUST_LOG=flt=trace,flt_lib=trace \
        cargo run -- \
            --maybe-secret-key=./fixtures/admin.ed25519 \
            --relay-mode={{relay_mode}} \
        admin \
            --node-id="{{ node_id }}" \
            \
            {{args}}

bench:
    cargo bench --features test

test:
    cargo nextest run
