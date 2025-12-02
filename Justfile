COORDINATOR_NODE_ID := "ba48d5a18a06a0348511b83ef8e8b900ea653c43086e55613344cdd8192f7f6c"
AGENT_NODE_ID := "976f02e6c46cd53189128d7b72ec1a2eeff05012130debefc7a5dab8d0744139"

DEFAULT_LOG_LEVEL := "debug"

coordinator-nodeid:
    echo {{COORDINATOR_NODE_ID}}

agent-nodeid:
    echo {{AGENT_NODE_ID}}

run-coordinator relay_mode="disabled" +args="":
    #!/usr/bin/env bash
    RUST_LOG=flt={{DEFAULT_LOG_LEVEL}},flt_lib={{DEFAULT_LOG_LEVEL}},iroh_blobs=debug,iroh_docs=debug \
        cargo run -- \
            --maybe-secret-key=./fixtures/coordinator.ed25519 \
            --relay-mode={{relay_mode}} \
        coordinator \
            --persistence-mode=filesystem --persistence-dir=.local/coordinator \
            {{args}}

run-agent relay_mode="disabled" node_id=COORDINATOR_NODE_ID +args="":
    #!/usr/bin/env bash
    RUST_LOG=flt={{DEFAULT_LOG_LEVEL}},flt_lib={{DEFAULT_LOG_LEVEL}} \
        cargo run -- \
            --maybe-secret-key=./fixtures/agent.ed25519 \
            --relay-mode={{relay_mode}} \
        agent \
            --coordinator="{{ node_id }}" \
            --maybe-subscribe-loop-interval-seconds=99999 \
            {{args}}

run-admin relay_mode="disabled" node_id=COORDINATOR_NODE_ID +args="":    #!/usr/bin/env bash
    RUST_LOG=flt={{DEFAULT_LOG_LEVEL}},flt_lib={{DEFAULT_LOG_LEVEL}} \
        cargo run -- \
            --maybe-secret-key=./fixtures/admin.ed25519 \
            --relay-mode={{relay_mode}} \
        admin \
            --node-id="{{ node_id }}" \
            \
            {{args}}

run-agent-on-installer:
    #!/usr/bin/env bash
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no ./fixtures/agent.ed25519 nixos@nixos:/home/nixos/
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no  nixos@nixos sudo \
        RUST_LOG=flt={{DEFAULT_LOG_LEVEL}} \
            flt \
                --relay-mode=default \
                --maybe-secret-key=/home/nixos/agent.ed25519 \
            agent \
                --coordinator={{COORDINATOR_NODE_ID}}

get-agent-facts:
    just run-admin disabled $(just coordinator-nodeid) enrollment-service get-facts $(just agent-nodeid) | jq .

bench:
    cargo bench --features test

test:
    cargo nextest run
