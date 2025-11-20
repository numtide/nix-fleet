COORDINATIR_NODE_ID := "ba48d5a18a06a0348511b83ef8e8b900ea653c43086e55613344cdd8192f7f6c"
AGENT_NODE_ID := "976f02e6c46cd53189128d7b72ec1a2eeff05012130debefc7a5dab8d0744139"

coordinator-nodeid:
    echo {{COORDINATIR_NODE_ID}}

agent-nodeid:
    echo {{AGENT_NODE_ID}}

run-coordinator +args="":
    #!/usr/bin/env bash
    RUST_LOG=flt=trace,flt_lib=trace \
        cargo run -- \
            --maybe-secret-key=./fixtures/coordinator.ed25519 \
        coordinator \
            {{args}}

run-agent +args="":
    #!/usr/bin/env bash
    RUST_LOG=flt=trace,flt_lib=trace \
        cargo run -- \
            --maybe-secret-key=./fixtures/agent.ed25519 \
        agent \
            --coordinators="{{ COORDINATIR_NODE_ID }}" \
            {{args}}

run-admin +args="":
    #!/usr/bin/env bash
    RUST_LOG=flt=trace,flt_lib=trace \
        cargo run -- \
            --maybe-secret-key=./fixtures/admin.ed25519 \
        admin \
            --coordinators="{{ COORDINATIR_NODE_ID }}" \
            \
            {{args}}

run-admin-echo-hash +args="-n100":
    just run-admin echo-hash "{{ COORDINATIR_NODE_ID}}" \
        {{args}}

bench:
    cargo bench --features test

test:
    cargo nextest run
