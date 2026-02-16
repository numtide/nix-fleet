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

get-agent-facts:
    just run-admin disabled $(just coordinator-nodeid) enrollment-service get-facts $(just agent-nodeid) | jq .

bench:
    cargo bench --features test

test:
    cargo nextest run


### recipes specific to steveej's local environment

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


stop-agent-on-steveej-sj-srv2:
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no root@sj-srv2 "systemctl stop flt-agent-dev.service"

run-agent-on-steveej-sj-srv2:
    #!/usr/bin/env bash
    set -xeE -o pipefail

    just stop-agent-on-steveej-sj-srv2 || true

    export FLT_PATH=$(nix build --no-link --print-out-paths --builders sj-srv2 .#packages.x86_64-linux.rust-workspace)/bin/flt
    export AGENT_SECRET_KEY=/root/.flt_agent_secret.key

    # TODO(MABYE): maybe set up cross compilation and make this work
    # export FLT_PATH=/root/.flt-bin-dev
    # cargo build --bin flt --target=x86_64-unknown-linux-gnu
    # scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no ./target/debug/flt root@sj-srv2:${FLT_PATH}

    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no ./fixtures/agent.ed25519 root@sj-srv2:${AGENT_SECRET_KEY}
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o CheckHostIP=no root@sj-srv2 \
        systemd-run \
                --unit="flt-agent-dev" \
                --remain-after-exit --collect --send-sighup --collect \
                --setenv=RUST_LOG=flt={{DEFAULT_LOG_LEVEL}} \
                --setenv=PATH=\$PATH \
            ${FLT_PATH} \
            \
                --relay-mode=default \
                --maybe-secret-key=${AGENT_SECRET_KEY} \
            agent \
                --persistence-mode=filesystem --persistence-dir=/var/lib/flt/agent \
                --maybe-subscribe-loop-interval-seconds=99999 \
                --coordinator={{COORDINATOR_NODE_ID}} \
        \; \
        journalctl -f --unit flt-agent-dev.service --no-hostname -f -q -o cat


push-closure-to-sj-srv2 args="":
    #!/usr/bin/env bash
    set -xeE -o pipefail

    just run-admin disabled $(just coordinator-nodeid) enrollment-service assign-nixos-closure \
            --node-id $(just agent-nodeid) --path $(nix build --no-link --print-out-paths ~/src/steveej/infra#nixosConfigurations.sj-srv2.config.system.build.toplevel) {{args}}
