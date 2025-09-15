run-coordinator +args="":
    #!/usr/bin/env bash
    RUST_LOG=app=trace,lib=trace cargo run -- \
        --maybe-secret-key=./fixtures/coordinator.ed25519 coordinator \
        {{args}}

run-admin +args="":
    #!/usr/bin/env bash
    RUST_LOG=app=trace,lib=trace cargo run -- \
        --maybe-secret-key=./fixtures/admin.ed25519 admin \
        {{args}}

run-admin-echo +args="-n100":
    just run-admin echo ba48d5a18a06a0348511b83ef8e8b900ea653c43086e55613344cdd8192f7f6c \
        {{args}}
