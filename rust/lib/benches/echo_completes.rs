use criterion::{criterion_group, criterion_main, Criterion};
use flt_lib::{
    protocols::echo_hash::{tests::run_echo_hash_with_context, SendMode},
    test_utils::RelayedTestContext,
};

fn echo_completes_bench_config() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .warm_up_time(std::time::Duration::from_secs(10))
}

fn echo_completes_bench(c: &mut Criterion) {
    let modes = vec![
        SendMode::Native,
        SendMode::Rpc,
        SendMode::RpcStream,
        SendMode::Docs,
    ];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let ctx = rt.block_on(RelayedTestContext::new());

    for mode in modes {
        c.bench_function(&format!("echo_completes_{:?}", mode), |b| {
            b.to_async(&rt).iter(|| async {
                #[allow(clippy::unit_arg)]
                std::hint::black_box(
                    run_echo_hash_with_context(
                        &ctx,
                        mode.clone(),
                        2,
                        flt_lib::protocols::echo_hash::rpc::EchoHashRpcApi::MAX_CHUNK_SIZE + 1,
                        10.0,
                    )
                    .await,
                );
            });
        });
    }
}

criterion_group!(
    name = benches;
    config = echo_completes_bench_config();
    targets = echo_completes_bench
);
criterion_main!(benches);
