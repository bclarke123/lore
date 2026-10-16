use std::future::Future;
use std::pin::pin;

use tokio::sync::mpsc;

/// Drain a streaming producer into a `Vec` alongside a summary value for
/// callers that do not benefit from streaming.
///
/// The producer takes an `mpsc::Sender` and emits `Ok(T)` items as it goes,
/// returning `Ok(S)` on success (where `S` is some summary or metadata
/// value — use `()` when there is none) or `Err(E)` on failure. Runs the
/// producer concurrently with a receive loop in the same task via
/// `tokio::select!`, so there is no `tokio::spawn` and no `JoinError`.
/// When the producer completes first, the loop drains any remaining
/// buffered items before returning.
///
/// Returns `Ok((S, Vec<T>))` — the summary first, then every item the
/// producer emitted. First error wins: a producer error or an `Err(E)`
/// item short-circuits the drain and propagates up.
///
/// A producer that outlives the channel is awaited outside the `select!`, and
/// the items left once the producer finishes are drained after the loop, so the
/// loop holds no received item and only the drain holds the summary.
pub async fn collect_stream_with_summary<T, S, E, Fut>(
    f: impl FnOnce(mpsc::Sender<Result<T, E>>) -> Fut,
) -> Result<(S, Vec<T>), E>
where
    Fut: Future<Output = Result<S, E>>,
{
    let (tx, mut rx) = mpsc::channel(256);
    let mut driver = pin!(f(tx));
    let mut out = Vec::new();
    let summary = loop {
        let closed = tokio::select! {
            biased;
            item = rx.recv() => match item {
                Some(item) => {
                    out.push(item?);
                    false
                }
                None => true,
            },
            result = &mut driver => break result?,
        };
        if closed {
            break (&mut driver).await?;
        }
    };
    while let Some(item) = rx.recv().await {
        out.push(item?);
    }
    Ok((summary, out))
}
