import Foundation
import os

// MARK: - HelperPollReplyTracker

/// Records helper XPC `fetchFrames` replies immediately on the XPC delivery queue
/// before hopping to `@MainActor`.
///
/// Under heavy 100+ MiB/s traffic, `@MainActor` scheduling and SwiftUI layout can
/// delay a `@MainActor` continuation by several seconds even though the helper XPC
/// replied in milliseconds. Recording the reply off-main prevents the poll watchdog
/// from mistaking `@MainActor` UI contention for a wedged capture helper.
nonisolated final class HelperPollReplyTracker: Sendable {
    // MARK: Internal

    /// Active-capture XPC non-response threshold (12s) before a helper drain call
    /// is treated as genuinely wedged.
    static let defaultWatchdogNanoseconds: UInt64 = 12_000_000_000

    func beginFetch(captureToken: Int, fetchToken: Int) {
        state.withLock { current in
            current = State(captureToken: captureToken, fetchToken: fetchToken, hasReplied: false)
        }
    }

    func recordReply(captureToken: Int, fetchToken: Int) {
        state.withLock { current in
            guard current.captureToken == captureToken,
                  current.fetchToken == fetchToken else
            {
                return
            }
            current.hasReplied = true
        }
    }

    func hasReplied(captureToken: Int, fetchToken: Int) -> Bool {
        state.withLock { current in
            current.captureToken == captureToken
                && current.fetchToken == fetchToken
                && current.hasReplied
        }
    }

    func reset() {
        state.withLock { current in
            current = State()
        }
    }

    // MARK: Private

    nonisolated private struct State: Sendable {
        var captureToken = 0
        var fetchToken = 0
        var hasReplied = false
    }

    private let state = OSAllocatedUnfairLock(initialState: State())
}

// MARK: - PendingLiveIngestBatch

/// One live batch (or coalesced run of compatible adjacent batches) awaiting off-main
/// spool persistence and incremental session folding.
nonisolated struct PendingLiveIngestBatch: Sendable {
    // MARK: Lifecycle

    init(
        frames: [CapturedFrame],
        linkType: UInt32,
        epoch: Int,
        loss: CaptureLossKnowledge,
        shouldSnapshot: Bool,
        spool: LiveCaptureSpool
    ) {
        self.frames = frames
        self.linkType = linkType
        self.epoch = epoch
        self.loss = loss
        self.shouldSnapshot = shouldSnapshot
        self.spool = spool
        allFramesTimed = frames.allSatisfy { $0.timestamp != nil }
    }

    // MARK: Internal

    var frames: [CapturedFrame]
    let linkType: UInt32
    let epoch: Int
    let loss: CaptureLossKnowledge
    var shouldSnapshot: Bool
    let spool: LiveCaptureSpool
    let allFramesTimed: Bool
}

// MARK: - LiveIngestBatchQueue

/// Bounded, lock-protected FIFO coalescing queue drained by a single off-`@MainActor`
/// worker task instead of chaining unbounded per-350ms `@MainActor` `Task` closures.
///
/// Every frame is spooled and folded in exact arrival order with its exact
/// `(linkType, epoch, loss)` and 1-to-1 `SessionEvidenceLocator` alignment. Adjacent
/// queued batches sharing `(epoch, linkType, loss, spool)` with valid frame timestamps
/// coalesce in place up to ``maxCoalescedFramesPerStep``, avoiding redundant actor hops
/// and publishing only the latest coalesced snapshot when `shouldSnapshot` holds.
nonisolated final class LiveIngestBatchQueue: Sendable {
    // MARK: Lifecycle

    init(firstBatch: PendingLiveIngestBatch) {
        state = OSAllocatedUnfairLock(initialState: State(pending: [firstBatch]))
    }

    // MARK: Internal

    /// Upper bound on frames merged into a single queued batch so individual
    /// `spool.append` and `engine.ingest` turns stay bounded in memory.
    static let maxCoalescedFramesPerStep = 16_384

    /// Telemetry for deterministic backpressure tests: `(enqueuedBatches, coalescedMerges)`.
    var metrics: (enqueuedBatches: Int, coalescedMerges: Int) {
        state.withLock { current in
            (current.enqueuedBatchCount, current.coalescedMergeCount)
        }
    }

    /// Append `batch` if this queue is still accepting live batches. Returns `false`
    /// once sealed by a boundary or closed by the worker reaching empty, instructing
    /// the caller to start a new drain task ordered after `ingestChain`.
    func tryAppend(_ batch: PendingLiveIngestBatch) -> Bool {
        state.withLock { current in
            guard !current.closedForAppends else {
                return false
            }
            current.enqueuedBatchCount += 1
            if current.headIndex < current.pending.count {
                let tailIndex = current.pending.count - 1
                if var tail = current.pending[tailIndex],
                   tail.epoch == batch.epoch,
                   tail.linkType == batch.linkType,
                   tail.loss == batch.loss,
                   tail.spool === batch.spool,
                   tail.allFramesTimed,
                   batch.allFramesTimed,
                   tail.frames.count + batch.frames.count <= Self.maxCoalescedFramesPerStep
                {
                    current.pending[tailIndex] = nil
                    tail.frames.append(contentsOf: batch.frames)
                    tail.shouldSnapshot = tail.shouldSnapshot || batch.shouldSnapshot
                    current.pending[tailIndex] = tail
                    current.coalescedMergeCount += 1
                    return true
                }
            }
            current.pending.append(batch)
            return true
        }
    }

    /// Seal this queue against *new* appends when a reset, stop drain, or file-set
    /// boundary chains onto `ingestChain`, while leaving all already-accepted batches
    /// intact for the running worker to finish draining in order.
    func sealForBoundary() {
        state.withLock { current in
            current.closedForAppends = true
        }
    }

    /// Pop the next batch in exact arrival order, releasing its buffer slot immediately,
    /// or atomically close the queue when all accepted batches have been drained.
    func dequeueNextOrClose() -> PendingLiveIngestBatch? {
        state.withLock { current in
            guard current.headIndex < current.pending.count else {
                current.pending.removeAll(keepingCapacity: false)
                current.headIndex = 0
                current.closedForAppends = true
                return nil
            }
            let next = current.pending[current.headIndex]
            current.pending[current.headIndex] = nil
            current.headIndex += 1
            if current.headIndex >= 32, current.headIndex * 2 >= current.pending.count {
                current.pending.removeFirst(current.headIndex)
                current.headIndex = 0
            }
            return next
        }
    }

    // MARK: Private

    nonisolated private struct State: Sendable {
        var pending: [PendingLiveIngestBatch?]
        var headIndex = 0
        var closedForAppends = false
        var enqueuedBatchCount = 1
        var coalescedMergeCount = 0
    }

    private let state: OSAllocatedUnfairLock<State>
}
