import Foundation
import os
import Testing
@testable import Tracexy

// MARK: - AsyncIngestGate

private actor AsyncIngestGate {
    // MARK: Internal

    func pause() async {
        entered = true
        entryWaiter?.resume()
        entryWaiter = nil
        if !released {
            await withCheckedContinuation { releaseWaiter = $0 }
        }
    }

    func waitForEntry() async {
        if !entered {
            await withCheckedContinuation { entryWaiter = $0 }
        }
    }

    func release() {
        released = true
        releaseWaiter?.resume()
        releaseWaiter = nil
    }

    // MARK: Private

    private var entered = false
    private var released = false
    private var entryWaiter: CheckedContinuation<Void, Never>?
    private var releaseWaiter: CheckedContinuation<Void, Never>?
}

// MARK: - MockCaptureHelperProxy

nonisolated private final class MockCaptureHelperProxy: NSObject, TracexyHelperProtocol, @unchecked Sendable {
    // MARK: Internal

    enum FetchBehavior: Sendable {
        case replyOffMain(FrameBatchMessage, signalReplied: @Sendable () -> Void)
        case neverReply
    }

    var fetchBehavior: FetchBehavior {
        get { state.withLock { $0.fetchBehavior } }
        set { state.withLock { $0.fetchBehavior = newValue } }
    }

    var stopBatch: FrameBatchMessage {
        get { state.withLock { $0.stopBatch } }
        set { state.withLock { $0.stopBatch = newValue } }
    }

    var fetchCallCount: Int {
        state.withLock { $0.fetchCallCount }
    }

    var stopCaptureCallCount: Int {
        state.withLock { $0.stopCaptureCallCount }
    }

    var lastFetchDeliveredOffMain: Bool? {
        state.withLock { $0.lastFetchDeliveredOffMain }
    }

    func getHelperInfo(withReply reply: @escaping (String, Int, Int) -> Void) {
        reply("2.5.0", 12, 6)
    }

    func prepareForExecutableRefresh(withReply reply: @escaping (Bool) -> Void) {
        reply(true)
    }

    func getExecutableIdentity(withReply reply: @escaping (String, String, Int32, String, Int, Int) -> Void) {
        reply("", "", 0, "2.5.0", 12, 6)
    }

    func startCapture(configuration _: CaptureConfiguration, withReply reply: @escaping (Bool, String) -> Void) {
        reply(true, "")
    }

    func stopCapture(withReply reply: @escaping (FrameBatchMessage) -> Void) {
        let batch = state.withLock { current -> FrameBatchMessage in
            current.stopCaptureCallCount += 1
            return current.stopBatch
        }
        replyQueue.async {
            reply(batch)
        }
    }

    func fetchFrames(withReply reply: @escaping (FrameBatchMessage) -> Void) {
        let behavior = state.withLock { current -> FetchBehavior in
            current.fetchCallCount += 1
            return current.fetchBehavior
        }
        switch behavior {
        case let .replyOffMain(batch, signalReplied):
            replyQueue.async { [weak self] in
                let offMain = !Thread.isMainThread
                self?.state.withLock { $0.lastFetchDeliveredOffMain = offMain }
                reply(batch)
                signalReplied()
            }
        case .neverReply:
            break
        }
    }

    // MARK: Private

    nonisolated private struct State: Sendable {
        var fetchBehavior: FetchBehavior = .neverReply
        var stopBatch = FrameBatchMessage(
            frames: [],
            bufferDroppedCount: 0,
            captureLinkType: LinkType.ethernet,
            stats: nil
        )
        var fetchCallCount = 0
        var stopCaptureCallCount = 0
        var lastFetchDeliveredOffMain: Bool?
    }

    private let replyQueue = DispatchQueue(label: "test.tracexy.mock-helper-xpc")
    private let state = OSAllocatedUnfairLock(initialState: State())
}

// MARK: - CaptureWatchdogAndDrainTests

@MainActor
@Suite("Helper poll watchdog decoupling, coalesced ingest, and failure tail drain")
struct CaptureWatchdogAndDrainTests {
    // MARK: Internal

    @Test("Default poll watchdog threshold is 12s and reply tracker isolates tokens off-main")
    func defaultWatchdogThresholdAndReplyTracker() async {
        let environment = ProjectIsolationEnvironment(name: "watchdog-defaults")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        #expect(HelperPollReplyTracker.defaultWatchdogNanoseconds == 12_000_000_000)
        #expect(coordinator.helperPollWatchdogNanoseconds == 12_000_000_000)

        let tracker = HelperPollReplyTracker()
        tracker.beginFetch(captureToken: 3, fetchToken: 7)
        #expect(!tracker.hasReplied(captureToken: 3, fetchToken: 7))

        // A stale reply from an older fetch or capture token must never satisfy the current fetch.
        await Task.detached {
            tracker.recordReply(captureToken: 3, fetchToken: 6)
            tracker.recordReply(captureToken: 2, fetchToken: 7)
        }.value
        #expect(!tracker.hasReplied(captureToken: 3, fetchToken: 7))

        await Task.detached {
            tracker.recordReply(captureToken: 3, fetchToken: 7)
        }.value
        #expect(tracker.hasReplied(captureToken: 3, fetchToken: 7))

        tracker.reset()
        #expect(!tracker.hasReplied(captureToken: 3, fetchToken: 7))
    }

    @Test("Fast off-main XPC reply survives MainActor contention past the watchdog deadline")
    func offMainXPCReplyPreventsFalseWatchdogKillUnderMainActorContention() async throws {
        let environment = ProjectIsolationEnvironment(name: "watchdog-mainactor-contention")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let captureToken = coordinator.startGeneration
        coordinator.resetSessionEngine(token: captureToken)
        await coordinator.ingestChain?.value

        let frame = try Self.makeTCPFrame(index: 1, payloadSeed: 0x41)
        let message = try Self.makeFrameMessage(from: frame)
        let batch = FrameBatchMessage(
            frames: [message],
            bufferDroppedCount: 0,
            captureLinkType: LinkType.ethernet,
            stats: HelperCaptureStats(received: 1, droppedByKernel: 0, droppedByInterface: 0)
        )

        let xpcReplySemaphore = DispatchSemaphore(value: 0)
        let proxy = MockCaptureHelperProxy()
        proxy.fetchBehavior = .replyOffMain(batch) {
            xpcReplySemaphore.signal()
        }
        coordinator.helperProxyOverride = { proxy }
        coordinator.helperPollWatchdogNanoseconds = 60_000_000 // 60 ms
        coordinator.isCapturing = true
        coordinator.captureStartedAt = Date()

        coordinator.pollHelper()
        // Wait for the off-main XPC callback to record its reply while we are still
        // occupying `@MainActor`, then hold `@MainActor` past the 60 ms watchdog window.
        let replyArrived = Self.holdMainActorPastWatchdog(
            waitingFor: xpcReplySemaphore,
            holdSeconds: 0.12
        )
        #expect(replyArrived)
        #expect(proxy.lastFetchDeliveredOffMain == true)

        // Let both the scheduled `@MainActor` frame continuation and the watchdog sleep run.
        try? await Task.sleep(nanoseconds: 90_000_000)
        await coordinator.ingestChain?.value

        #expect(coordinator.isCapturing)
        #expect(coordinator.captureError == nil)
        #expect(proxy.fetchCallCount == 1)
        #expect(proxy.stopCaptureCallCount == 0)

        let spooled = try await coordinator.liveCaptureSpool.capture()
        #expect(spooled.frames.map(\.bytes) == [frame.bytes])
        coordinator.isCapturing = false
    }

    @Test("Genuine XPC hang trips watchdog, stops helper, and drains all queued tail batches to UI and History")
    func genuineHelperHangFailsCaptureAndPublishesCompleteQueuedTail() async throws {
        let environment = ProjectIsolationEnvironment(name: "watchdog-genuine-hang-drain")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let proxy = MockCaptureHelperProxy()
        proxy.fetchBehavior = .neverReply
        coordinator.helperProxyOverride = { proxy }
        coordinator.helperPollWatchdogNanoseconds = 40_000_000 // 40 ms

        let captureToken = coordinator.startGeneration
        coordinator.resetSessionEngine(token: captureToken)
        await coordinator.ingestChain?.value

        coordinator.isCapturing = true
        coordinator.captureStartedAt = Date()
        coordinator.beginLiveHistoryLifetime(captureGeneration: captureToken)

        // Batch 0 publishes immediately (`shouldSnapshot == true` from distantPast), advancing
        // `lastSessionsUpdate` to `now` so rapid tail batches below have `shouldSnapshot == false`.
        let headFrame = try Self.makeTCPFrame(index: 0, payloadSeed: 0x10)
        coordinator.ingest([headFrame], linkType: LinkType.ethernet)
        await coordinator.ingestChain?.value
        await Task.yield()
        #expect(coordinator.presentedSessions.count == 1)

        // Gate `ingestChain` to simulate heavy disk/decode backlog while 5 tail batches queue up
        // with `shouldSnapshot == false` (the exact 105 MB / 417-session tail loss scenario).
        let gate = AsyncIngestGate()
        let previousChain = coordinator.ingestChain
        coordinator.ingestChain = Task.detached {
            await previousChain?.value
            await gate.pause()
        }
        await gate.waitForEntry()

        var tailFrames: [CapturedFrame] = []
        for index in 1 ... 5 {
            let frame = try Self.makeTCPFrame(index: index, payloadSeed: UInt8(0x20 + index))
            tailFrames.append(frame)
            coordinator.ingest([frame], linkType: LinkType.ethernet)
        }
        // Only the head session has been published so far; the 5 tail batches are still queued.
        #expect(coordinator.presentedSessions.count == 1)

        // Start a poll that never receives an XPC reply; let the watchdog fire while tail batches
        // are still parked behind `gate`.
        coordinator.pollHelper()
        try? await Task.sleep(nanoseconds: 90_000_000)

        #expect(!coordinator.isCapturing)
        #expect(proxy.stopCaptureCallCount == 1)
        #expect(
            coordinator.captureError
                == "The capture helper stopped responding while capture was active. Recover it in Settings → Helper."
        )
        #expect(coordinator.helper.status == .unreachable)
        // Final drain remains owed until the queued tail batches finish folding and publishing.
        #expect(coordinator.isFinalDrainPending)

        let drainTask = coordinator.ingestChain
        await gate.release()
        await drainTask?.value
        await coordinator.waitForHistory()

        let allExpectedFrames = [headFrame] + tailFrames
        let expectedSessions = SessionBuilder.build(from: allExpectedFrames, linkType: LinkType.ethernet)
        #expect(expectedSessions.count == 6)

        #expect(!coordinator.isFinalDrainPending)
        #expect(coordinator.stoppedCaptureReadyGeneration == coordinator.startGeneration)
        #expect(coordinator.presentedSessions.map(\.id) == expectedSessions.map(\.id))

        let presentedBytes = coordinator.presentedSessions.reduce(0) { $0 + $1.totalBytes }
        let expectedBytes = expectedSessions.reduce(0) { $0 + $1.totalBytes }
        #expect(presentedBytes == expectedBytes)

        let spooled = try await coordinator.liveCaptureSpool.capture()
        #expect(spooled.frames.map(\.bytes) == allExpectedFrames.map(\.bytes))

        #expect(coordinator.historyCaptures.count == 1)
        #expect(coordinator.historyCaptures.first?.record.completeness == .incomplete)
        if let captureID = coordinator.historyCaptures.first?.id {
            coordinator.selectHistoryCapture(captureID)
            await coordinator.waitForHistory()
            #expect(coordinator.historySessions.count == 6)
        }
    }

    @Test("Coalesced live ingest spawns one worker task and preserves order, locators, and per-batch loss")
    func coalescedLiveIngestPreservesOrderLocatorsAndPerBatchLoss() async throws {
        let environment = ProjectIsolationEnvironment(name: "coalesced-ingest-invariants")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let proxy = MockCaptureHelperProxy()
        coordinator.helperProxyOverride = { proxy }

        let captureToken = coordinator.startGeneration
        coordinator.resetSessionEngine(token: captureToken)
        await coordinator.ingestChain?.value

        let gate = AsyncIngestGate()
        coordinator.ingestChain = Task.detached {
            await gate.pause()
        }
        await gate.waitForEntry()

        coordinator.isCapturing = true
        coordinator.captureStartedAt = Date()

        var expectedFrames: [CapturedFrame] = []
        // First 10 batches arrive with clean kernel accounting (`noLossReported`).
        coordinator.captureStatistics = CaptureStatistics(received: 100, droppedByKernel: 0, droppedByInterface: 0)
        for index in 0 ..< 10 {
            let frame = try Self.makeTCPFrame(index: index, payloadSeed: UInt8(0x30 + index))
            expectedFrames.append(frame)
            coordinator.ingest([frame], linkType: LinkType.ethernet)
        }

        // Next 10 batches arrive after kernel drops appear (`lossReported`).
        coordinator.captureStatistics = CaptureStatistics(received: 200, droppedByKernel: 5, droppedByInterface: 0)
        for index in 10 ..< 20 {
            let frame = try Self.makeTCPFrame(index: index, payloadSeed: UInt8(0x30 + index))
            expectedFrames.append(frame)
            coordinator.ingest([frame], linkType: LinkType.ethernet)
        }

        // All 20 batches share a single off-main worker task rather than chaining 20 `@MainActor` tasks,
        // merging within each loss regime while keeping the `noLossReported` -> `lossReported` boundary exact.
        #expect(coordinator.liveIngestDrainTaskCount == 1)
        let metrics = try #require(coordinator.lastLiveIngestQueue?.metrics)
        #expect(metrics.enqueuedBatches == 20)
        #expect(metrics.coalescedMerges == 18)

        await gate.release()
        coordinator.failActiveHelperCapture("Synthetic stop after burst.")
        await coordinator.ingestChain?.value

        #expect(coordinator.presentedSessions.count == 20)
        let spooled = try await coordinator.liveCaptureSpool.capture()
        #expect(spooled.frames.map(\.bytes) == expectedFrames.map(\.bytes))

        let summaries = coordinator.connectionSnapshot.summaries
        #expect(summaries.count == 20)
        for index in 0 ..< 20 {
            let summary = summaries[index]
            #expect(summary.firstProvenance.ordinal == FrameOrdinal(UInt64(index + 1)))
            let expectedLoss: CaptureLossKnowledge = index < 10 ? .noLossReported : .lossReported
            #expect(summary.lossKnowledge == expectedLoss)

            let locator = try #require(summary.firstProvenance.locator)
            let readBytes = try await coordinator.liveCaptureSpool.read(
                locator,
                capturedLength: summary.firstProvenance.capturedLength,
                epoch: captureToken
            )
            #expect(readBytes == expectedFrames[index].bytes)
        }
    }

    @Test("Engine reset boundaries seal active coalescing queues without reordering pre- and post-clear batches")
    func clearBoundarySealsQueueWithoutReordering() async throws {
        let environment = ProjectIsolationEnvironment(name: "coalesced-clear-boundary")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let proxy = MockCaptureHelperProxy()
        coordinator.helperProxyOverride = { proxy }

        let initialToken = coordinator.startGeneration
        coordinator.resetSessionEngine(token: initialToken)
        await coordinator.ingestChain?.value

        let gate = AsyncIngestGate()
        coordinator.ingestChain = Task.detached {
            await gate.pause()
        }
        await gate.waitForEntry()

        coordinator.isCapturing = true
        coordinator.captureStartedAt = Date()

        let preClearA = try Self.makeTCPFrame(index: 1, payloadSeed: 0x61)
        let preClearB = try Self.makeTCPFrame(index: 2, payloadSeed: 0x62)
        coordinator.ingest([preClearA], linkType: LinkType.ethernet)
        coordinator.ingest([preClearB], linkType: LinkType.ethernet)

        // Clear while `isCapturing == true` seals the pre-clear queue, bumps `startGeneration`,
        // and chains `resetSessionEngine` strictly between pre-clear and post-clear batches.
        coordinator.clearSessions()

        let postClearA = try Self.makeTCPFrame(index: 101, payloadSeed: 0x71)
        let postClearB = try Self.makeTCPFrame(index: 102, payloadSeed: 0x72)
        coordinator.ingest([postClearA], linkType: LinkType.ethernet)
        coordinator.ingest([postClearB], linkType: LinkType.ethernet)

        await gate.release()
        coordinator.failActiveHelperCapture("Stop after clear boundary.")
        await coordinator.ingestChain?.value

        let expectedPostClear = SessionBuilder.build(
            from: [postClearA, postClearB],
            linkType: LinkType.ethernet
        )
        #expect(coordinator.presentedSessions.map(\.id) == expectedPostClear.map(\.id))

        let spooled = try await coordinator.liveCaptureSpool.capture()
        #expect(spooled.frames.map(\.bytes) == [postClearA.bytes, postClearB.bytes])
    }

    @Test("Source failure and final helper stop batch order strictly after coalesced live batches")
    func sourceFailureOrdersFinalHelperBatchAfterCoalescedLiveBatches() async throws {
        let environment = ProjectIsolationEnvironment(name: "coalesced-source-failure-order")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let frame1 = try Self.makeTCPFrame(index: 1, payloadSeed: 0x81)
        let frame2 = try Self.makeTCPFrame(index: 2, payloadSeed: 0x82)
        let frame3 = try Self.makeTCPFrame(index: 3, payloadSeed: 0x83)
        let finalStopFrame = try Self.makeTCPFrame(index: 4, payloadSeed: 0x84)

        let proxy = MockCaptureHelperProxy()
        proxy.stopBatch = FrameBatchMessage(
            frames: [try Self.makeFrameMessage(from: finalStopFrame)],
            bufferDroppedCount: 0,
            captureLinkType: LinkType.ethernet,
            stats: HelperCaptureStats(received: 4, droppedByKernel: 0, droppedByInterface: 0)
        )
        coordinator.helperProxyOverride = { proxy }

        let captureToken = coordinator.startGeneration
        coordinator.resetSessionEngine(token: captureToken)
        await coordinator.ingestChain?.value

        let gate = AsyncIngestGate()
        coordinator.ingestChain = Task.detached {
            await gate.pause()
        }
        await gate.waitForEntry()

        coordinator.isCapturing = true
        coordinator.captureStartedAt = Date()
        coordinator.beginLiveHistoryLifetime(captureGeneration: captureToken)

        coordinator.ingest([frame1], linkType: LinkType.ethernet)
        coordinator.ingest([frame2], linkType: LinkType.ethernet)
        coordinator.ingest([frame3], linkType: LinkType.ethernet)
        #expect(coordinator.liveIngestDrainTaskCount == 1)

        // Trigger source read failure while the 3 live batches are still gated;
        // `performStopCapture()` requests the helper's atomic final batch (`finalStopFrame`),
        // which must fold strictly AFTER `frame1`, `frame2`, and `frame3`.
        let drainOp = coordinator.beginFinalCaptureDrain(stoppedToken: nil, captureToken: captureToken)
        coordinator.captureSourceDidFail("en0: Interface detached", captureToken: captureToken)
        await gate.release()

        let drained = await coordinator.waitForFinalCaptureDrain(timeout: .seconds(5), operationID: drainOp)
        #expect(drained)
        await coordinator.ingestChain?.value

        let expectedFrames = [frame1, frame2, frame3, finalStopFrame]
        let expectedSessions = SessionBuilder.build(from: expectedFrames, linkType: LinkType.ethernet)
        #expect(coordinator.presentedSessions.map(\.id) == expectedSessions.map(\.id))

        let spooled = try await coordinator.liveCaptureSpool.capture()
        #expect(spooled.frames.map(\.bytes) == expectedFrames.map(\.bytes))
        #expect(coordinator.captureError == "Capture ended because the source stopped: en0: Interface detached")
    }

    @Test("LiveIngestBatchQueue caps coalesced step size at maxCoalescedFramesPerStep while preserving FIFO order")
    func liveIngestBatchQueueCapsStepSizeAndPreservesFIFO() async throws {
        let environment = ProjectIsolationEnvironment(name: "queue-step-cap")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let sampleFrame = try Self.makeTCPFrame(index: 1, payloadSeed: 0x91)
        let cap = LiveIngestBatchQueue.maxCoalescedFramesPerStep
        let halfCap = cap / 2
        let spool = coordinator.liveCaptureSpool

        let batchA = PendingLiveIngestBatch(
            frames: Array(repeating: sampleFrame, count: halfCap),
            linkType: LinkType.ethernet,
            epoch: 1,
            loss: .noLossReported,
            shouldSnapshot: false,
            spool: spool
        )
        let batchB = PendingLiveIngestBatch(
            frames: Array(repeating: sampleFrame, count: halfCap),
            linkType: LinkType.ethernet,
            epoch: 1,
            loss: .noLossReported,
            shouldSnapshot: true,
            spool: spool
        )
        let batchOverflow = PendingLiveIngestBatch(
            frames: [sampleFrame],
            linkType: LinkType.ethernet,
            epoch: 1,
            loss: .noLossReported,
            shouldSnapshot: false,
            spool: spool
        )

        let queue = LiveIngestBatchQueue(firstBatch: batchA)
        #expect(queue.tryAppend(batchB))
        #expect(queue.tryAppend(batchOverflow))
        #expect(queue.metrics.enqueuedBatches == 3)
        #expect(queue.metrics.coalescedMerges == 1)

        let firstPopped = try #require(queue.dequeueNextOrClose())
        #expect(firstPopped.frames.count == cap)
        #expect(firstPopped.shouldSnapshot)

        let secondPopped = try #require(queue.dequeueNextOrClose())
        #expect(secondPopped.frames.count == 1)
        #expect(!secondPopped.shouldSnapshot)

        #expect(queue.dequeueNextOrClose() == nil)
        // Once closed by reaching empty, further appends return false so the caller starts a new worker.
        #expect(!queue.tryAppend(batchOverflow))
    }

    // MARK: Private

    private static let baseEpoch = Date(timeIntervalSince1970: 1_700_100_000)

    private static func makeTCPFrame(index: Int, payloadSeed: UInt8) throws -> CapturedFrame {
        let payload = Array(repeating: payloadSeed, count: 64 + (index % 32))
        let rawPayloadFrame = CapturedFrame(
            bytes: payload,
            timestamp: baseEpoch.addingTimeInterval(Double(index) * 0.01),
            originalLength: payload.count,
            linkType: LinkType.ethernet,
            direction: .outbound
        )
        let wrapped = try SyntheticTCPPacketBuilder.wrap(
            [rawPayloadFrame],
            options: .init(
                sourceAddress: "198.51.100.10",
                destinationAddress: "203.0.113.50",
                sourcePort: 40_000 + index,
                destinationPort: 443,
                ipv6: false
            ),
            linkType: LinkType.ethernet,
            maxFrameBytes: 65_535,
            maxTotalFrameBytes: 65_535
        )
        return try #require(wrapped.first)
    }

    private static func holdMainActorPastWatchdog(
        waitingFor semaphore: DispatchSemaphore,
        holdSeconds: TimeInterval
    )
        -> Bool
    {
        guard semaphore.wait(timeout: .now() + .seconds(2)) == .success else {
            return false
        }
        Thread.sleep(forTimeInterval: holdSeconds)
        return true
    }

    private static func makeFrameMessage(from frame: CapturedFrame) throws -> CapturedFrameMessage {
        let timestamp = try #require(frame.timestamp)
        let totalMicroseconds = try CaptureTimestampEncoding.microseconds(timestamp)
        let seconds = Int64(totalMicroseconds / 1_000_000)
        let microseconds = Int64(totalMicroseconds % 1_000_000)
        return CapturedFrameMessage(
            bytes: Data(frame.bytes),
            timestampSeconds: seconds,
            timestampMicroseconds: microseconds,
            capturedLength: Int64(frame.capturedLength),
            originalLength: Int64(frame.originalLength),
            linkType: frame.linkType ?? LinkType.ethernet
        )
    }
}
