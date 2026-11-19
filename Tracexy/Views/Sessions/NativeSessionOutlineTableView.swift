import AppKit
import Foundation
import SwiftUI

// MARK: - SessionOutlineNode

/// Stable reference-type wrapper around a `SessionOutlineRowModel` so
/// `NSOutlineView` preserves object identity, selection, and expansion state
/// across incremental live refreshes.
final class SessionOutlineNode: NSObject {
    let id: UUID
    var model: SessionOutlineRowModel
    var children: [SessionOutlineNode]
    weak var parent: SessionOutlineNode?

    init(model: SessionOutlineRowModel, parent: SessionOutlineNode? = nil) {
        id = model.id
        self.model = model
        self.parent = parent
        children = []
        super.init()
        children = model.children.map { SessionOutlineNode(model: $0, parent: self) }
    }
}

// MARK: - Pure AppKit Cell Views (Zero NSHostingView)

@MainActor
func measureSingleLineTextField(_ field: NSTextField) -> NSSize {
    field.cell?.cellSize(forBounds: NSRect(x: 0, y: 0, width: 10_000, height: 100)) ?? field.intrinsicContentSize
}

private protocol SessionOutlineConfigurableCell: AnyObject {
    func configure(with model: SessionOutlineRowModel, column: SessionOutlineColumnID)
}

final class SessionPillView: NSView {
    // MARK: Lifecycle

    init(font: NSFont, horizontalPadding: CGFloat = 6, verticalPadding: CGFloat = 1.5) {
        self.horizontalPadding = horizontalPadding
        self.verticalPadding = verticalPadding
        super.init(frame: .zero)
        wantsLayer = true
        label.font = font
        label.lineBreakMode = .byTruncatingTail
        label.maximumNumberOfLines = 1
        label.usesSingleLineMode = true
        label.alignment = .center
        addSubview(label)
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    // MARK: Internal

    let label = NSTextField(labelWithString: "")

    func configure(text: String, textColor: NSColor, fillColor: NSColor, font: NSFont? = nil) {
        if let font {
            label.font = font
        }
        label.stringValue = text
        label.textColor = textColor
        currentFillColor = fillColor
        applyFillColor()
        label.invalidateIntrinsicContentSize()
        invalidateIntrinsicContentSize()
        needsLayout = true
    }

    override var intrinsicContentSize: NSSize {
        let textSize = measureSingleLineTextField(label)
        return NSSize(
            width: ceil(textSize.width) + horizontalPadding * 2 + 2,
            height: ceil(textSize.height) + verticalPadding * 2
        )
    }

    override func layout() {
        super.layout()
        layer?.cornerRadius = bounds.height * 0.5
        let textSize = measureSingleLineTextField(label)
        let textHeight = min(bounds.height, ceil(textSize.height))
        let textWidth = max(0, bounds.width - horizontalPadding * 2 + 2)
        label.frame = NSRect(
            x: horizontalPadding - 1,
            y: floor((bounds.height - textHeight) * 0.5),
            width: textWidth,
            height: textHeight
        )
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        applyFillColor()
    }

    // MARK: Private

    private let horizontalPadding: CGFloat
    private let verticalPadding: CGFloat
    private var currentFillColor: NSColor = .clear

    private func applyFillColor() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            layer?.backgroundColor = currentFillColor.cgColor
        }
    }
}

private final class SessionTagDotsView: NSView {
    // MARK: Internal

    var tags: [SessionTag] = [] {
        didSet {
            guard oldValue != tags else {
                return
            }
            if tags.isEmpty {
                toolTip = nil
                setAccessibilityLabel(nil)
            } else {
                let joined = ListFormatter.localizedString(byJoining: tags.map(\.title))
                toolTip = joined
                setAccessibilityLabel("Tagged \(joined)")
            }
            needsDisplay = true
        }
    }

    var preferredWidth: CGFloat {
        guard !tags.isEmpty else {
            return 0
        }
        return CGFloat(8 + max(0, tags.count - 1) * 5)
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard !tags.isEmpty else {
            return
        }
        let dotDiameter: CGFloat = 8
        let y = floor((bounds.height - dotDiameter) * 0.5)
        let strokeColor = NSColor.windowBackgroundColor
        for (index, tag) in tags.enumerated() {
            let x = CGFloat(index * 5)
            let dotRect = NSRect(x: x, y: y, width: dotDiameter, height: dotDiameter)
            let circle = NSBezierPath(ovalIn: dotRect.insetBy(dx: 0.5, dy: 0.5))
            SessionOutlineStyle.color(for: tag).setFill()
            circle.fill()
            circle.lineWidth = 1
            strokeColor.setStroke()
            circle.stroke()
        }
    }
}

private final class SessionTextCellView: NSTableCellView, SessionOutlineConfigurableCell {
    // MARK: Lifecycle

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        label.lineBreakMode = .byTruncatingTail
        label.maximumNumberOfLines = 1
        label.usesSingleLineMode = true
        label.drawsBackground = false
        label.isBezeled = false
        label.isEditable = false
        label.isSelectable = false
        addSubview(label)
        textField = label
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    // MARK: Internal

    func configure(with model: SessionOutlineRowModel, column: SessionOutlineColumnID) {
        switch column {
        case .time:
            label.font = SessionOutlineStyle.monoSmallFont
            label.stringValue = model.timeText
            label.textColor = model.isUntimed ? .tertiaryLabelColor : .secondaryLabelColor
            toolTip = model.timeTooltip
            setAccessibilityLabel(nil)

        case .source:
            label.font = SessionOutlineStyle.monoFont
            label.stringValue = model.sourceEndpoint
            label.textColor = .labelColor
            toolTip = model.sourceEndpoint
            setAccessibilityLabel(nil)

        case .destination:
            label.font = SessionOutlineStyle.monoFont
            label.stringValue = model.destinationEndpoint
            label.textColor = .labelColor
            toolTip = model.destinationEndpoint
            setAccessibilityLabel(nil)

        case .length:
            label.font = SessionOutlineStyle.monoSmallFont
            label.stringValue = model.lengthText
            label.textColor = .secondaryLabelColor
            toolTip = nil
            setAccessibilityLabel(nil)

        case .latency:
            label.font = SessionOutlineStyle.monoSmallFont
            label.stringValue = model.latencyText
            label.textColor = .secondaryLabelColor
            toolTip = nil
            setAccessibilityLabel(nil)

        case .summary:
            label.font = SessionOutlineStyle.bodyFont
            label.stringValue = model.summary
            label.textColor = model.status == .error ? .systemRed : .labelColor
            toolTip = model.summary
            setAccessibilityLabel(nil)

        case .serverName:
            label.font = SessionOutlineStyle.monoFont
            label.stringValue = model.sni ?? "—"
            label.textColor = model.sni == nil ? .tertiaryLabelColor : .labelColor
            toolTip = model.sni
            setAccessibilityLabel(nil)

        case .duration:
            label.font = SessionOutlineStyle.monoSmallFont
            label.stringValue = model.durationText.isEmpty ? "—" : model.durationText
            label.textColor = .secondaryLabelColor
            toolTip = nil
            setAccessibilityLabel(nil)

        case .bytesUp:
            label.font = SessionOutlineStyle.monoSmallFont
            label.stringValue = model.bytesUpText
            label.textColor = .secondaryLabelColor
            toolTip = nil
            setAccessibilityLabel(nil)

        case .bytesDown:
            label.font = SessionOutlineStyle.monoSmallFont
            label.stringValue = model.bytesDownText
            label.textColor = .secondaryLabelColor
            toolTip = nil
            setAccessibilityLabel(nil)

        case .protocolStack:
            label.font = SessionOutlineStyle.monoSmallFont
            label.stringValue = model.protocolStackText
            label.textColor = .secondaryLabelColor
            toolTip = model.protocolStackText.isEmpty ? nil : model.protocolStackText
            setAccessibilityLabel(nil)

        case .tcpCompleteness:
            label.font = SessionOutlineStyle.monoSmallFont
            if let stage = model.tcpCompletenessStage {
                label.stringValue = stage
                label.textColor = model.tcpCompletenessIsComplete ? .labelColor : .secondaryLabelColor
                toolTip = model.tcpCompletenessHelp
                setAccessibilityLabel(model.tcpCompletenessLabel)
            } else {
                label.stringValue = "—"
                label.textColor = .tertiaryLabelColor
                toolTip = nil
                setAccessibilityLabel(nil)
            }

        case .host,
             .client,
             .protocolKind,
             .status,
             .timeline:
            break
        }
        needsLayout = true
    }

    override func layout() {
        super.layout()
        let textHeight = min(bounds.height, ceil(measureSingleLineTextField(label).height))
        label.frame = NSRect(
            x: 0,
            y: floor((bounds.height - textHeight) * 0.5),
            width: bounds.width,
            height: textHeight
        )
    }

    // MARK: Private

    private let label = NSTextField(labelWithString: "")
}

final class SessionHostCellView: NSTableCellView, SessionOutlineConfigurableCell {
    // MARK: Lifecycle

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        primaryLabel.font = SessionOutlineStyle.bodyFont
        primaryLabel.maximumNumberOfLines = 1
        primaryLabel.usesSingleLineMode = true
        primaryLabel.drawsBackground = false

        evidenceLabel.font = SessionOutlineStyle.microFont
        evidenceLabel.lineBreakMode = .byTruncatingTail
        evidenceLabel.maximumNumberOfLines = 1
        evidenceLabel.usesSingleLineMode = true
        evidenceLabel.drawsBackground = false

        leadingIconView.imageScaling = .scaleProportionallyDown
        trailingIconView.imageScaling = .scaleProportionallyDown

        addSubview(tagDotsView)
        addSubview(leadingIconView)
        addSubview(primaryLabel)
        addSubview(firstPillView)
        addSubview(secondPillView)
        addSubview(trailingIconView)
        addSubview(evidenceLabel)
        textField = primaryLabel
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    // MARK: Internal

    let primaryLabel = NSTextField(labelWithString: "")
    let firstPillView = SessionPillView(font: SessionOutlineStyle.microFont, horizontalPadding: 5, verticalPadding: 1)
    let secondPillView = SessionPillView(font: SessionOutlineStyle.badgeFont, horizontalPadding: 5, verticalPadding: 1)

    func configure(with model: SessionOutlineRowModel, column _: SessionOutlineColumnID) {
        currentKind = model.kind
        switch model.kind {
        case let .session(hostData):
            tagDotsView.tags = hostData.tags
            tagDotsView.isHidden = hostData.tags.isEmpty
            leadingIconView.isHidden = true

            primaryLabel.stringValue = hostData.displayHost
            primaryLabel.textColor = .labelColor
            primaryLabel.lineBreakMode = .byTruncatingTail

            if let badgeTitle = hostData.localDiscoveryBadgeTitle {
                firstPillView.isHidden = false
                firstPillView.configure(
                    text: badgeTitle,
                    textColor: .secondaryLabelColor,
                    fillColor: NSColor.secondaryLabelColor.withAlphaComponent(0.12),
                    font: SessionOutlineStyle.microFont
                )
            } else {
                firstPillView.isHidden = true
            }
            secondPillView.isHidden = true

            if hostData.hasNote {
                trailingIconView.isHidden = false
                trailingIconView.image = SessionOutlineIconCache.smallSymbol(
                    named: "note.text",
                    color: .secondaryLabelColor,
                    colorKey: "secondary"
                )
                trailingIconView.toolTip = String(
                    localized: "You wrote a note about this session",
                    bundle: AppLanguage.currentLocalizedBundle()
                )
                trailingIconView.setAccessibilityLabel("Has a note")
            } else {
                trailingIconView.isHidden = true
                trailingIconView.toolTip = nil
            }
            evidenceLabel.isHidden = true
            toolTip = hostData.tooltip

        case let .action(actionData):
            tagDotsView.tags = []
            tagDotsView.isHidden = true
            leadingIconView.isHidden = true

            primaryLabel.stringValue = actionData.title
            primaryLabel.textColor = .labelColor
            primaryLabel.lineBreakMode = .byTruncatingMiddle

            let countLabel = String(
                localized: "\(actionData.sessionCount) sessions",
                bundle: AppLanguage.currentLocalizedBundle()
            )
            firstPillView.isHidden = false
            firstPillView.configure(
                text: countLabel,
                textColor: .secondaryLabelColor,
                fillColor: NSColor.secondaryLabelColor.withAlphaComponent(0.14),
                font: SessionOutlineStyle.badgeFont
            )

            let confidenceColor = SessionOutlineStyle.color(for: actionData.confidence)
            secondPillView.isHidden = false
            secondPillView.configure(
                text: actionData.confidenceTitle,
                textColor: confidenceColor,
                fillColor: confidenceColor.withAlphaComponent(0.16),
                font: SessionOutlineStyle.badgeFont
            )

            if actionData.isContested {
                trailingIconView.isHidden = false
                trailingIconView.image = SessionOutlineIconCache.smallSymbol(
                    named: "questionmark.circle",
                    color: .systemOrange,
                    colorKey: "orange"
                )
                trailingIconView.toolTip = actionData.evidenceLine
            } else {
                trailingIconView.isHidden = true
                trailingIconView.toolTip = nil
            }

            evidenceLabel.isHidden = false
            evidenceLabel.stringValue = actionData.evidenceLine
            evidenceLabel.textColor = actionData.isContested ? .systemOrange : confidenceColor
            toolTip = actionData.evidenceLine

        case let .group(groupData):
            tagDotsView.tags = []
            tagDotsView.isHidden = true

            leadingIconView.isHidden = false
            leadingIconView.image = SessionOutlineIconCache.smallSymbol(
                named: groupData.groupKind == .host ? "globe" : "app.badge",
                color: .secondaryLabelColor,
                colorKey: "secondary"
            )

            primaryLabel.stringValue = groupData.title
            primaryLabel.textColor = .labelColor
            primaryLabel.lineBreakMode = .byTruncatingMiddle

            firstPillView.isHidden = false
            firstPillView.configure(
                text: "\(groupData.sessionCount)",
                textColor: .secondaryLabelColor,
                fillColor: NSColor.secondaryLabelColor.withAlphaComponent(0.14),
                font: SessionOutlineStyle.badgeFont
            )
            secondPillView.isHidden = true
            trailingIconView.isHidden = true
            evidenceLabel.isHidden = true
            toolTip = groupData.title
        }
        needsLayout = true
    }

    override func layout() {
        super.layout()
        guard let kind = currentKind else {
            return
        }
        switch kind {
        case .action:
            layoutActionRow()
        case .session,
             .group:
            layoutSingleLineRow()
        }
    }

    // MARK: Private

    private let tagDotsView = SessionTagDotsView()
    private let leadingIconView = NSImageView()
    private let trailingIconView = NSImageView()
    private let evidenceLabel = NSTextField(labelWithString: "")
    private var currentKind: SessionOutlineRowKind?

    private func layoutSingleLineRow() {
        let spacing: CGFloat = 5
        var x: CGFloat = 0
        let height = bounds.height

        if !tagDotsView.isHidden {
            let dotsWidth = tagDotsView.preferredWidth
            tagDotsView.frame = NSRect(x: x, y: 0, width: dotsWidth, height: height)
            x += dotsWidth + spacing
        }

        if !leadingIconView.isHidden {
            let iconDim: CGFloat = 12
            leadingIconView.frame = NSRect(
                x: x,
                y: floor((height - iconDim) * 0.5),
                width: iconDim,
                height: iconDim
            )
            x += iconDim + spacing
        }

        var trailingReserved: CGFloat = 0
        let iconDim: CGFloat = 12
        if !trailingIconView.isHidden {
            trailingReserved += iconDim + spacing
        }
        let pillSize = firstPillView.isHidden ? .zero : firstPillView.intrinsicContentSize
        if !firstPillView.isHidden {
            trailingReserved += pillSize.width + spacing
        }

        let labelSize = measureSingleLineTextField(primaryLabel)
        let availableForLabel = max(0, bounds.width - x - trailingReserved)
        let labelWidth = min(ceil(labelSize.width), availableForLabel)
        let labelHeight = min(height, ceil(labelSize.height))
        primaryLabel.frame = NSRect(
            x: x,
            y: floor((height - labelHeight) * 0.5),
            width: labelWidth,
            height: labelHeight
        )
        x += labelWidth

        if !firstPillView.isHidden {
            x += spacing
            let pillHeight = min(height - 2, pillSize.height)
            firstPillView.frame = NSRect(
                x: x,
                y: floor((height - pillHeight) * 0.5),
                width: min(pillSize.width, max(0, bounds.width - x)),
                height: pillHeight
            )
            x += pillSize.width
        }

        if !trailingIconView.isHidden {
            x += spacing
            trailingIconView.frame = NSRect(
                x: x,
                y: floor((height - iconDim) * 0.5),
                width: iconDim,
                height: iconDim
            )
        }
    }

    private func layoutActionRow() {
        let spacing: CGFloat = 5
        let topLineHeight: CGFloat = 19
        let bottomLineHeight: CGFloat = 13
        let topY = bounds.height - topLineHeight - 1
        let bottomY: CGFloat = 2

        let countSize = firstPillView.intrinsicContentSize
        let confSize = secondPillView.intrinsicContentSize
        let iconDim: CGFloat = 12
        var trailingReserved = countSize.width + spacing + confSize.width + spacing
        if !trailingIconView.isHidden {
            trailingReserved += iconDim + spacing
        }

        let labelSize = measureSingleLineTextField(primaryLabel)
        let availableTitleWidth = max(24, bounds.width - trailingReserved)
        let titleWidth = min(ceil(labelSize.width), availableTitleWidth)
        let titleHeight = min(topLineHeight, ceil(labelSize.height))
        var x: CGFloat = 0
        primaryLabel.frame = NSRect(
            x: x,
            y: topY + floor((topLineHeight - titleHeight) * 0.5),
            width: titleWidth,
            height: titleHeight
        )
        x += titleWidth + spacing

        let countHeight = min(topLineHeight - 2, countSize.height)
        firstPillView.frame = NSRect(
            x: x,
            y: topY + floor((topLineHeight - countHeight) * 0.5),
            width: min(countSize.width, max(0, bounds.width - x)),
            height: countHeight
        )
        x += countSize.width + spacing

        let confHeight = min(topLineHeight - 2, confSize.height)
        secondPillView.frame = NSRect(
            x: x,
            y: topY + floor((topLineHeight - confHeight) * 0.5),
            width: min(confSize.width, max(0, bounds.width - x)),
            height: confHeight
        )
        x += confSize.width

        if !trailingIconView.isHidden {
            x += spacing
            trailingIconView.frame = NSRect(
                x: x,
                y: topY + floor((topLineHeight - iconDim) * 0.5),
                width: iconDim,
                height: iconDim
            )
        }

        let evidenceHeight = min(bottomLineHeight, ceil(measureSingleLineTextField(evidenceLabel).height))
        evidenceLabel.frame = NSRect(
            x: 0,
            y: bottomY,
            width: bounds.width,
            height: evidenceHeight
        )
    }
}

private final class SessionClientCellView: NSTableCellView, SessionOutlineConfigurableCell {
    // MARK: Lifecycle

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        iconView.imageScaling = .scaleProportionallyDown
        label.font = SessionOutlineStyle.bodyFont
        label.lineBreakMode = .byTruncatingTail
        label.maximumNumberOfLines = 1
        label.usesSingleLineMode = true
        label.drawsBackground = false

        addSubview(iconView)
        addSubview(label)
        imageView = iconView
        textField = label
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    // MARK: Internal

    func configure(with model: SessionOutlineRowModel, column _: SessionOutlineColumnID) {
        let client = model.client
        currentClient = client
        showsIcon = client.showsIcon
        iconView.isHidden = !client.showsIcon
        if client.showsIcon {
            iconView.image = SessionOutlineIconCache.clientIcon(for: client, appearance: effectiveAppearance)
        } else {
            iconView.image = nil
        }
        label.stringValue = client.label
        label.textColor = SessionOutlineStyle.textColor(for: client.emphasis)
        toolTip = client.tooltip
        needsLayout = true
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        if let client = currentClient, client.showsIcon {
            iconView.image = SessionOutlineIconCache.clientIcon(for: client, appearance: effectiveAppearance)
        }
    }

    override func layout() {
        super.layout()
        let iconDim: CGFloat = 17
        var x: CGFloat = showsIcon ? 1 : 0
        if showsIcon {
            iconView.frame = NSRect(
                x: x,
                y: floor((bounds.height - iconDim) * 0.5),
                width: iconDim,
                height: iconDim
            )
            x += iconDim + 6
        }
        let labelHeight = min(bounds.height, ceil(measureSingleLineTextField(label).height))
        label.frame = NSRect(
            x: x,
            y: floor((bounds.height - labelHeight) * 0.5),
            width: max(0, bounds.width - x),
            height: labelHeight
        )
    }

    // MARK: Private

    private let iconView = NSImageView()
    private let label = NSTextField(labelWithString: "")
    private var showsIcon = false
    private var currentClient: SessionOutlineClientPresentation?
}

private final class SessionProtocolPillCellView: NSTableCellView, SessionOutlineConfigurableCell {
    // MARK: Lifecycle

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        addSubview(pillView)
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    // MARK: Internal

    func configure(with model: SessionOutlineRowModel, column _: SessionOutlineColumnID) {
        if let proto = model.primaryProtocol {
            let color = SessionOutlineStyle.color(for: proto)
            pillView.isHidden = false
            pillView.configure(
                text: proto.label,
                textColor: color,
                fillColor: color.withAlphaComponent(0.18)
            )
            toolTip = proto.label
        } else {
            pillView.isHidden = true
            toolTip = nil
        }
        needsLayout = true
    }

    override func layout() {
        super.layout()
        guard !pillView.isHidden else {
            return
        }
        let size = pillView.intrinsicContentSize
        let width = min(bounds.width, size.width)
        let height = min(bounds.height - 2, size.height)
        pillView.frame = NSRect(
            x: 0,
            y: floor((bounds.height - height) * 0.5),
            width: width,
            height: height
        )
    }

    // MARK: Private

    private let pillView = SessionPillView(
        font: SessionOutlineStyle.badgeFont,
        horizontalPadding: 6,
        verticalPadding: 2
    )
}

private final class SessionStatusCellView: NSTableCellView, SessionOutlineConfigurableCell {
    // MARK: Lifecycle

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        iconView.imageScaling = .scaleProportionallyDown
        addSubview(iconView)
        imageView = iconView
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    // MARK: Internal

    func configure(with model: SessionOutlineRowModel, column _: SessionOutlineColumnID) {
        let status = model.status
        iconView.image = SessionOutlineIconCache.smallSymbol(
            named: status.systemImage,
            color: SessionOutlineStyle.color(for: status),
            colorKey: status.rawValue
        )
        toolTip = status.label
        setAccessibilityLabel(status.label)
        needsLayout = true
    }

    override func layout() {
        super.layout()
        let dim: CGFloat = 12
        iconView.frame = NSRect(
            x: floor((bounds.width - dim) * 0.5),
            y: floor((bounds.height - dim) * 0.5),
            width: dim,
            height: dim
        )
    }

    // MARK: Private

    private let iconView = NSImageView()
}

private final class SessionTimelineCellView: NSTableCellView, SessionOutlineConfigurableCell {
    // MARK: Internal

    func configure(with model: SessionOutlineRowModel, column _: SessionOutlineColumnID) {
        fraction = model.timelineFraction
        barColor = model.primaryProtocol.map { SessionOutlineStyle.color(for: $0) } ?? .controlAccentColor
        toolTip = model.timelineHelp
        setAccessibilityLabel("Timeline")
        setAccessibilityValue(model.timelineHelp)
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard let fraction, bounds.width > 2 else {
            return
        }
        let width = bounds.width
        let trackRect = NSRect(x: 0, y: floor((bounds.height - 4) * 0.5), width: width, height: 4)
        NSColor.quaternaryLabelColor.setFill()
        NSBezierPath(roundedRect: trackRect, xRadius: 2, yRadius: 2).fill()

        let start = width * CGFloat(fraction.lowerBound)
        let rawLength = max(2, width * CGFloat(fraction.upperBound - fraction.lowerBound))
        let clampedLength = min(rawLength, max(2, width - start))
        let barRect = NSRect(x: start, y: floor((bounds.height - 6) * 0.5), width: clampedLength, height: 6)
        barColor.setFill()
        NSBezierPath(roundedRect: barRect, xRadius: 3, yRadius: 3).fill()
    }

    // MARK: Private

    private var fraction: ClosedRange<Double>?
    private var barColor: NSColor = .controlAccentColor
}

// MARK: - SessionOutlineNSView & SessionOutlineScrollView

/// Custom `NSOutlineView` whose right-click context menu resolves the exact
/// row under the pointer (`row(at:)`) without mutating or relying on stale
/// selection state.
final class SessionOutlineNSView: NSOutlineView {
    var contextMenuProvider: ((SessionOutlineRowModel) -> NSMenu?)?

    override func menu(for event: NSEvent) -> NSMenu? {
        let point = convert(event.locationInWindow, from: nil)
        let clicked = row(at: point)
        guard clicked >= 0,
              let node = item(atRow: clicked) as? SessionOutlineNode
        else {
            return nil
        }
        return contextMenuProvider?(node.model)
    }
}

/// Custom `NSScrollView` that detects discrete mouse-wheel scrolling in addition
/// to AppKit's live-scroll notifications so Follow Live disengages cleanly on
/// both trackpads and scroll wheels.
final class SessionOutlineScrollView: NSScrollView {
    var onDiscreteScrollWheel: (() -> Void)?

    override func scrollWheel(with event: NSEvent) {
        if event.phase.isEmpty, event.momentumPhase.isEmpty {
            onDiscreteScrollWheel?()
        }
        super.scrollWheel(with: event)
    }
}

// MARK: - NativeSessionOutlineTable

/// Pure AppKit virtualized `NSOutlineView` session table supporting both flat
/// and grouped (`.action` / `.host` / `.process`) modes with O(visible) live
/// cell diffing, incremental tail insertion, zero `NSHostingView` cells,
/// header sort & column visibility persistence, and native right-click menus.
struct NativeSessionOutlineTable: NSViewRepresentable {
    // MARK: Internal

    let rows: [SessionOutlineRowModel]
    let isGrouped: Bool
    let timeFormat: SessionTimeFormat
    let languageBundlePath: String
    @Binding var selectedSessionID: UUID?
    @Binding var sortCriteria: [SessionOutlineSortCriterion]
    @Binding var columnState: SessionOutlineColumnState
    let revealToken: Int
    var onLiveScrollStateChange: ((Bool) -> Void)?
    let onUserNavigateHistory: () -> Void
    let contextMenuBuilder: (SessionOutlineRowModel) -> NSMenu?

    static func dismantleNSView(_: SessionOutlineScrollView, coordinator: Coordinator) {
        coordinator.tearDown()
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(
            onSelectSessionID: { selectedSessionID = $0 },
            onSortCriteriaChange: { sortCriteria = $0 },
            onColumnStateChange: { columnState = $0 },
            onLiveScrollStateChange: onLiveScrollStateChange,
            onUserNavigateHistory: onUserNavigateHistory,
            contextMenuBuilder: contextMenuBuilder
        )
    }

    func makeNSView(context: Context) -> SessionOutlineScrollView {
        let scrollView = context.coordinator.makeScrollView()
        context.coordinator.apply(
            rows: rows,
            isGrouped: isGrouped,
            timeFormat: timeFormat,
            languageBundlePath: languageBundlePath,
            selectedSessionID: selectedSessionID,
            sortCriteria: sortCriteria,
            columnState: columnState,
            revealToken: revealToken
        )
        return scrollView
    }

    func updateNSView(_: SessionOutlineScrollView, context: Context) {
        let coordinator = context.coordinator
        coordinator.onSelectSessionID = { selectedSessionID = $0 }
        coordinator.onSortCriteriaChange = { sortCriteria = $0 }
        coordinator.onColumnStateChange = { columnState = $0 }
        coordinator.onLiveScrollStateChange = onLiveScrollStateChange
        coordinator.onUserNavigateHistory = onUserNavigateHistory
        coordinator.contextMenuBuilder = contextMenuBuilder

        coordinator.apply(
            rows: rows,
            isGrouped: isGrouped,
            timeFormat: timeFormat,
            languageBundlePath: languageBundlePath,
            selectedSessionID: selectedSessionID,
            sortCriteria: sortCriteria,
            columnState: columnState,
            revealToken: revealToken
        )
    }
}

// MARK: - NativeSessionOutlineTable.Coordinator

extension NativeSessionOutlineTable {
    @MainActor
    final class Coordinator: NSObject, NSOutlineViewDataSource, NSOutlineViewDelegate, NSMenuDelegate {
        // MARK: Lifecycle

        init(
            onSelectSessionID: @escaping (UUID?) -> Void,
            onSortCriteriaChange: @escaping ([SessionOutlineSortCriterion]) -> Void,
            onColumnStateChange: @escaping (SessionOutlineColumnState) -> Void,
            onLiveScrollStateChange: ((Bool) -> Void)? = nil,
            onUserNavigateHistory: @escaping () -> Void,
            contextMenuBuilder: @escaping (SessionOutlineRowModel) -> NSMenu?
        ) {
            self.onSelectSessionID = onSelectSessionID
            self.onSortCriteriaChange = onSortCriteriaChange
            self.onColumnStateChange = onColumnStateChange
            self.onLiveScrollStateChange = onLiveScrollStateChange
            self.onUserNavigateHistory = onUserNavigateHistory
            self.contextMenuBuilder = contextMenuBuilder
            super.init()
        }

        // MARK: Internal

        var onSelectSessionID: (UUID?) -> Void
        var onSortCriteriaChange: ([SessionOutlineSortCriterion]) -> Void
        var onColumnStateChange: (SessionOutlineColumnState) -> Void
        var onLiveScrollStateChange: ((Bool) -> Void)?
        var onUserNavigateHistory: () -> Void
        var contextMenuBuilder: (SessionOutlineRowModel) -> NSMenu?

        private(set) var scrollView: SessionOutlineScrollView?
        private(set) var outlineView: SessionOutlineNSView?
        private(set) var topLevelNodes: [SessionOutlineNode] = []

        // Diagnostic counters verified by unit tests
        private(set) var fullReloadCount = 0
        private(set) var incrementalVisibleUpdateCount = 0
        private(set) var incrementalTailInsertCount = 0

        func makeScrollView() -> SessionOutlineScrollView {
            let outline = SessionOutlineNSView(frame: .zero)
            outline.style = .fullWidth
            outline.usesAlternatingRowBackgroundColors = true
            outline.gridStyleMask = []
            outline.intercellSpacing = NSSize(width: 8, height: 0)
            outline.rowSizeStyle = .custom
            outline.usesAutomaticRowHeights = false
            outline.rowHeight = 24
            outline.allowsMultipleSelection = false
            outline.allowsEmptySelection = true
            outline.allowsColumnReordering = true
            outline.allowsColumnResizing = true
            outline.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
            outline.autoresizesOutlineColumn = false
            outline.indentationPerLevel = 0
            outline.focusRingType = .none
            outline.delegate = self
            outline.dataSource = self
            outline.contextMenuProvider = { [weak self] model in
                self?.contextMenuBuilder(model)
            }

            let headerMenu = NSMenu()
            headerMenu.autoenablesItems = false
            headerMenu.delegate = self
            outline.headerView?.menu = headerMenu
            self.headerMenu = headerMenu

            let scroll = SessionOutlineScrollView(frame: .zero)
            scroll.hasVerticalScroller = true
            scroll.hasHorizontalScroller = true
            scroll.autohidesScrollers = true
            scroll.borderType = .noBorder
            scroll.drawsBackground = false
            scroll.automaticallyAdjustsContentInsets = true
            scroll.documentView = outline
            scroll.onDiscreteScrollWheel = { [weak self] in
                self?.onUserNavigateHistory()
            }

            outlineView = outline
            scrollView = scroll
            installScrollObservers(on: scroll)
            installInitialColumns(on: outline)
            return scroll
        }

        func tearDown() {
            removeScrollObservers()
            if isLiveScrolling {
                isLiveScrolling = false
                onLiveScrollStateChange?(false)
            }
        }

        /// Applies a new presentation snapshot using O(visible) in-place diffing
        /// or incremental tail insertion whenever possible, falling back to
        /// `reloadData()` only on genuine structural changes.
        func apply(
            rows: [SessionOutlineRowModel],
            isGrouped: Bool,
            timeFormat: SessionTimeFormat,
            languageBundlePath: String = AppLanguage.currentLocalizedBundle().bundlePath,
            selectedSessionID: UUID?,
            sortCriteria: [SessionOutlineSortCriterion],
            columnState: SessionOutlineColumnState,
            revealToken: Int
        ) {
            guard let outlineView else {
                return
            }

            let groupingChanged = hasMounted && (self.isGrouped != isGrouped)
            let languageChanged = hasMounted && (lastLanguageBundlePath != languageBundlePath)
            self.isGrouped = isGrouped
            lastLanguageBundlePath = languageBundlePath
            currentTimeFormat = timeFormat
            currentSortCriteria = sortCriteria
            currentColumnState = columnState
            currentSelectedSessionID = selectedSessionID

            syncColumns(on: outlineView, isGrouped: isGrouped, timeFormat: timeFormat, columnState: columnState, sortCriteria: sortCriteria)

            if !hasMounted || groupingChanged {
                hasMounted = true
                performFullReload(rows: rows, on: outlineView, restoreExpansion: !groupingChanged)
            } else if isSameTopAndChildStructure(rows: rows) {
                applyInPlaceUpdates(rows: rows, on: outlineView, forceReconfigureVisible: languageChanged)
            } else if isPureTailAppend(rows: rows) {
                applyTailAppend(rows: rows, on: outlineView, forceReconfigureVisible: languageChanged)
            } else {
                performFullReload(rows: rows, on: outlineView, restoreExpansion: true)
            }

            syncSelection(selectedSessionID: selectedSessionID, on: outlineView)

            if revealToken != lastRevealToken {
                lastRevealToken = revealToken
                scheduleRevealSelectedRow(selectedSessionID: selectedSessionID)
            }
        }

        /// Builds the column-header context menu (also invoked directly by unit tests).
        func populateHeaderMenu(_ menu: NSMenu, bundle: Bundle = AppLanguage.currentLocalizedBundle()) {
            menu.removeAllItems()
            menu.autoenablesItems = false

            if !isGrouped {
                for colID in SessionOutlineColumnID.standardColumns where colID.allowsVisibilityCustomization {
                    let item = SessionOutlineContextMenuBuilder.makeItem(
                        title: colID.title(timeFormat: currentTimeFormat, bundle: bundle),
                        handler: { [weak self] in
                            self?.toggleColumnVisibility(colID)
                        }
                    )
                    item.state = currentColumnState.isVisible(colID) ? .on : .off
                    menu.addItem(item)
                }

                menu.addItem(.separator())

                for colID in SessionOutlineColumnID.optionalColumns {
                    let item = SessionOutlineContextMenuBuilder.makeItem(
                        title: colID.title(timeFormat: currentTimeFormat, bundle: bundle),
                        handler: { [weak self] in
                            self?.toggleColumnVisibility(colID)
                        }
                    )
                    item.state = currentColumnState.isVisible(colID) ? .on : .off
                    menu.addItem(item)
                }

                menu.addItem(.separator())

                if !currentSortCriteria.isEmpty {
                    menu.addItem(SessionOutlineContextMenuBuilder.makeItem(
                        title: String(localized: "Reset Sort Order", bundle: bundle),
                        handler: { [weak self] in
                            self?.resetSortOrder()
                        }
                    ))
                }
            }

            menu.addItem(SessionOutlineContextMenuBuilder.makeItem(
                title: String(localized: "Reset Columns", bundle: bundle),
                handler: { [weak self] in
                    self?.resetColumns()
                }
            ))
        }

        // MARK: NSMenuDelegate

        func menuNeedsUpdate(_ menu: NSMenu) {
            guard menu === headerMenu else {
                return
            }
            populateHeaderMenu(menu)
        }

        // MARK: NSOutlineViewDataSource

        func outlineView(_: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
            if item == nil {
                return topLevelNodes.count
            }
            guard let node = item as? SessionOutlineNode else {
                return 0
            }
            return node.children.count
        }

        func outlineView(_: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
            if item == nil {
                return topLevelNodes[index]
            }
            guard let node = item as? SessionOutlineNode else {
                return topLevelNodes[index]
            }
            return node.children[index]
        }

        func outlineView(_: NSOutlineView, isItemExpandable item: Any) -> Bool {
            guard isGrouped, let node = item as? SessionOutlineNode else {
                return false
            }
            return !node.children.isEmpty
        }

        func outlineView(_ outlineView: NSOutlineView, sortDescriptorsDidChange _: [NSSortDescriptor]) {
            guard !isProgrammaticColumnUpdate, !isGrouped else {
                return
            }
            let next = outlineView.sortDescriptors.compactMap(SessionOutlineSortCriterion.init(sortDescriptor:))
            if next != currentSortCriteria {
                currentSortCriteria = next
                onSortCriteriaChange(next)
            }
        }

        // MARK: NSOutlineViewDelegate

        func outlineView(_: NSOutlineView, heightOfRowByItem item: Any) -> CGFloat {
            guard isGrouped, let node = item as? SessionOutlineNode else {
                return 24
            }
            return node.model.preferredRowHeight
        }

        func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
            guard let tableColumn,
                  let colID = SessionOutlineColumnID(rawValue: tableColumn.identifier.rawValue),
                  let node = item as? SessionOutlineNode
            else {
                return nil
            }
            let cell = dequeueOrCreateCell(for: colID, in: outlineView)
            cell.configure(with: node.model, column: colID)
            return cell as? NSView
        }

        func outlineViewSelectionDidChange(_ notification: Notification) {
            guard !isProgrammaticSelectionChange,
                  let outlineView = notification.object as? NSOutlineView
            else {
                return
            }
            let row = outlineView.selectedRow
            guard row >= 0, let node = outlineView.item(atRow: row) as? SessionOutlineNode else {
                lastUserSelectedRowID = nil
                if currentSelectedSessionID != nil {
                    currentSelectedSessionID = nil
                    onUserNavigateHistory()
                    onSelectSessionID(nil)
                }
                return
            }
            lastUserSelectedRowID = node.id
            let resolved = node.model.representativeSessionID
            if currentSelectedSessionID != resolved {
                currentSelectedSessionID = resolved
                onUserNavigateHistory()
                onSelectSessionID(resolved)
            }
        }

        func outlineViewItemDidExpand(_ notification: Notification) {
            guard !isProgrammaticSelectionChange,
                  let node = notification.userInfo?["NSObject"] as? SessionOutlineNode
            else {
                return
            }
            expandedParentIDs.insert(node.id)
        }

        func outlineViewItemDidCollapse(_ notification: Notification) {
            guard !isProgrammaticSelectionChange,
                  let node = notification.userInfo?["NSObject"] as? SessionOutlineNode
            else {
                return
            }
            expandedParentIDs.remove(node.id)
        }

        func outlineViewColumnDidResize(_ notification: Notification) {
            guard !isProgrammaticColumnUpdate,
                  !isGrouped,
                  let outlineView,
                  !outlineView.inLiveResize,
                  let column = notification.userInfo?["NSTableColumn"] as? NSTableColumn,
                  !column.isHidden,
                  let colID = SessionOutlineColumnID(rawValue: column.identifier.rawValue)
            else {
                return
            }
            var updated = currentColumnState
            updated.setWidth(column.width, for: colID)
            if updated != currentColumnState {
                currentColumnState = updated
                onColumnStateChange(updated)
            }
        }

        func outlineViewColumnDidMove(_: Notification) {
            guard !isProgrammaticColumnUpdate,
                  !isGrouped,
                  let outlineView
            else {
                return
            }
            let newOrder = outlineView.tableColumns.compactMap {
                SessionOutlineColumnID(rawValue: $0.identifier.rawValue)
            }
            var updated = currentColumnState
            updated.setOrder(newOrder)
            if updated != currentColumnState {
                currentColumnState = updated
                onColumnStateChange(updated)
            }
        }

        // MARK: Private

        private var hasMounted = false
        private var isGrouped = false
        private var isProgrammaticSelectionChange = false
        private var isProgrammaticColumnUpdate = false
        private var isLiveScrolling = false

        private var currentTimeFormat: SessionTimeFormat = .timeOfDay
        private var currentSortCriteria: [SessionOutlineSortCriterion] = []
        private var currentColumnState: SessionOutlineColumnState = .defaultState
        private var currentSelectedSessionID: UUID?
        private var lastUserSelectedRowID: UUID?
        private var lastRevealToken = 0
        private var lastLanguageBundlePath = ""

        private var nodesByID: [UUID: SessionOutlineNode] = [:]
        private var expandedParentIDs: Set<UUID> = []
        private var headerMenu: NSMenu?
        private var scrollObservers: [NSObjectProtocol] = []

        private func installScrollObservers(on scrollView: NSScrollView) {
            let center = NotificationCenter.default
            let startObserver = center.addObserver(
                forName: NSScrollView.willStartLiveScrollNotification,
                object: scrollView,
                queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    self.isLiveScrolling = true
                    self.onLiveScrollStateChange?(true)
                    self.onUserNavigateHistory()
                }
            }
            let endObserver = center.addObserver(
                forName: NSScrollView.didEndLiveScrollNotification,
                object: scrollView,
                queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    self.isLiveScrolling = false
                    self.onLiveScrollStateChange?(false)
                }
            }
            scrollObservers = [startObserver, endObserver]
        }

        private func removeScrollObservers() {
            let center = NotificationCenter.default
            for observer in scrollObservers {
                center.removeObserver(observer)
            }
            scrollObservers.removeAll()
        }

        private func installInitialColumns(on outlineView: NSOutlineView) {
            isProgrammaticColumnUpdate = true
            defer { isProgrammaticColumnUpdate = false }

            let bundle = AppLanguage.currentLocalizedBundle()
            for colID in SessionOutlineColumnID.allCases {
                let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(colID.rawValue))
                column.title = colID.title(timeFormat: currentTimeFormat, bundle: bundle)
                column.minWidth = colID.minWidth
                column.width = colID.idealWidth
                if let maxWidth = colID.maxWidth {
                    column.maxWidth = maxWidth
                }
                column.resizingMask = colID == .status ? [] : .userResizingMask
                column.isHidden = !colID.isDefaultVisible
                if colID.isSortable {
                    column.sortDescriptorPrototype = NSSortDescriptor(key: colID.rawValue, ascending: true)
                }
                outlineView.addTableColumn(column)
            }
        }

        private func syncColumns(
            on outlineView: NSOutlineView,
            isGrouped: Bool,
            timeFormat: SessionTimeFormat,
            columnState: SessionOutlineColumnState,
            sortCriteria: [SessionOutlineSortCriterion]
        ) {
            isProgrammaticColumnUpdate = true
            defer { isProgrammaticColumnUpdate = false }

            let bundle = AppLanguage.currentLocalizedBundle()

            // Reorder columns when needed (flat mode respects persisted order;
            // grouped mode uses canonical standard order).
            let desiredOrder = isGrouped ? SessionOutlineColumnID.allCases : columnState.columnOrder
            for (targetIndex, colID) in desiredOrder.enumerated() {
                let identifier = NSUserInterfaceItemIdentifier(colID.rawValue)
                let currentIndex = outlineView.column(withIdentifier: identifier)
                if currentIndex >= 0, currentIndex != targetIndex {
                    outlineView.moveColumn(currentIndex, toColumn: targetIndex)
                }
            }

            // Refresh titles, visibility, widths, and sort prototypes.
            for column in outlineView.tableColumns {
                guard let colID = SessionOutlineColumnID(rawValue: column.identifier.rawValue) else {
                    continue
                }
                let expectedTitle = colID.title(timeFormat: timeFormat, bundle: bundle)
                if column.title != expectedTitle {
                    column.title = expectedTitle
                }

                let shouldHide: Bool = if isGrouped {
                    colID.isOptional
                } else {
                    !columnState.isVisible(colID)
                }
                if column.isHidden != shouldHide {
                    column.isHidden = shouldHide
                }

                if !isGrouped {
                    let expectedWidth = columnState.width(for: colID)
                    if abs(column.width - expectedWidth) > 1 {
                        column.width = expectedWidth
                    }
                    if colID.isSortable {
                        if column.sortDescriptorPrototype == nil {
                            column.sortDescriptorPrototype = NSSortDescriptor(key: colID.rawValue, ascending: true)
                        }
                    } else {
                        column.sortDescriptorPrototype = nil
                    }
                } else {
                    column.sortDescriptorPrototype = nil
                }
            }

            // Configure disclosure triangle column & indentation.
            if isGrouped {
                outlineView.indentationPerLevel = 14
                let hostCol = outlineView.tableColumn(
                    withIdentifier: NSUserInterfaceItemIdentifier(SessionOutlineColumnID.host.rawValue)
                )
                let firstVisible = outlineView.tableColumns.first { !$0.isHidden }
                let targetOutlineCol = (hostCol?.isHidden == false ? hostCol : firstVisible) ?? firstVisible
                if outlineView.outlineTableColumn !== targetOutlineCol {
                    outlineView.outlineTableColumn = targetOutlineCol
                }
                if !outlineView.sortDescriptors.isEmpty {
                    outlineView.sortDescriptors = []
                }
            } else {
                outlineView.indentationPerLevel = 0
                let firstVisible = outlineView.tableColumns.first { !$0.isHidden }
                if outlineView.outlineTableColumn !== firstVisible {
                    outlineView.outlineTableColumn = firstVisible
                }
                let expectedDescriptors = sortCriteria.map(\.sortDescriptor)
                if outlineView.sortDescriptors != expectedDescriptors {
                    outlineView.sortDescriptors = expectedDescriptors
                }
            }
        }

        private func isSameTopAndChildStructure(rows: [SessionOutlineRowModel]) -> Bool {
            guard rows.count == topLevelNodes.count else {
                return false
            }
            for index in rows.indices {
                let node = topLevelNodes[index]
                let row = rows[index]
                if node.id != row.id || node.children.count != row.children.count {
                    return false
                }
                for childIndex in row.children.indices where node.children[childIndex].id != row.children[childIndex].id {
                    return false
                }
            }
            return true
        }

        private func isPureTailAppend(rows: [SessionOutlineRowModel]) -> Bool {
            let oldCount = topLevelNodes.count
            guard oldCount > 0, rows.count > oldCount else {
                return false
            }
            for index in 0 ..< oldCount {
                let node = topLevelNodes[index]
                let row = rows[index]
                if node.id != row.id || node.children.count != row.children.count {
                    return false
                }
                for childIndex in row.children.indices where node.children[childIndex].id != row.children[childIndex].id {
                    return false
                }
            }
            return true
        }

        private func updateExistingPrefix(
            from rows: [SessionOutlineRowModel],
            count: Int
        ) -> (changedIDs: Set<UUID>, heightChanged: [SessionOutlineNode]) {
            var changedIDs: Set<UUID> = []
            var heightChanged: [SessionOutlineNode] = []
            for index in 0 ..< count {
                let node = topLevelNodes[index]
                let newModel = rows[index]
                if node.model != newModel {
                    if node.model.preferredRowHeight != newModel.preferredRowHeight {
                        heightChanged.append(node)
                    }
                    node.model = newModel
                    changedIDs.insert(node.id)
                }
                for childIndex in newModel.children.indices {
                    let childNode = node.children[childIndex]
                    let newChildModel = newModel.children[childIndex]
                    if childNode.model != newChildModel {
                        childNode.model = newChildModel
                        changedIDs.insert(childNode.id)
                    }
                }
            }
            return (changedIDs, heightChanged)
        }

        private func applyInPlaceUpdates(
            rows: [SessionOutlineRowModel],
            on outlineView: NSOutlineView,
            forceReconfigureVisible: Bool = false
        ) {
            let (changedIDs, heightChangedRows) = updateExistingPrefix(from: rows, count: rows.count)
            guard !changedIDs.isEmpty || forceReconfigureVisible else {
                return
            }

            if !heightChangedRows.isEmpty {
                var rowIndexes = IndexSet()
                for node in heightChangedRows {
                    let rowIndex = outlineView.row(forItem: node)
                    if rowIndex >= 0 {
                        rowIndexes.insert(rowIndex)
                    }
                }
                if !rowIndexes.isEmpty {
                    outlineView.noteHeightOfRows(withIndexesChanged: rowIndexes)
                }
            }

            reconfigureVisibleRows(
                changedIDs: forceReconfigureVisible ? nil : changedIDs,
                on: outlineView
            )
            incrementalVisibleUpdateCount += 1
        }

        private func applyTailAppend(
            rows: [SessionOutlineRowModel],
            on outlineView: NSOutlineView,
            forceReconfigureVisible: Bool = false
        ) {
            let oldCount = topLevelNodes.count
            let (changedIDs, _) = updateExistingPrefix(from: rows, count: oldCount)

            if !changedIDs.isEmpty || forceReconfigureVisible {
                reconfigureVisibleRows(
                    changedIDs: forceReconfigureVisible ? nil : changedIDs,
                    on: outlineView
                )
                incrementalVisibleUpdateCount += 1
            }

            var appendedNodes: [SessionOutlineNode] = []
            appendedNodes.reserveCapacity(rows.count - oldCount)
            for index in oldCount ..< rows.count {
                let node = SessionOutlineNode(model: rows[index])
                appendedNodes.append(node)
                nodesByID[node.id] = node
                for child in node.children {
                    nodesByID[child.id] = child
                }
            }
            topLevelNodes.append(contentsOf: appendedNodes)

            isProgrammaticSelectionChange = true
            defer { isProgrammaticSelectionChange = false }
            outlineView.beginUpdates()
            outlineView.insertItems(at: IndexSet(oldCount ..< rows.count), inParent: nil, withAnimation: [])
            outlineView.endUpdates()
            incrementalTailInsertCount += 1
        }

        private func performFullReload(
            rows: [SessionOutlineRowModel],
            on outlineView: NSOutlineView,
            restoreExpansion: Bool
        ) {
            if restoreExpansion {
                for node in topLevelNodes where outlineView.isItemExpanded(node) {
                    expandedParentIDs.insert(node.id)
                }
            } else {
                expandedParentIDs.removeAll()
            }

            let previousByID = nodesByID
            var nextTop: [SessionOutlineNode] = []
            nextTop.reserveCapacity(rows.count)
            var nextMap: [UUID: SessionOutlineNode] = [:]
            nextMap.reserveCapacity(rows.count)

            for row in rows {
                let node: SessionOutlineNode
                if let existing = previousByID[row.id] {
                    existing.model = row
                    existing.parent = nil
                    existing.children = row.children.map { childRow in
                        if let existingChild = previousByID[childRow.id] {
                            existingChild.model = childRow
                            existingChild.parent = existing
                            existingChild.children = []
                            return existingChild
                        }
                        return SessionOutlineNode(model: childRow, parent: existing)
                    }
                    node = existing
                } else {
                    node = SessionOutlineNode(model: row)
                }
                nextTop.append(node)
                nextMap[node.id] = node
                for child in node.children {
                    nextMap[child.id] = child
                }
            }

            topLevelNodes = nextTop
            nodesByID = nextMap

            isProgrammaticSelectionChange = true
            defer { isProgrammaticSelectionChange = false }

            outlineView.reloadData()
            fullReloadCount += 1

            if isGrouped, restoreExpansion, !expandedParentIDs.isEmpty {
                for node in topLevelNodes where !node.children.isEmpty && expandedParentIDs.contains(node.id) {
                    outlineView.expandItem(node)
                }
            }
        }

        private func reconfigureVisibleRows(changedIDs: Set<UUID>?, on outlineView: NSOutlineView) {
            let visibleRange = outlineView.rows(in: outlineView.visibleRect)
            guard visibleRange.length > 0 else {
                return
            }
            let columnIDs: [SessionOutlineColumnID?] = outlineView.tableColumns.map {
                SessionOutlineColumnID(rawValue: $0.identifier.rawValue)
            }
            let upperBound = min(outlineView.numberOfRows, visibleRange.location + visibleRange.length)
            for rowIndex in visibleRange.location ..< upperBound {
                guard let node = outlineView.item(atRow: rowIndex) as? SessionOutlineNode else {
                    continue
                }
                if let changedIDs, !changedIDs.contains(node.id) {
                    continue
                }
                for colIndex in 0 ..< columnIDs.count {
                    guard let colID = columnIDs[colIndex],
                          !outlineView.tableColumns[colIndex].isHidden,
                          let cell = outlineView.view(atColumn: colIndex, row: rowIndex, makeIfNecessary: false)
                              as? SessionOutlineConfigurableCell
                    else {
                        continue
                    }
                    cell.configure(with: node.model, column: colID)
                }
            }
        }

        private func syncSelection(selectedSessionID: UUID?, on outlineView: NSOutlineView) {
            let targetRow = resolvedOutlineRowIndex(for: selectedSessionID, on: outlineView)
            let currentRow = outlineView.selectedRow
            if targetRow == currentRow {
                return
            }

            isProgrammaticSelectionChange = true
            defer { isProgrammaticSelectionChange = false }

            if let targetRow, targetRow >= 0 {
                outlineView.selectRowIndexes(IndexSet(integer: targetRow), byExtendingSelection: false)
            } else {
                outlineView.deselectAll(nil)
            }
        }

        private func resolvedOutlineRowIndex(for selectedSessionID: UUID?, on outlineView: NSOutlineView) -> Int? {
            guard let selectedSessionID else {
                return nil
            }
            // If the user explicitly clicked an `.action` or `.group` row whose
            // representative session still matches, keep that parent row selected.
            if let preferredRowID = lastUserSelectedRowID,
               let preferredNode = nodesByID[preferredRowID],
               preferredNode.model.representativeSessionID == selectedSessionID
            {
                let row = outlineView.row(forItem: preferredNode)
                if row >= 0 {
                    return row
                }
            }
            // Exact node match (flat row or currently visible expanded child).
            if let exact = nodesByID[selectedSessionID] {
                let row = outlineView.row(forItem: exact)
                if row >= 0 {
                    return row
                }
            }
            // Collapsed parent whose representative or child matches `selectedSessionID`.
            for node in topLevelNodes {
                if node.model.representativeSessionID == selectedSessionID
                    || node.children.contains(where: { $0.id == selectedSessionID })
                {
                    let row = outlineView.row(forItem: node)
                    if row >= 0 {
                        return row
                    }
                }
            }
            return nil
        }

        private func scheduleRevealSelectedRow(selectedSessionID: UUID?) {
            DispatchQueue.main.async { [weak self] in
                guard let self, let outlineView = self.outlineView else {
                    return
                }
                let targetRow = self.resolvedOutlineRowIndex(for: selectedSessionID, on: outlineView)
                    ?? (outlineView.selectedRow >= 0 ? outlineView.selectedRow : nil)
                guard let targetRow, targetRow >= 0, targetRow < outlineView.numberOfRows else {
                    return
                }
                let rowRect = outlineView.rect(ofRow: targetRow)
                let visible = outlineView.visibleRect
                let margin = rowRect.height * 2
                guard !visible.insetBy(dx: 0, dy: min(margin, visible.height / 4)).contains(rowRect) else {
                    return
                }
                let y = max(0, rowRect.midY - visible.height / 2)
                outlineView.scroll(NSPoint(x: visible.minX, y: y))
            }
        }

        private func dequeueOrCreateCell(
            for column: SessionOutlineColumnID,
            in outlineView: NSOutlineView
        ) -> SessionOutlineConfigurableCell {
            let identifier = cellIdentifier(for: column)
            if let reused = outlineView.makeView(withIdentifier: identifier, owner: self) as? SessionOutlineConfigurableCell {
                return reused
            }
            let created: NSTableCellView & SessionOutlineConfigurableCell = switch column {
            case .host:
                SessionHostCellView(frame: .zero)
            case .client:
                SessionClientCellView(frame: .zero)
            case .protocolKind:
                SessionProtocolPillCellView(frame: .zero)
            case .status:
                SessionStatusCellView(frame: .zero)
            case .timeline:
                SessionTimelineCellView(frame: .zero)
            case .time,
                 .source,
                 .destination,
                 .length,
                 .latency,
                 .summary,
                 .serverName,
                 .duration,
                 .bytesUp,
                 .bytesDown,
                 .protocolStack,
                 .tcpCompleteness:
                SessionTextCellView(frame: .zero)
            }
            created.identifier = identifier
            return created
        }

        private func cellIdentifier(for column: SessionOutlineColumnID) -> NSUserInterfaceItemIdentifier {
            switch column {
            case .host: NSUserInterfaceItemIdentifier("SessionHostCell")
            case .client: NSUserInterfaceItemIdentifier("SessionClientCell")
            case .protocolKind: NSUserInterfaceItemIdentifier("SessionProtocolCell")
            case .status: NSUserInterfaceItemIdentifier("SessionStatusCell")
            case .timeline: NSUserInterfaceItemIdentifier("SessionTimelineCell")
            case .time,
                 .source,
                 .destination,
                 .length,
                 .latency,
                 .summary,
                 .serverName,
                 .duration,
                 .bytesUp,
                 .bytesDown,
                 .protocolStack,
                 .tcpCompleteness:
                NSUserInterfaceItemIdentifier("SessionTextCell")
            }
        }

        private func toggleColumnVisibility(_ colID: SessionOutlineColumnID) {
            var updated = currentColumnState
            updated.toggleVisibility(for: colID)
            if updated != currentColumnState {
                currentColumnState = updated
                if let outlineView {
                    syncColumns(
                        on: outlineView,
                        isGrouped: isGrouped,
                        timeFormat: currentTimeFormat,
                        columnState: updated,
                        sortCriteria: currentSortCriteria
                    )
                }
                onColumnStateChange(updated)
            }
        }

        private func resetSortOrder() {
            guard !currentSortCriteria.isEmpty else {
                return
            }
            currentSortCriteria = []
            if let outlineView {
                syncColumns(
                    on: outlineView,
                    isGrouped: isGrouped,
                    timeFormat: currentTimeFormat,
                    columnState: currentColumnState,
                    sortCriteria: []
                )
            }
            onSortCriteriaChange([])
        }

        private func resetColumns() {
            var updated = currentColumnState
            updated.reset()
            if updated != currentColumnState {
                currentColumnState = updated
                if let outlineView {
                    syncColumns(
                        on: outlineView,
                        isGrouped: isGrouped,
                        timeFormat: currentTimeFormat,
                        columnState: updated,
                        sortCriteria: currentSortCriteria
                    )
                }
                onColumnStateChange(updated)
            }
        }
    }
}
