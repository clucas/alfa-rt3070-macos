#!/usr/bin/env swift
import AppKit

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
let output = root.appendingPathComponent("macos/Packaging")
let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
let iconset = temporary.appendingPathComponent("AppIcon.iconset")
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: temporary) }

func render(pixels: Int, compact: Bool = false) throws -> Data {
    let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
                                  bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                  isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    let context = NSGraphicsContext(bitmapImageRep: bitmap)!
    NSGraphicsContext.saveGraphicsState()
    defer { NSGraphicsContext.restoreGraphicsState() }
    NSGraphicsContext.current = context
    context.cgContext.scaleBy(x: CGFloat(pixels) / 1024, y: CGFloat(pixels) / 1024)
    context.imageInterpolation = .high

    let tile = NSBezierPath(roundedRect: NSRect(x: 96, y: 96, width: 832, height: 832), xRadius: 188, yRadius: 188)
    NSGraphicsContext.saveGraphicsState()
    let shadow = NSShadow()
    shadow.shadowColor = NSColor.black.withAlphaComponent(0.22)
    shadow.shadowBlurRadius = 22
    shadow.shadowOffset = NSSize(width: 0, height: -10)
    shadow.set()
    NSColor(srgbRed: 0.067, green: 0.133, blue: 0.20, alpha: 1).setFill()
    tile.fill()
    NSGraphicsContext.restoreGraphicsState()
    NSGradient(starting: NSColor(srgbRed: 0.067, green: 0.133, blue: 0.20, alpha: 1),
               ending: NSColor(srgbRed: 0.12, green: 0.22, blue: 0.29, alpha: 1))!.draw(in: tile, angle: 90)

    let tint = NSColor(srgbRed: 0.29, green: 0.88, blue: 0.80, alpha: 1)
    tint.setStroke()
    tint.setFill()
    if !compact {
        let outer = NSBezierPath()
        outer.move(to: NSPoint(x: 331, y: 665))
        outer.curve(to: NSPoint(x: 693, y: 665), controlPoint1: NSPoint(x: 430, y: 769), controlPoint2: NSPoint(x: 594, y: 769))
        outer.lineWidth = 39
        outer.lineCapStyle = .round
        outer.stroke()
        let inner = NSBezierPath()
        inner.move(to: NSPoint(x: 399, y: 600))
        inner.curve(to: NSPoint(x: 625, y: 600), controlPoint1: NSPoint(x: 461, y: 661), controlPoint2: NSPoint(x: 563, y: 661))
        inner.lineWidth = 39
        inner.lineCapStyle = .round
        inner.stroke()
        NSBezierPath(ovalIn: NSRect(x: 488, y: 514, width: 48, height: 48)).fill()
    }
    let size: CGFloat = compact ? 590 : 224
    let baseFont = NSFont.systemFont(ofSize: size, weight: .bold)
    let font = baseFont.fontDescriptor.withDesign(.rounded).flatMap { NSFont(descriptor: $0, size: size) } ?? baseFont
    let word = NSAttributedString(string: compact ? "α" : "alpha", attributes: [.font: font, .foregroundColor: NSColor.white])
    let textSize = word.size()
    word.draw(at: NSPoint(x: (1024 - textSize.width) / 2, y: compact ? (1024 - textSize.height) / 2 + 28 : 244))
    return bitmap.representation(using: .png, properties: [:])!
}

try render(pixels: 1024).write(to: output.appendingPathComponent("AppIcon.png"))
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let suffix = scale == 2 ? "@2x" : ""
        try render(pixels: points * scale, compact: points <= 32)
            .write(to: iconset.appendingPathComponent("icon_\(points)x\(points)\(suffix).png"))
    }
}
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
process.arguments = ["-c", "icns", iconset.path, "-o", output.appendingPathComponent("AppIcon.icns").path]
try process.run()
process.waitUntilExit()
guard process.terminationStatus == 0 else { fatalError("Icon conversion failed") }
print("Created macos/Packaging/AppIcon.png and AppIcon.icns")
