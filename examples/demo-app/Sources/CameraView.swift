import AVFoundation

func configureCamera() {
    _ = AVCaptureDevice.default(for: .video)
}
