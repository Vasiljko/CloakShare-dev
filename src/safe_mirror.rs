use crate::{
    cross_platform_capture::CrossPlatformScreenCapture, gpu_renderer::GpuRenderer,
    sensitive_data_detector::SensitiveDataDetector,
};
use std::sync::Arc;
use winit::window::Window;

/// SafeMirror: The core structure that handles GPU rendering and screen capture
/// Coordinates between screen capture and GPU rendering components
pub struct SafeMirror {
    /// GPU renderer handles all wgpu operations
    gpu_renderer: GpuRenderer,

    /// Cross-platform screen capture manager
    screen_capture: CrossPlatformScreenCapture,

    /// Sensitive data detector
    sensitive_detector: Option<SensitiveDataDetector>,

    /// Cached sensitive matches for persistent redaction
    cached_sensitive_matches: Vec<crate::sensitive_data_detector::SensitiveMatch>,
}

impl SafeMirror {
    /// Creates a new SafeMirror instance with full GPU setup
    /// This initializes the entire rendering pipeline from scratch
    pub async fn new(window: Arc<Window>, mut screen_capture: CrossPlatformScreenCapture) -> Self {
        // Get the actual display resolution from the provided screen capture
        let resolution = screen_capture.get_display_resolution().unwrap_or_else(|e| {
            eprintln!("Failed to get display resolution: {}, using fallback", e);
            crate::platform::DisplayResolution {
                width: 1920,
                height: 1080,
            }
        });

        println!(
            "Display resolution: {}x{}",
            resolution.width, resolution.height
        );

        let gpu_renderer =
            GpuRenderer::new(window.clone(), resolution.width, resolution.height).await;

        if let Err(e) = screen_capture.start_capture(Some(&window)) {
            eprintln!("Failed to start screen capture: {}", e);
        }

        // Initialize sensitive data detector
        let sensitive_detector = match SensitiveDataDetector::new() {
            Ok(detector) => {
                println!("🔍 Sensitive data detector initialized");
                Some(detector)
            }
            Err(e) => {
                eprintln!(
                    "Warning: Failed to initialize sensitive data detector: {}",
                    e
                );
                None
            }
        };

        Self {
            gpu_renderer,
            screen_capture,
            sensitive_detector,
            cached_sensitive_matches: Vec::new(),
        }
    }

    /// Handles window resizing by updating GPU surface configuration
    /// When user drags window corner, we need to tell GPU about new dimensions
    pub fn resize(&mut self, new_size: winit::dpi::PhysicalSize<u32>) {
        self.gpu_renderer.resize(new_size);
    }

    /// Updates the screen capture texture with new image data and renders
    pub fn update_and_render(&mut self) -> Result<(), wgpu::SurfaceError> {
        // Get latest frame or use test pattern
        let mut texture_data = self
            .screen_capture
            .get_latest_frame()
            .unwrap_or_else(|| self.gpu_renderer.create_test_pattern());

        // Remove test redaction since pipeline is confirmed working

        // Get display resolution for redaction
        let resolution = self
            .screen_capture
            .get_display_resolution()
            .unwrap_or_else(|_| crate::platform::DisplayResolution {
                width: 1920,
                height: 1080,
            });

        // Detect sensitive data (only on OCR frames) and update cache
        if let Some(ref mut detector) = self.sensitive_detector {
            let new_matches =
                detector.detect_sensitive_data(&texture_data, resolution.width, resolution.height);

            // Update cache with new detections
            if !new_matches.is_empty() {
                self.cached_sensitive_matches = new_matches;
                println!(
                    "🔒 Updated sensitive data cache with {} areas",
                    self.cached_sensitive_matches.len()
                );
            }
        }

        // Always apply redaction using cached matches (every frame)
        if !self.cached_sensitive_matches.is_empty() {
            if let Some(ref detector) = self.sensitive_detector {
                detector.apply_redaction(
                    &mut texture_data,
                    resolution.width,
                    resolution.height,
                    &self.cached_sensitive_matches,
                );
            }
        }

        // Update GPU texture and render
        self.gpu_renderer.update_texture(&texture_data);
        self.gpu_renderer.render()
    }

    /// Get current window size for resize operations
    pub fn size(&self) -> winit::dpi::PhysicalSize<u32> {
        self.gpu_renderer.size()
    }

    /// Test redaction by blacking out top-left corner
    fn test_redaction(&self, rgba_buffer: &mut [u8], width: u32, height: u32) {
        let test_width = 200;
        let test_height = 100;

        for y in 0..test_height.min(height) {
            for x in 0..test_width.min(width) {
                let pixel_index = ((y * width + x) * 4) as usize;
                if pixel_index + 3 < rgba_buffer.len() {
                    rgba_buffer[pixel_index] = 255; // R - red for visibility
                    rgba_buffer[pixel_index + 1] = 0; // G
                    rgba_buffer[pixel_index + 2] = 0; // B
                    rgba_buffer[pixel_index + 3] = 255; // A
                }
            }
        }
        println!("🟥 Applied test redaction (red box) at top-left corner");
    }
}
