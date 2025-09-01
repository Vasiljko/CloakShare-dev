use crate::{cross_platform_capture::CrossPlatformScreenCapture, gpu_renderer::GpuRenderer};
use std::sync::Arc;
use winit::window::Window;

/// SafeMirror: The core structure that handles GPU rendering and screen capture
/// Coordinates between screen capture and GPU rendering components
pub struct SafeMirror {
    /// GPU renderer handles all wgpu operations
    gpu_renderer: GpuRenderer,

    /// Cross-platform screen capture manager
    screen_capture: CrossPlatformScreenCapture,
}

impl SafeMirror {
    /// Creates a new SafeMirror instance with full GPU setup
    /// This initializes the entire rendering pipeline from scratch
    pub async fn new(window: Arc<Window>) -> Self {
        let mut screen_capture = CrossPlatformScreenCapture::new()
            .expect("Failed to create cross-platform screen capture");
        
        // Get the actual display resolution
        let resolution = screen_capture.get_display_resolution()
            .unwrap_or_else(|e| {
                eprintln!("Failed to get display resolution: {}, using fallback", e);
                crate::platform::DisplayResolution { width: 1920, height: 1080 }
            });
        
        println!("Display resolution: {}x{}", resolution.width, resolution.height);
        
        let gpu_renderer = GpuRenderer::new(window, resolution.width, resolution.height).await;

        if let Err(e) = screen_capture.start_capture() {
            eprintln!("Failed to start screen capture: {}", e);
        }

        Self {
            gpu_renderer,
            screen_capture,
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
        let texture_data = self
            .screen_capture
            .get_latest_frame()
            .unwrap_or_else(|| self.gpu_renderer.create_test_pattern());

        // Update GPU texture and render
        self.gpu_renderer.update_texture(&texture_data);
        self.gpu_renderer.render()
    }

    /// Get current window size for resize operations
    pub fn size(&self) -> winit::dpi::PhysicalSize<u32> {
        self.gpu_renderer.size()
    }
}
